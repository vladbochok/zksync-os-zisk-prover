//! ZiSK Prover Service for ZKsync OS
//!
//! External prover that polls the ZKsync OS server for ZiSK batch data,
//! generates STARK + SNARK proofs using `cargo-zisk`, and submits the
//! results back to the server for multi-proof composition.

mod metrics;
mod prover;
mod sequencer_client;

use clap::Parser;
use std::path::PathBuf;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Parser, Debug)]
#[command(name = "zksync-os-zisk-prover-service", about = "ZiSK prover for ZKsync OS")]
struct Args {
    /// Sequencer URL. Supports Basic Auth: http://user:pass@host:port
    #[arg(short, long)]
    sequencer_url: String,

    /// Path to the cargo-zisk binary.
    #[arg(long)]
    zisk_binary: PathBuf,

    /// Path to the ZiSK guest ELF binary.
    #[arg(long)]
    elf_path: PathBuf,

    /// Path to the ZiSK STARK proving key directory.
    #[arg(long)]
    proving_key: PathBuf,

    /// Path to the ZiSK SNARK proving key directory.
    #[arg(long)]
    proving_key_snark: PathBuf,

    /// Directory for intermediate proof files.
    #[arg(long, default_value = "/tmp/zisk_proofs")]
    work_dir: PathBuf,

    /// Poll interval in seconds when no work is available.
    #[arg(long, default_value_t = 5)]
    poll_interval_secs: u64,

    /// Number of proofs to generate before exiting (0 = unlimited).
    #[arg(long, default_value_t = 0)]
    iterations: u64,

    /// Supported VK hashes (hex, 0x-prefixed). If not specified, accepts all.
    /// Pass multiple times: --supported-vk 0xabc... --supported-vk 0xdef...
    /// Or load from a file with --vk-hashes-file.
    #[arg(long = "supported-vk")]
    supported_vk_hashes: Vec<String>,

    /// Path to a file containing supported VK hashes (one per line).
    /// Lines starting with # are ignored. Combined with --supported-vk.
    #[arg(long)]
    vk_hashes_file: Option<PathBuf>,

    /// Prometheus metrics listen address.
    #[arg(long, default_value = "0.0.0.0:3313")]
    metrics_address: String,
}

fn load_supported_vk_hashes(args: &Args) -> Vec<String> {
    let mut hashes: Vec<String> = args.supported_vk_hashes
        .iter()
        .map(|h| h.to_lowercase())
        .collect();

    if let Some(ref path) = args.vk_hashes_file {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        hashes.push(line.to_lowercase());
                    }
                }
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), "failed to read VK hashes file: {e}");
            }
        }
    }

    hashes.dedup();
    hashes
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let supported_vks = load_supported_vk_hashes(&args);

    tracing::info!(
        sequencer_url = %args.sequencer_url,
        zisk_binary = %args.zisk_binary.display(),
        elf_path = %args.elf_path.display(),
        supported_vk_hashes = ?supported_vks,
        vk_filter = if supported_vks.is_empty() { "disabled (accepts all)" } else { "enabled" },
        "Starting ZiSK prover service"
    );

    // Validate paths.
    for (name, path) in [
        ("zisk_binary", &args.zisk_binary),
        ("elf_path", &args.elf_path),
        ("proving_key", &args.proving_key),
        ("proving_key_snark", &args.proving_key_snark),
    ] {
        anyhow::ensure!(path.exists(), "{name} does not exist: {}", path.display());
    }

    // Start Prometheus metrics server.
    let metrics_addr: std::net::SocketAddr = args.metrics_address.parse()?;
    let exporter = vise_exporter::MetricsExporter::default();
    tokio::spawn(exporter.start(metrics_addr));
    tracing::info!(address = %metrics_addr, "metrics server started");

    let client = sequencer_client::SequencerClient::new(&args.sequencer_url, "zisk_prover")?;
    tracing::info!(url = client.url(), "connected to sequencer");

    let prover = prover::ZiskProver::new(
        args.zisk_binary,
        args.elf_path,
        args.proving_key,
        args.proving_key_snark,
        args.work_dir,
    );

    let poll_interval = Duration::from_secs(args.poll_interval_secs);
    let mut proofs_generated: u64 = 0;

    // Graceful shutdown via CancellationToken.
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => tracing::info!("received SIGINT"),
            _ = sigterm.recv() => tracing::info!("received SIGTERM"),
        }
        cancel_clone.cancel();
    });

    loop {
        if cancel.is_cancelled() {
            tracing::info!("shutdown requested, exiting");
            break;
        }

        // Poll for work.
        let batch = match client.pick_next_batch().await {
            Ok(Some(batch)) => batch,
            Ok(None) => {
                tokio::select! {
                    _ = tokio::time::sleep(poll_interval) => {}
                    _ = cancel.cancelled() => break,
                }
                continue;
            }
            Err(e) => {
                tracing::warn!("poll failed: {e:#}");
                tokio::select! {
                    _ = tokio::time::sleep(poll_interval) => {}
                    _ = cancel.cancelled() => break,
                }
                continue;
            }
        };

        // VK hash filter.
        if !supported_vks.is_empty() {
            let vk_lower = batch.vk_hash.to_lowercase();
            if !supported_vks.iter().any(|h| *h == vk_lower) {
                tracing::warn!(
                    batch = batch.batch_number,
                    vk_hash = %batch.vk_hash,
                    "unsupported VK hash — skipping"
                );
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        }

        tracing::info!(
            batch = batch.batch_number,
            data_bytes = batch.zisk_data.len(),
            vk_hash = %batch.vk_hash,
            "picked ZiSK batch"
        );

        // Prove. Uses tokio::process internally — cancellation is instant.
        let result = prover.generate_proof(
            &batch.zisk_data,
            batch.batch_number,
            &cancel,
        ).await?;

        let Some(result) = result else {
            tracing::info!("proof cancelled, exiting");
            break;
        };

        tracing::info!(
            batch = batch.batch_number,
            proof_bytes = result.proof.len(),
            pv_bytes = result.public_values.len(),
            "proof generated"
        );

        client
            .submit_zisk_proof(
                batch.batch_number,
                &batch.vk_hash,
                &result.proof,
                &result.public_values,
            )
            .await?;

        tracing::info!(batch = batch.batch_number, "proof submitted");

        proofs_generated += 1;
        if args.iterations > 0 && proofs_generated >= args.iterations {
            tracing::info!(proofs_generated, "iteration limit reached");
            break;
        }
    }

    Ok(())
}
