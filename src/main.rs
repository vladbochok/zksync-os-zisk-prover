//! ZiSK Prover Service for ZKsync OS
//!
//! External prover that polls the ZKsync OS server for ZiSK batch data,
//! generates STARK + SNARK proofs using `cargo-zisk`, and submits the
//! results back to the server for multi-proof composition.
//!
//! Mirrors the Airbender prover service (`zksync-os-prover-service`) in
//! architecture: pull model over HTTP, no server-side process management.
//!
//! Supports HTTP Basic Auth via URL credentials, graceful SIGTERM shutdown,
//! and rejects unsupported VK hashes before proving.

mod metrics;
mod prover;
mod sequencer_client;

use clap::Parser;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Supported VK hashes. The prover will only prove batches whose VK hash
/// appears in this list. Prevents wasting GPU time on batches from
/// protocol versions we can't produce valid proofs for.
///
/// Updated when the guest ELF or SNARK circuit changes.
/// Format: lowercase hex with 0x prefix.
const SUPPORTED_VK_HASHES: &[&str] = &[
    // Current guest ELF VK hash — update when ZiSK_vk.json changes.
    // Run `cargo run -- --variant zisk` in era-contracts/tools/verifier-gen
    // to see the current hash, or use update-zisk-vk.sh --extract-only.
    "0x21a582e2fb44e0732b565ffe36331ffb77a315870076b1dc1556579bbc4a67b2",
    // Legacy VK hash from initial deployment.
    "0x124ebcd537a1e1c152774dd18f67660e35625bba0b669bf3b4836d636b105337",
];

#[derive(Parser, Debug)]
#[command(name = "zksync-os-zisk-prover-service", about = "ZiSK prover for ZKsync OS")]
struct Args {
    /// Sequencer URL for polling ZiSK batch data and submitting proofs.
    /// Supports Basic Auth via URL: http://user:pass@host:port
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

    /// Directory for intermediate proof files. Cleaned up after each proof.
    #[arg(long, default_value = "/tmp/zisk_proofs")]
    work_dir: PathBuf,

    /// Poll interval in seconds when no work is available.
    #[arg(long, default_value_t = 5)]
    poll_interval_secs: u64,

    /// Number of proofs to generate before exiting (0 = unlimited).
    #[arg(long, default_value_t = 0)]
    iterations: u64,
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

    tracing::info!(
        sequencer_url = %args.sequencer_url,
        zisk_binary = %args.zisk_binary.display(),
        elf_path = %args.elf_path.display(),
        supported_vk_hashes = ?SUPPORTED_VK_HASHES,
        "Starting ZiSK prover service"
    );

    // Validate paths at startup.
    for (name, path) in [
        ("zisk_binary", &args.zisk_binary),
        ("elf_path", &args.elf_path),
        ("proving_key", &args.proving_key),
        ("proving_key_snark", &args.proving_key_snark),
    ] {
        anyhow::ensure!(path.exists(), "{name} does not exist: {}", path.display());
    }

    let client = sequencer_client::SequencerClient::new(&args.sequencer_url, "zisk_prover")?;
    tracing::info!(url = client.url(), "connected to sequencer (credentials stripped)");

    let prover = prover::ZiskProver::new(
        args.zisk_binary,
        args.elf_path,
        args.proving_key,
        args.proving_key_snark,
        args.work_dir,
    );

    let poll_interval = Duration::from_secs(args.poll_interval_secs);
    let mut proofs_generated: u64 = 0;

    // Graceful shutdown: set flag on SIGTERM/SIGINT, prover checks it between phases.
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => tracing::info!("received SIGINT, shutting down gracefully"),
            _ = sigterm.recv() => tracing::info!("received SIGTERM, shutting down gracefully"),
        }
        shutdown_clone.store(true, Ordering::Relaxed);
    });

    loop {
        if shutdown.load(Ordering::Relaxed) {
            tracing::info!("shutdown requested, exiting main loop");
            break;
        }

        // Poll for available ZiSK batch data.
        let batch = match client.pick_next_batch().await {
            Ok(Some(batch)) => batch,
            Ok(None) => {
                tracing::trace!("no ZiSK batches available");
                tokio::time::sleep(poll_interval).await;
                continue;
            }
            Err(e) => {
                tracing::warn!("failed to poll for batches: {e:#}");
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        };

        // Protocol version validation: reject unsupported VK hashes.
        let vk_lower = batch.vk_hash.to_lowercase();
        if !SUPPORTED_VK_HASHES.iter().any(|h| h.to_lowercase() == vk_lower) {
            tracing::warn!(
                batch_number = batch.batch_number,
                vk_hash = %batch.vk_hash,
                "unsupported VK hash — skipping batch (protocol version not supported by this prover)"
            );
            // Sleep briefly to avoid busy-looping on the same unsupported batch.
            tokio::time::sleep(Duration::from_secs(10)).await;
            continue;
        }

        tracing::info!(
            batch_number = batch.batch_number,
            data_bytes = batch.zisk_data.len(),
            vk_hash = %batch.vk_hash,
            "received ZiSK batch data"
        );

        // Generate proof (blocking — runs subprocesses).
        let result = tokio::task::spawn_blocking({
            let prover = prover.clone();
            let data = batch.zisk_data.clone();
            let batch_num = batch.batch_number;
            let shutdown = shutdown.clone();
            move || prover.generate_proof(&data, batch_num, &shutdown)
        })
        .await??;

        // Check if cancelled by shutdown
        let Some(result) = result else {
            tracing::info!("proof generation was cancelled, exiting");
            break;
        };

        tracing::info!(
            batch_number = batch.batch_number,
            proof_bytes = result.proof.len(),
            pv_bytes = result.public_values.len(),
            "ZiSK SNARK proof generated"
        );

        // Submit proof back to the server.
        client
            .submit_zisk_proof(
                batch.batch_number,
                &batch.vk_hash,
                &result.proof,
                &result.public_values,
            )
            .await?;

        tracing::info!(batch_number = batch.batch_number, "proof submitted to server");

        proofs_generated += 1;
        if args.iterations > 0 && proofs_generated >= args.iterations {
            tracing::info!(proofs_generated, "iteration limit reached, exiting");
            break;
        }
    }

    Ok(())
}
