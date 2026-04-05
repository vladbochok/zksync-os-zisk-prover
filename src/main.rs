//! ZiSK Prover Service for ZKsync OS
//!
//! External prover that polls the ZKsync OS server for ZiSK batch data,
//! generates STARK + SNARK proofs using `cargo-zisk`, and submits the
//! results back to the server for multi-proof composition.
//!
//! Mirrors the Airbender prover service (`zksync-os-prover-service`) in
//! architecture: pull model over HTTP, no server-side process management.

mod prover;
mod sequencer_client;

use clap::Parser;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "zksync-os-zisk-prover-service", about = "ZiSK prover for ZKsync OS")]
struct Args {
    /// Sequencer URL for polling ZiSK batch data and submitting proofs.
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

    let client = sequencer_client::SequencerClient::new(&args.sequencer_url);
    let prover = prover::ZiskProver::new(
        args.zisk_binary,
        args.elf_path,
        args.proving_key,
        args.proving_key_snark,
        args.work_dir,
    );

    let poll_interval = Duration::from_secs(args.poll_interval_secs);
    let mut proofs_generated: u64 = 0;

    loop {
        // Poll for available ZiSK batch data.
        let batch = match client.poll_next_batch().await {
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

        tracing::info!(
            batch_number = batch.batch_number,
            data_bytes = batch.zisk_data.len(),
            "received ZiSK batch data"
        );

        // Generate proof (blocking — runs subprocesses).
        let result = tokio::task::spawn_blocking({
            let prover = prover.clone();
            let data = batch.zisk_data.clone();
            let batch_num = batch.batch_number;
            move || prover.generate_proof(&data, batch_num)
        })
        .await??;

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
