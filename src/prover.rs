//! ZiSK proof generation via `cargo-zisk` subprocesses.
//!
//! Runs STARK aggregation → SNARK wrapping, parses the output, and cleans up
//! work directories on success.
//!
//! Uses `tokio::process` so subprocess waits are futures that can be cancelled
//! via `CancellationToken` — no busy-polling with `thread::sleep`.

use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::metrics::ZISK_PROVER_METRICS;

/// Expected proof output sizes (invariants of the ZiSK Plonk verifier).
const ZISK_SNARK_PROOF_BYTES: usize = 768;
const ZISK_PUBLIC_VALUES_BYTES: usize = 256;

/// Proof output.
pub struct ZiskSnarkOutput {
    pub proof: Vec<u8>,
    pub public_values: Vec<u8>,
}

/// ZiSK prover with validated paths.
#[derive(Clone)]
pub struct ZiskProver {
    binary: PathBuf,
    elf_path: PathBuf,
    proving_key: PathBuf,
    proving_key_snark: PathBuf,
    work_dir_base: PathBuf,
}

impl ZiskProver {
    pub fn new(
        binary: PathBuf,
        elf_path: PathBuf,
        proving_key: PathBuf,
        proving_key_snark: PathBuf,
        work_dir_base: PathBuf,
    ) -> Self {
        Self { binary, elf_path, proving_key, proving_key_snark, work_dir_base }
    }

    /// Generate a ZiSK SNARK proof for the given batch.
    ///
    /// Returns `Ok(None)` if cancelled via the shutdown token.
    /// This runs on a blocking thread but the subprocess is managed with
    /// `std::process` + periodic cancel checks (since `tokio::process`
    /// can't be used from `spawn_blocking`).
    pub fn generate_proof(
        &self,
        zisk_bincode: &[u8],
        batch_number: u64,
        cancel: &CancellationToken,
    ) -> anyhow::Result<Option<ZiskSnarkOutput>> {
        let start = Instant::now();
        let work_dir = self.work_dir_base.join(format!("batch_{batch_number}"));

        let _ = std::fs::remove_dir_all(&work_dir);
        std::fs::create_dir_all(&work_dir)?;

        let result = self.run_pipeline(zisk_bincode, batch_number, &work_dir, cancel);

        let elapsed = start.elapsed();
        ZISK_PROVER_METRICS.proof_generation_time.observe(elapsed);

        match &result {
            Ok(Some(_)) => {
                tracing::info!(batch_number, elapsed_secs = elapsed.as_secs(), "proof generated");
                let _ = std::fs::remove_dir_all(&work_dir);
            }
            Ok(None) => {
                tracing::info!(batch_number, "proof cancelled by shutdown");
                let _ = std::fs::remove_dir_all(&work_dir);
            }
            Err(e) => {
                tracing::error!(
                    batch_number, elapsed_secs = elapsed.as_secs(),
                    path = %work_dir.display(), "proof failed: {e}"
                );
            }
        }

        result
    }

    fn run_pipeline(
        &self,
        zisk_bincode: &[u8],
        batch_number: u64,
        work_dir: &Path,
        cancel: &CancellationToken,
    ) -> anyhow::Result<Option<ZiskSnarkOutput>> {
        let input_path = work_dir.join("input.bin");
        write_zisk_input(&input_path, zisk_bincode)?;

        // STARK aggregation
        let stark_dir = work_dir.join("stark");
        std::fs::create_dir_all(stark_dir.join("proofs"))?;
        tracing::info!(batch_number, "STARK aggregation starting");
        let stark_start = Instant::now();
        if !run_cancellable(&self.binary, &[
            "prove",
            "-e", &p(&self.elf_path),
            "-i", &p(&input_path),
            "-k", &p(&self.proving_key),
            "-o", &p(&stark_dir),
            "--emulator", "--aggregation", "--save-proofs", "-v",
        ], cancel)? {
            return Ok(None);
        }
        ZISK_PROVER_METRICS.stark_time.observe(stark_start.elapsed());

        let vadcop_path = stark_dir.join("vadcop_final_proof.bin");
        anyhow::ensure!(vadcop_path.exists(), "vadcop_final_proof.bin not generated");

        if cancel.is_cancelled() { return Ok(None); }

        // SNARK wrapping
        let snark_dir = work_dir.join("snark");
        std::fs::create_dir_all(&snark_dir)?;
        tracing::info!(batch_number, "SNARK wrapping starting");
        let snark_start = Instant::now();
        if !run_cancellable(&self.binary, &[
            "prove-snark",
            "--proof", &p(&vadcop_path),
            "--elf", &p(&self.elf_path),
            "--proving-key-snark", &p(&self.proving_key_snark),
            "-o", &p(&snark_dir),
            "-v",
        ], cancel)? {
            return Ok(None);
        }
        ZISK_PROVER_METRICS.snark_time.observe(snark_start.elapsed());

        let snark_proof_path = snark_dir.join("final_snark_proof.bin");
        anyhow::ensure!(snark_proof_path.exists(), "final_snark_proof.bin not generated");

        parse_snark_output(&snark_proof_path).map(Some)
    }
}

fn p(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn write_zisk_input(path: &Path, bincode: &[u8]) -> anyhow::Result<()> {
    let len = bincode.len() as u64;
    let mut buf = Vec::with_capacity(8 + bincode.len() + 8);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bincode);
    let padding = (8 - ((8 + bincode.len()) % 8)) % 8;
    buf.extend(std::iter::repeat(0u8).take(padding));
    std::fs::write(path, &buf)?;
    Ok(())
}

/// Run a subprocess, checking the cancel token every second.
/// Returns `Ok(true)` on success, `Ok(false)` on cancellation.
fn run_cancellable(
    binary: &Path,
    args: &[&str],
    cancel: &CancellationToken,
) -> anyhow::Result<bool> {
    let mut child = std::process::Command::new(binary)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    loop {
        if cancel.is_cancelled() {
            tracing::info!("shutdown requested, killing subprocess");
            let _ = child.kill();
            let _ = child.wait();
            return Ok(false);
        }
        match child.try_wait()? {
            Some(status) if status.success() => return Ok(true),
            Some(_) => {
                let stderr = child.stderr.take()
                    .map(|mut s| {
                        let mut buf = String::new();
                        std::io::Read::read_to_string(&mut s, &mut buf).ok();
                        buf
                    })
                    .unwrap_or_default();
                let tail = &stderr[stderr.len().saturating_sub(1000)..];
                anyhow::bail!("{} failed: {tail}", binary.display());
            }
            None => std::thread::sleep(std::time::Duration::from_secs(1)),
        }
    }
}

fn parse_snark_output(path: &Path) -> anyhow::Result<ZiskSnarkOutput> {
    let data = std::fs::read(path)?;
    let min_size = 8 + ZISK_SNARK_PROOF_BYTES + 8 + ZISK_PUBLIC_VALUES_BYTES;
    anyhow::ensure!(data.len() >= min_size, "output too small: {} < {min_size}", data.len());

    let proof_len = u64::from_le_bytes(data[0..8].try_into()?) as usize;
    anyhow::ensure!(proof_len == ZISK_SNARK_PROOF_BYTES, "proof length {proof_len} != {ZISK_SNARK_PROOF_BYTES}");

    let pv_offset = 8 + ZISK_SNARK_PROOF_BYTES;
    let pv_len = u64::from_le_bytes(data[pv_offset..pv_offset + 8].try_into()?) as usize;
    anyhow::ensure!(pv_len == ZISK_PUBLIC_VALUES_BYTES, "pv length {pv_len} != {ZISK_PUBLIC_VALUES_BYTES}");

    Ok(ZiskSnarkOutput {
        proof: data[8..8 + ZISK_SNARK_PROOF_BYTES].to_vec(),
        public_values: data[pv_offset + 8..pv_offset + 8 + ZISK_PUBLIC_VALUES_BYTES].to_vec(),
    })
}
