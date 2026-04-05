//! ZiSK proof generation via `cargo-zisk` subprocesses.
//!
//! Runs STARK aggregation → SNARK wrapping, parses the output, and cleans up
//! work directories on success.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

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
        Self {
            binary,
            elf_path,
            proving_key,
            proving_key_snark,
            work_dir_base,
        }
    }

    /// Generate a ZiSK SNARK proof for the given batch.
    pub fn generate_proof(
        &self,
        zisk_bincode: &[u8],
        batch_number: u64,
    ) -> anyhow::Result<ZiskSnarkOutput> {
        let start = Instant::now();
        let work_dir = self.work_dir_base.join(format!("batch_{batch_number}"));

        let _ = std::fs::remove_dir_all(&work_dir);
        std::fs::create_dir_all(&work_dir)?;

        let result = self.run_pipeline(zisk_bincode, batch_number, &work_dir);

        let elapsed = start.elapsed();
        match &result {
            Ok(_) => {
                tracing::info!(batch_number, elapsed_secs = elapsed.as_secs(), "proof generated");
                let _ = std::fs::remove_dir_all(&work_dir);
            }
            Err(e) => {
                tracing::error!(
                    batch_number,
                    elapsed_secs = elapsed.as_secs(),
                    path = %work_dir.display(),
                    "proof generation failed: {e}"
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
    ) -> anyhow::Result<ZiskSnarkOutput> {
        // Write input.
        let input_path = work_dir.join("input.bin");
        write_zisk_input(&input_path, zisk_bincode)?;

        // STARK aggregation.
        let stark_dir = work_dir.join("stark");
        std::fs::create_dir_all(stark_dir.join("proofs"))?;
        tracing::info!(batch_number, "running STARK aggregation...");
        run_subprocess(
            &self.binary,
            &[
                "prove",
                "-e", &p(&self.elf_path),
                "-i", &p(&input_path),
                "-k", &p(&self.proving_key),
                "-o", &p(&stark_dir),
                "--emulator", "--aggregation", "--save-proofs", "-v",
            ],
        )?;

        let vadcop_path = stark_dir.join("vadcop_final_proof.bin");
        anyhow::ensure!(vadcop_path.exists(), "vadcop_final_proof.bin not generated");

        // SNARK wrapping.
        let snark_dir = work_dir.join("snark");
        std::fs::create_dir_all(&snark_dir)?;
        tracing::info!(batch_number, "running SNARK wrapping...");
        run_subprocess(
            &self.binary,
            &[
                "prove-snark",
                "--proof", &p(&vadcop_path),
                "--elf", &p(&self.elf_path),
                "--proving-key-snark", &p(&self.proving_key_snark),
                "-o", &p(&snark_dir),
                "-v",
            ],
        )?;

        let snark_proof_path = snark_dir.join("final_snark_proof.bin");
        anyhow::ensure!(snark_proof_path.exists(), "final_snark_proof.bin not generated");

        parse_snark_output(&snark_proof_path)
    }
}

/// Path to string (lossy).
fn p(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Write ZiSK stdin format: `[len:u64_LE][bincode][padding_to_8B]`.
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

/// Run a subprocess and check exit code.
fn run_subprocess(binary: &Path, args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new(binary).args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail = &stderr[stderr.len().saturating_sub(1000)..];
        anyhow::bail!("{} failed: {tail}", binary.display());
    }
    Ok(())
}

/// Parse `final_snark_proof.bin`: `[proof_len:u64_LE][proof][pv_len:u64_LE][pv]`.
fn parse_snark_output(path: &Path) -> anyhow::Result<ZiskSnarkOutput> {
    let data = std::fs::read(path)?;
    let min_size = 8 + ZISK_SNARK_PROOF_BYTES + 8 + ZISK_PUBLIC_VALUES_BYTES;
    anyhow::ensure!(
        data.len() >= min_size,
        "output too small: {} bytes, expected >= {min_size}",
        data.len()
    );

    let proof_len = u64::from_le_bytes(data[0..8].try_into()?) as usize;
    anyhow::ensure!(proof_len == ZISK_SNARK_PROOF_BYTES, "proof length {proof_len}, expected {ZISK_SNARK_PROOF_BYTES}");

    let pv_offset = 8 + ZISK_SNARK_PROOF_BYTES;
    let pv_len = u64::from_le_bytes(data[pv_offset..pv_offset + 8].try_into()?) as usize;
    anyhow::ensure!(pv_len == ZISK_PUBLIC_VALUES_BYTES, "pv length {pv_len}, expected {ZISK_PUBLIC_VALUES_BYTES}");

    Ok(ZiskSnarkOutput {
        proof: data[8..8 + ZISK_SNARK_PROOF_BYTES].to_vec(),
        public_values: data[pv_offset + 8..pv_offset + 8 + ZISK_PUBLIC_VALUES_BYTES].to_vec(),
    })
}
