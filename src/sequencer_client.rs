//! HTTP client for the ZKsync OS server's prover API.
//!
//! Mirrors the client in `zksync-os-prover-service` for Airbender.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};

/// Batch data returned by the server for ZiSK proof generation.
pub struct ZiskBatchData {
    pub batch_number: u64,
    pub vk_hash: String,
    pub zisk_data: Vec<u8>,
}

/// HTTP client for the server's prover API.
pub struct SequencerClient {
    base_url: String,
    client: reqwest::Client,
}

#[derive(Deserialize)]
struct PeekResponse {
    batch_number: u64,
    vk_hash: String,
    /// Base64-encoded ZiSK prover input.
    zisk_data: Option<String>,
}

#[derive(Serialize)]
struct SnarkSubmitPayload {
    from_batch_number: u64,
    to_batch_number: u64,
    vk_hash: String,
    proof: String,
}

/// Status response from the server.
#[derive(Deserialize)]
struct StatusEntry {
    batch_number: u64,
    #[allow(dead_code)]
    stage: String,
}

impl SequencerClient {
    pub fn new(base_url: &str) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    /// Poll the server for the next batch that has ZiSK data available.
    ///
    /// Checks the SNARK job queue status to find batches awaiting proving,
    /// then fetches the ZiSK data for the first available batch.
    pub async fn poll_next_batch(&self) -> anyhow::Result<Option<ZiskBatchData>> {
        // Get SNARK queue status to find batches needing proofs.
        let status_url = format!("{}/prover-jobs/v1/status/", self.base_url);
        let resp = self.client.get(&status_url).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("status request failed: {}", resp.status());
        }
        let entries: Vec<StatusEntry> = resp.json().await?;
        if entries.is_empty() {
            return Ok(None);
        }

        // Try each batch to find one with ZiSK data.
        for entry in &entries {
            let peek_url = format!(
                "{}/prover-jobs/v1/ZiSK/{}/peek",
                self.base_url, entry.batch_number
            );
            let resp = self.client.get(&peek_url).send().await?;
            if resp.status() == reqwest::StatusCode::NO_CONTENT {
                continue;
            }
            if !resp.status().is_success() {
                tracing::debug!(
                    batch = entry.batch_number,
                    status = %resp.status(),
                    "ZiSK peek failed"
                );
                continue;
            }

            let peek: PeekResponse = resp.json().await?;
            if let Some(zisk_b64) = peek.zisk_data {
                let zisk_data = BASE64.decode(&zisk_b64)?;
                return Ok(Some(ZiskBatchData {
                    batch_number: peek.batch_number,
                    vk_hash: peek.vk_hash,
                    zisk_data,
                }));
            }
        }

        Ok(None)
    }

    /// Submit a ZiSK SNARK proof for a batch.
    ///
    /// The server combines it with the Airbender SNARK into a MultiProof.
    pub async fn submit_zisk_proof(
        &self,
        batch_number: u64,
        vk_hash: &str,
        proof: &[u8],
        public_values: &[u8],
    ) -> anyhow::Result<()> {
        // Encode proof + public values as a single base64 payload.
        // The server expects the SNARK proof in the standard submit format.
        let mut combined = Vec::with_capacity(proof.len() + public_values.len());
        combined.extend_from_slice(proof);
        combined.extend_from_slice(public_values);

        let payload = SnarkSubmitPayload {
            from_batch_number: batch_number,
            to_batch_number: batch_number,
            vk_hash: vk_hash.to_string(),
            proof: BASE64.encode(&combined),
        };

        let url = format!(
            "{}/prover-jobs/v1/SNARK/submit?id=zisk_prover",
            self.base_url
        );
        let resp = self.client.post(&url).json(&payload).send().await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("SNARK submit failed for batch {batch_number}: {body}");
        }

        Ok(())
    }
}
