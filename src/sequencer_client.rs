//! HTTP client for the ZKsync OS server's ZiSK prover API.
//!
//! Uses the same pick/submit model as the Airbender prover:
//! - `POST /ZiSK/pick` — get assigned batch with ZiSK data
//! - `POST /ZiSK/submit` — submit ZiSK SNARK proof

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};

/// Batch data returned by `/ZiSK/pick`.
pub struct ZiskBatchData {
    pub batch_number: u64,
    pub vk_hash: String,
    pub zisk_data: Vec<u8>,
}

/// HTTP client for the server's prover API.
pub struct SequencerClient {
    base_url: String,
    prover_id: String,
    client: reqwest::Client,
}

#[derive(Deserialize)]
struct PickResponse {
    batch_number: u64,
    vk_hash: String,
    zisk_data: String,
}

#[derive(Serialize)]
struct ZiskSubmitPayload {
    batch_number: u64,
    proof: String,
    public_values: String,
}

impl SequencerClient {
    pub fn new(base_url: &str, prover_id: &str) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        Self {
            base_url,
            prover_id: prover_id.to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Pick the next assigned ZiSK batch from the server.
    ///
    /// Returns `None` if no batches are available.
    /// The server tracks the assignment with timeout-based reassignment.
    pub async fn pick_next_batch(&self) -> anyhow::Result<Option<ZiskBatchData>> {
        let url = format!(
            "{}/prover-jobs/v1/ZiSK/pick?id={}",
            self.base_url, self.prover_id
        );
        let resp = self.client.post(&url).send().await?;

        if resp.status() == reqwest::StatusCode::NO_CONTENT
            || resp.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE
        {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!("ZiSK pick failed: {}", resp.status());
        }

        let pick: PickResponse = resp.json().await?;
        let zisk_data = BASE64.decode(&pick.zisk_data)?;

        Ok(Some(ZiskBatchData {
            batch_number: pick.batch_number,
            vk_hash: pick.vk_hash,
            zisk_data,
        }))
    }

    /// Submit a ZiSK SNARK proof for a batch.
    ///
    /// The server pairs it with the Airbender SNARK and sends the
    /// combined MultiProof to L1.
    pub async fn submit_zisk_proof(
        &self,
        batch_number: u64,
        _vk_hash: &str,
        proof: &[u8],
        public_values: &[u8],
    ) -> anyhow::Result<()> {
        let payload = ZiskSubmitPayload {
            batch_number,
            proof: BASE64.encode(proof),
            public_values: BASE64.encode(public_values),
        };

        let url = format!(
            "{}/prover-jobs/v1/ZiSK/submit?id={}",
            self.base_url, self.prover_id
        );
        let resp = self.client.post(&url).json(&payload).send().await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("ZiSK submit failed for batch {batch_number}: {body}");
        }

        Ok(())
    }
}
