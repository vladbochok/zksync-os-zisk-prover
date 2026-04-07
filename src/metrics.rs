//! Metrics for ZiSK prover service.

use std::time::Duration;
use vise::{Buckets, EncodeLabelSet, EncodeLabelValue, Family, Histogram, Metrics};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EncodeLabelValue, EncodeLabelSet)]
#[metrics(label = "method")]
pub enum Method {
    #[metrics(rename = "pick")]
    Pick,
    #[metrics(rename = "submit")]
    Submit,
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Method::Pick => write!(f, "pick"),
            Method::Submit => write!(f, "submit"),
        }
    }
}

const LATENCY_BUCKETS: Buckets = Buckets::exponential(0.01..=60.0, 2.0);
const PROOF_TIME_BUCKETS: Buckets = Buckets::exponential(10.0..=7200.0, 2.0);

#[derive(Debug, Metrics)]
#[metrics(prefix = "zisk_prover")]
pub struct ZiskProverMetrics {
    /// HTTP request latency by method.
    #[metrics(buckets = LATENCY_BUCKETS)]
    pub http_latency: Family<Method, Histogram<Duration>>,

    /// Total proof generation time (STARK + SNARK).
    #[metrics(buckets = PROOF_TIME_BUCKETS)]
    pub proof_generation_time: Histogram<Duration>,

    /// STARK aggregation time.
    #[metrics(buckets = PROOF_TIME_BUCKETS)]
    pub stark_time: Histogram<Duration>,

    /// SNARK wrapping time.
    #[metrics(buckets = PROOF_TIME_BUCKETS)]
    pub snark_time: Histogram<Duration>,
}

#[vise::register]
pub static ZISK_PROVER_METRICS: vise::Global<ZiskProverMetrics> = vise::Global::new();
