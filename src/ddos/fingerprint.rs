//! Request fingerprinting for coordinated attack campaign detection.
//!
//! Clusters requests by header order, user-agent, and content-type to identify
//! automated attack tools sending structurally identical requests.

use axum::http::{HeaderMap, Request};
use sha2::{Digest, Sha256};

/// Known attack tool user-agent substrings.
const ATTACK_TOOL_AGENTS: &[&str] = &[
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "gobuster",
    "dirbuster", "hydra", "medusa", "burpsuite", "python-requests/2",
    "go-http-client/1.1", "curl/7.68", "libwww-perl",
];

#[derive(Debug, Clone)]
pub struct RequestFingerprint {
    /// Stable cluster key — same for structurally identical requests.
    pub cluster_key: String,
    pub is_attack_tool_agent: bool,
    pub is_missing_agent: bool,
    pub is_malformed: bool,
}

impl RequestFingerprint {
    pub fn from_request<B>(req: &Request<B>) -> Self {
        let headers = req.headers();

        let cluster_key = compute_cluster_key(headers);
        let ua = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let is_missing_agent = ua.is_empty();
        let is_attack_tool_agent = ATTACK_TOOL_AGENTS
            .iter()
            .any(|tool| ua.to_lowercase().contains(tool));

        let is_malformed = is_malformed_request(headers);

        Self {
            cluster_key,
            is_attack_tool_agent,
            is_missing_agent,
            is_malformed,
        }
    }

    /// Returns a suspicion score 0.0–1.0 based on fingerprint signals.
    pub fn suspicion_score(&self) -> f64 {
        let mut score = 0.0f64;
        if self.is_attack_tool_agent { score += 0.6; }
        if self.is_missing_agent { score += 0.3; }
        if self.is_malformed { score += 0.4; }
        score.min(1.0)
    }
}

/// Hash the header names (in order) + content-type + accept to produce a cluster key.
fn compute_cluster_key(headers: &HeaderMap) -> String {
    let mut hasher = Sha256::new();

    // Header name order is a strong signal for automated tools
    for name in headers.keys() {
        hasher.update(name.as_str().as_bytes());
        hasher.update(b"|");
    }

    // Include content-type and accept as additional discriminators
    if let Some(ct) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
        hasher.update(ct.as_bytes());
    }
    if let Some(acc) = headers.get("accept").and_then(|v| v.to_str().ok()) {
        hasher.update(acc.as_bytes());
    }

    let result = hasher.finalize();
    hex::encode(&result[..8]) // 8 bytes = 16 hex chars, enough for clustering
}

fn is_malformed_request(headers: &HeaderMap) -> bool {
    // Missing Host header is a strong malformation signal
    if headers.get("host").is_none() {
        return true;
    }

    // Content-type present but clearly invalid
    if let Some(ct) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
        if ct.contains('\0') || ct.len() > 256 {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[test]
    fn test_attack_tool_agent_detected() {
        let req = Request::builder()
            .header("user-agent", "sqlmap/1.7")
            .header("host", "example.com")
            .body(())
            .unwrap();
        let fp = RequestFingerprint::from_request(&req);
        assert!(fp.is_attack_tool_agent);
        assert!(fp.suspicion_score() >= 0.6);
    }

    #[test]
    fn test_missing_agent_flagged() {
        let req = Request::builder()
            .header("host", "example.com")
            .body(())
            .unwrap();
        let fp = RequestFingerprint::from_request(&req);
        assert!(fp.is_missing_agent);
    }

    #[test]
    fn test_same_structure_same_cluster() {
        let req1 = Request::builder()
            .header("host", "example.com")
            .header("user-agent", "bot/1.0")
            .header("content-type", "application/json")
            .body(())
            .unwrap();
        let req2 = Request::builder()
            .header("host", "example.com")
            .header("user-agent", "bot/2.0") // different value, same structure
            .header("content-type", "application/json")
            .body(())
            .unwrap();
        let fp1 = RequestFingerprint::from_request(&req1);
        let fp2 = RequestFingerprint::from_request(&req2);
        assert_eq!(fp1.cluster_key, fp2.cluster_key);
    }

    #[test]
    fn test_different_structure_different_cluster() {
        let req1 = Request::builder()
            .header("host", "example.com")
            .header("user-agent", "browser/1.0")
            .body(())
            .unwrap();
        let req2 = Request::builder()
            .header("host", "example.com")
            .header("accept", "application/json")
            .header("user-agent", "browser/1.0")
            .body(())
            .unwrap();
        let fp1 = RequestFingerprint::from_request(&req1);
        let fp2 = RequestFingerprint::from_request(&req2);
        assert_ne!(fp1.cluster_key, fp2.cluster_key);
    }
}
