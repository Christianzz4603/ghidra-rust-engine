//! HTTP client for a Dazhbog Lumina-compatible metadata server.
use crate::{Error, Result};
use serde_json::Value;

/// Read-only client for Dazhbog's HTTP workbench API.
///
/// This is deliberately separate from the native decompiler database: Lumina
/// metadata is external evidence and is never silently treated as ground truth.
#[derive(Clone, Debug)]
pub struct LuminaClient {
    base_url: String,
}

impl LuminaClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
            return Err(Error::Lowlevel(
                "Lumina URL must start with http:// or https://".to_string(),
            ));
        }
        Ok(Self { base_url })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Search Dazhbog's indexed function names and demangled names.
    pub fn search_functions(&self, query: &str, limit: usize) -> Result<Value> {
        let limit = limit.clamp(1, 200);
        let url = format!(
            "{}/api/search?q={}&mode=functions&limit={limit}",
            self.base_url,
            percent_encode(query.as_bytes())
        );
        self.get_json(&url)
    }

    /// Retrieve the metadata record for a Lumina function key.
    pub fn function_detail(&self, key: &str, binary_md5: Option<&str>) -> Result<Value> {
        if key.is_empty() || key.len() > 512 {
            return Err(Error::Lowlevel("invalid Lumina function key length".to_string()));
        }
        let mut url = format!("{}/api/function/{}", self.base_url, percent_encode(key.as_bytes()));
        if let Some(md5) = binary_md5 {
            if md5.len() != 32 || !md5.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(Error::Lowlevel(
                    "binary MD5 must contain exactly 32 hexadecimal characters".to_string(),
                ));
            }
            url.push_str("?md5=");
            url.push_str(md5);
        }
        self.get_json(&url)
    }

    fn get_json(&self, url: &str) -> Result<Value> {
        let response = ureq::get(url)
            .set("Accept", "application/json")
            .set("User-Agent", "ghidra-rust-engine")
            .call()
            .map_err(|error| Error::Lowlevel(format!("Lumina request failed: {error}")))?;
        let body = response
            .into_string()
            .map_err(|error| Error::Lowlevel(format!("could not read Lumina response: {error}")))?;
        serde_json::from_str(&body).map_err(|error| Error::Lowlevel(format!("Lumina returned invalid JSON: {error}")))
    }
}

fn percent_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len());
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encoding_preserves_query_syntax_safely() {
        assert_eq!(
            percent_encode(b"memcpy + std::vector"),
            "memcpy%20%2B%20std%3A%3Avector"
        );
    }

    #[test]
    fn rejects_non_http_endpoints() {
        assert!(LuminaClient::new("file:///tmp/lumina").is_err());
    }

    #[test]
    fn validates_binary_md5_before_network_access() {
        let client = LuminaClient::new("http://127.0.0.1:1234").unwrap();
        assert!(client.function_detail("some-key", Some("not-an-md5")).is_err());
    }
}
