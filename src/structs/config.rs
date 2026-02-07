use serde::Deserialize;

use std::collections::HashMap;

pub const DEFAULT_LISTEN: &str = "0.0.0.0:443";

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: Option<String>,
    pub ca: Option<CaConfig>,
    pub proxies: HashMap<String, ProxyEntry>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: Some(DEFAULT_LISTEN.to_string()),
            ca: None,
            proxies: HashMap::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CaConfig {
    pub cert: Option<String>,
    pub key: Option<String>,

    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            cert: Some("ca.crt".to_string()),
            key: Some("ca.key".to_string()),

            common_name: Some("Mallory CA".to_string()),
            organization: Some("Mallory".to_string()),
            country: Some("US".to_string()),
            state: Some("California".to_string()),
            locality: Some("San Francisco".to_string()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyEntry {
    pub domains: Vec<String>,
    pub target: String,
    pub dns: Option<String>,
}
