use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

/// clasp CLI credential format (~/.clasprc.json).
#[derive(Debug, Deserialize)]
pub struct ClaspCredentials {
    pub tokens: std::collections::HashMap<String, ClaspToken>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ClaspToken {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
    #[serde(default)]
    pub access_token: Option<String>,
}

pub struct GasConfig {
    pub credentials_path: PathBuf,
}

impl GasConfig {
    pub fn new(credentials_path: Option<PathBuf>) -> Self {
        let path = credentials_path.unwrap_or_else(|| {
            dirs::home_dir()
                .expect("cannot determine home directory")
                .join(".clasprc.json")
        });
        Self {
            credentials_path: path,
        }
    }

    pub fn load_clasp_credentials(&self) -> Result<ClaspCredentials> {
        let content = std::fs::read_to_string(&self.credentials_path)
            .with_context(|| format!("failed to read {}", self.credentials_path.display()))?;
        serde_json::from_str(&content).context("failed to parse clasp credentials")
    }
}
