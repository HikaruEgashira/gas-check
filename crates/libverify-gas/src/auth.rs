use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use serde::Deserialize;

use crate::config::GasConfig;

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Resolve an OAuth2 access token from clasp credentials.
///
/// Reads `~/.clasprc.json`, extracts the refresh token, and exchanges it
/// for a fresh access token via Google's OAuth2 token endpoint.
pub fn resolve_access_token(config: &GasConfig) -> Result<String> {
    let creds = config.load_clasp_credentials()?;
    let token = creds
        .tokens
        .get("default")
        .context("no 'default' token in clasp credentials")?;

    let client = Client::new();
    let resp = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", token.client_id.as_str()),
            ("client_secret", token.client_secret.as_str()),
            ("refresh_token", token.refresh_token.as_str()),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .context("failed to refresh access token")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        bail!("token refresh failed ({status}): {body}");
    }

    let token_resp: TokenResponse = resp.json().context("failed to parse token response")?;
    Ok(token_resp.access_token)
}
