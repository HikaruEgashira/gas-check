use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};
use serde::de::DeserializeOwned;

const MAX_HTTP_ATTEMPTS: usize = 3;
const INITIAL_RETRY_DELAY_MS: u64 = 250;

pub struct GasClient {
    client: Client,
}

impl GasClient {
    pub fn new(access_token: &str) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {access_token}"))
                .context("invalid access token")?,
        );
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("gas-check/0.1.0"),
        );

        let client = Client::builder()
            .default_headers(headers)
            .build()
            .context("failed to create HTTP client")?;

        Ok(Self { client })
    }

    /// GET a JSON resource with retry.
    pub fn get_json<T: DeserializeOwned>(&self, url: &str) -> Result<T> {
        let mut delay = Duration::from_millis(INITIAL_RETRY_DELAY_MS);

        for attempt in 1..=MAX_HTTP_ATTEMPTS {
            let resp = self
                .client
                .get(url)
                .send()
                .with_context(|| format!("HTTP GET failed: {url}"))?;

            let status = resp.status();
            if status.is_success() {
                return resp
                    .json::<T>()
                    .with_context(|| format!("failed to parse JSON from {url}"));
            }

            if (status.as_u16() == 429 || status.is_server_error())
                && attempt < MAX_HTTP_ATTEMPTS
            {
                eprintln!("  retry {attempt}/{MAX_HTTP_ATTEMPTS} after {status} for {url}");
                thread::sleep(delay);
                delay *= 2;
                continue;
            }

            let body = resp.text().unwrap_or_default();
            bail!("GET {url} returned {status}: {body}");
        }

        unreachable!()
    }

    // --- Apps Script API ---

    pub fn get_project<T: DeserializeOwned>(&self, script_id: &str) -> Result<T> {
        self.get_json(&format!(
            "https://script.googleapis.com/v1/projects/{script_id}"
        ))
    }

    pub fn get_content<T: DeserializeOwned>(&self, script_id: &str) -> Result<T> {
        self.get_json(&format!(
            "https://script.googleapis.com/v1/projects/{script_id}/content"
        ))
    }

    pub fn get_versions<T: DeserializeOwned>(&self, script_id: &str) -> Result<T> {
        self.get_json(&format!(
            "https://script.googleapis.com/v1/projects/{script_id}/versions"
        ))
    }

    pub fn get_deployments<T: DeserializeOwned>(&self, script_id: &str) -> Result<T> {
        self.get_json(&format!(
            "https://script.googleapis.com/v1/projects/{script_id}/deployments"
        ))
    }

    // --- Drive API ---

    #[allow(dead_code)]
    pub fn get_file_metadata<T: DeserializeOwned>(&self, file_id: &str) -> Result<T> {
        self.get_json(&format!(
            "https://www.googleapis.com/drive/v3/files/{file_id}?fields=id,name,owners,sharingUser,shared,permissions"
        ))
    }

    pub fn get_permissions<T: DeserializeOwned>(&self, file_id: &str) -> Result<T> {
        self.get_json(&format!(
            "https://www.googleapis.com/drive/v3/files/{file_id}/permissions?fields=permissions(id,type,role,emailAddress)"
        ))
    }
}
