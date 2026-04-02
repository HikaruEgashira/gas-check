use crate::gas::types::{
    Deployment, DrivePermission, LibraryDependency, Manifest, ScriptFile, Version, WebAppConfig,
    ExecutionApiConfig,
};

#[allow(dead_code)]
/// GAS-specific evidence that cannot be represented in `EvidenceBundle`.
///
/// Custom controls hold `Arc<GasProjectEvidence>` to access this data.
#[derive(Debug, Clone)]
pub struct GasProjectEvidence {
    pub script_id: String,
    pub title: String,
    pub parent_id: Option<String>,

    // Manifest (appsscript.json)
    pub manifest: Manifest,
    pub manifest_raw: Option<String>,

    // OAuth scopes declared in manifest
    pub oauth_scopes: Vec<String>,

    // Versions
    pub versions: Vec<Version>,

    // Deployments
    pub deployments: Vec<Deployment>,

    // Drive permissions
    pub permissions: Vec<DrivePermission>,

    // Web app config (from manifest)
    pub webapp_config: Option<WebAppConfig>,

    // API executable config (from manifest)
    pub execution_api_config: Option<ExecutionApiConfig>,

    // Libraries
    pub libraries: Vec<LibraryDependency>,

    // GCP project linkage
    pub has_explicit_gcp_project: bool,

    // HEAD content files (current editor state)
    pub head_files: Vec<ScriptFile>,

    // Latest version content files (None if no versions exist)
    pub latest_version_files: Option<Vec<ScriptFile>>,
}
