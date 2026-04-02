use serde::Deserialize;

// --- Apps Script API types ---

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    pub script_id: String,
    pub title: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub create_time: Option<String>,
    #[serde(default)]
    pub update_time: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentResponse {
    pub script_id: String,
    #[serde(default)]
    pub files: Vec<ScriptFile>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptFile {
    pub name: String,
    #[serde(rename = "type")]
    pub file_type: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub function_set: Option<FunctionSet>,
    #[serde(default)]
    pub create_time: Option<String>,
    #[serde(default)]
    pub update_time: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionSet {
    #[serde(default)]
    pub values: Vec<FunctionEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionEntry {
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionsResponse {
    #[serde(default)]
    pub versions: Vec<Version>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    #[serde(default)]
    pub version_number: Option<i64>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub create_time: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentsResponse {
    #[serde(default)]
    pub deployments: Vec<Deployment>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Deployment {
    pub deployment_id: String,
    #[serde(default)]
    pub deployment_config: Option<DeploymentConfig>,
    #[serde(default)]
    pub update_time: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentConfig {
    #[serde(default)]
    pub script_id: Option<String>,
    #[serde(default)]
    pub version_number: Option<i64>,
    #[serde(default)]
    pub manifest_file_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

// --- appsscript.json manifest ---

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    #[serde(default)]
    pub time_zone: Option<String>,
    #[serde(default)]
    pub dependencies: Option<ManifestDependencies>,
    #[serde(default)]
    pub exception_logging: Option<String>,
    #[serde(default)]
    pub runtime_version: Option<String>,
    #[serde(default)]
    pub oauth_scopes: Vec<String>,
    #[serde(default)]
    pub webapp: Option<WebAppConfig>,
    #[serde(default)]
    pub execution_api: Option<ExecutionApiConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ManifestDependencies {
    #[serde(default)]
    pub libraries: Vec<LibraryDependency>,
    #[serde(default)]
    pub enable_advanced_services: Vec<AdvancedService>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryDependency {
    pub user_symbol: String,
    pub library_id: String,
    pub version: String,
    #[serde(default)]
    pub development_mode: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvancedService {
    #[serde(default)]
    pub user_symbol: Option<String>,
    pub service_id: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebAppConfig {
    #[serde(default)]
    pub access: Option<String>,
    #[serde(default)]
    pub execute_as: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionApiConfig {
    #[serde(default)]
    pub access: Option<String>,
}

// --- Drive API types ---

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveFile {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub shared: Option<bool>,
    #[serde(default)]
    pub permissions: Option<Vec<DrivePermission>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionsResponse {
    #[serde(default)]
    pub permissions: Vec<DrivePermission>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DrivePermission {
    pub id: String,
    #[serde(rename = "type")]
    pub permission_type: String,
    pub role: String,
    #[serde(default)]
    pub email_address: Option<String>,
}
