use std::sync::Arc;

use libverify_core::control::Control;

use crate::evidence::GasProjectEvidence;

pub mod api_executable_access;
pub mod deployment_version_linkage;
pub mod description_quality;
pub mod edit_source_detection;
pub mod editor_count_audit;
pub mod external_library_audit;
pub mod gcp_project_linkage;
pub mod head_drift;
pub mod library_inventory;
pub mod manifest_integrity;
pub mod oauth_scope_minimization;
pub mod secret_scanning;
pub mod sharing_restriction;
pub mod stale_deployment;
pub mod trigger_audit;
mod util;
pub mod version_history_integrity;
pub mod version_hygiene;
pub mod webapp_access_control;

/// Control ID → description pairs for CLI display.
pub const CONTROL_DESCRIPTIONS: &[(&str, &str)] = &[
    ("gas-sharing-restriction", "Project must not be shared broadly (no 'anyone' or 'domain' permissions)"),
    ("gas-editor-count-audit", "Number of editors on the project should be limited"),
    ("gas-oauth-scope-minimization", "OAuth scopes in appsscript.json should follow least-privilege principle"),
    ("gas-version-hygiene", "Deployments must reference a specific version, not HEAD"),
    ("gas-deployment-version-linkage", "Every active deployment must be linked to an existing version"),
    ("gas-description-quality", "Versions should have meaningful descriptions"),
    ("gas-trigger-audit", "Audit OAuth scopes available to triggers for appropriate privilege level"),
    ("gas-external-library-audit", "External libraries must be pinned to specific versions (not development mode)"),
    ("gas-gcp-project-linkage", "Project should be linked to an explicit GCP project (not the default invisible project)"),
    ("gas-library-inventory", "All external library dependencies must be inventoried"),
    ("gas-manifest-integrity", "appsscript.json must be well-formed and declare expected runtime version"),
    ("gas-webapp-access-control", "Web app deployments must restrict access (not 'ANYONE_ANONYMOUS')"),
    ("gas-api-executable-access", "API executable deployments must restrict access"),
    ("gas-head-drift", "HEAD must not diverge from the latest version (no unversioned changes in production)"),
    ("gas-secret-scanning", "Source files must not contain hardcoded secrets (API keys, tokens, passwords, private keys)"),
    ("gas-edit-source-detection", "HEAD content should be pushed via clasp (batch API), not edited manually in the web IDE"),
    ("gas-version-history-integrity", "Version history must be sequential and have monotonically increasing timestamps"),
    ("gas-stale-deployment", "Deployments should not point to versions that are 2+ versions behind the latest"),
];

/// All GAS-specific control IDs.
pub const ALL_GAS_CONTROLS: &[&str] = &[
    "gas-sharing-restriction",
    "gas-editor-count-audit",
    "gas-oauth-scope-minimization",
    "gas-version-hygiene",
    "gas-deployment-version-linkage",
    "gas-description-quality",
    "gas-trigger-audit",
    "gas-external-library-audit",
    "gas-gcp-project-linkage",
    "gas-library-inventory",
    "gas-manifest-integrity",
    "gas-webapp-access-control",
    "gas-api-executable-access",
    "gas-head-drift",
    "gas-secret-scanning",
    "gas-edit-source-detection",
    "gas-version-history-integrity",
    "gas-stale-deployment",
];

/// Instantiate all GAS-specific controls with shared evidence.
pub fn gas_controls(evidence: Arc<GasProjectEvidence>) -> Vec<Box<dyn Control>> {
    vec![
        Box::new(sharing_restriction::SharingRestrictionControl::new(evidence.clone())),
        Box::new(editor_count_audit::EditorCountAuditControl::new(evidence.clone())),
        Box::new(oauth_scope_minimization::OauthScopeMinimizationControl::new(evidence.clone())),
        Box::new(version_hygiene::VersionHygieneControl::new(evidence.clone())),
        Box::new(deployment_version_linkage::DeploymentVersionLinkageControl::new(evidence.clone())),
        Box::new(description_quality::DescriptionQualityControl::new(evidence.clone())),
        Box::new(trigger_audit::TriggerAuditControl::new(evidence.clone())),
        Box::new(external_library_audit::ExternalLibraryAuditControl::new(evidence.clone())),
        Box::new(gcp_project_linkage::GcpProjectLinkageControl::new(evidence.clone())),
        Box::new(library_inventory::LibraryInventoryControl::new(evidence.clone())),
        Box::new(manifest_integrity::ManifestIntegrityControl::new(evidence.clone())),
        Box::new(webapp_access_control::WebappAccessControl::new(evidence.clone())),
        Box::new(api_executable_access::ApiExecutableAccessControl::new(evidence.clone())),
        Box::new(head_drift::HeadDriftControl::new(evidence.clone())),
        Box::new(secret_scanning::SecretScanningControl::new(evidence.clone())),
        Box::new(edit_source_detection::EditSourceDetectionControl::new(evidence.clone())),
        Box::new(version_history_integrity::VersionHistoryIntegrityControl::new(evidence.clone())),
        Box::new(stale_deployment::StaleDeploymentControl::new(evidence)),
    ]
}
