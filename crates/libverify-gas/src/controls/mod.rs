use std::sync::Arc;

use libverify_core::control::Control;

use crate::evidence::GasProjectEvidence;

pub mod api_executable_access;
pub mod deployment_version_linkage;
pub mod description_quality;
pub mod editor_count_audit;
pub mod external_library_audit;
pub mod gcp_project_linkage;
pub mod head_drift;
pub mod library_inventory;
pub mod manifest_integrity;
pub mod oauth_scope_minimization;
pub mod sharing_restriction;
pub mod trigger_audit;
pub mod version_hygiene;
pub mod secret_scanning;
pub mod webapp_access_control;

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
        Box::new(secret_scanning::SecretScanningControl::new(evidence)),
    ]
}
