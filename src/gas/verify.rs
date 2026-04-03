use std::sync::Arc;

use anyhow::{Context, Result};

use libverify_core::assessment::VerificationResult;
use libverify_core::control::Control;
use libverify_core::evidence::EvidenceBundle;
use libverify_core::control::ControlFinding;
use libverify_core::profile::{ControlProfile, ProfileOutcome, SeverityLabels};
use libverify_policy::OpaProfile;

const GAS_DEFAULT_REGO: &str = include_str!("../policies/gas-default.rego");

/// Wrapper that sets `name()` to "gas-default" while delegating all policy
/// evaluation to the embedded OPA profile.
struct GasDefaultProfile(OpaProfile);

impl ControlProfile for GasDefaultProfile {
    fn name(&self) -> &str {
        "gas-default"
    }
    fn map(&self, finding: &ControlFinding) -> ProfileOutcome {
        self.0.map(finding)
    }
    fn severity_labels(&self) -> SeverityLabels {
        self.0.severity_labels()
    }
}

use crate::controls;
use crate::gas::adapter;
use crate::gas::client::GasClient;
use crate::gas::evidence::GasProjectEvidence;
use crate::gas::types::{
    ContentResponse, DeploymentsResponse, Manifest, PermissionsResponse, Project,
    VersionsResponse,
};

/// Collect all evidence for a GAS project.
pub fn collect_project_evidence(
    client: &GasClient,
    script_id: &str,
) -> Result<GasProjectEvidence> {
    let project: Project = client
        .get_project(script_id)
        .context("failed to fetch project metadata")?;

    let content: ContentResponse = client
        .get_content(script_id)
        .context("failed to fetch project content")?;

    let versions_resp: VersionsResponse = client
        .get_versions(script_id)
        .unwrap_or(VersionsResponse {
            versions: Vec::new(),
        });

    let deployments_resp: DeploymentsResponse = client
        .get_deployments(script_id)
        .unwrap_or(DeploymentsResponse {
            deployments: Vec::new(),
        });

    // Parse manifest from appsscript.json
    let manifest_file = content
        .files
        .iter()
        .find(|f| f.name == "appsscript" && f.file_type == "JSON");

    let (manifest, manifest_raw) = match manifest_file.and_then(|f| f.source.as_ref()) {
        Some(source) => {
            let m = adapter::parse_manifest(source).unwrap_or_default();
            (m, Some(source.clone()))
        }
        None => (Manifest::default(), None),
    };

    // Fetch Drive permissions using script_id as file_id
    let permissions = client
        .get_permissions::<PermissionsResponse>(script_id)
        .map(|r| r.permissions)
        .unwrap_or_default();

    let has_explicit_gcp_project = project.parent_id.is_some();

    Ok(GasProjectEvidence {
        script_id: script_id.to_string(),
        title: project.title,
        parent_id: project.parent_id,
        oauth_scopes: manifest.oauth_scopes.clone(),
        webapp_config: manifest.webapp.clone(),
        execution_api_config: manifest.execution_api.clone(),
        libraries: manifest
            .dependencies
            .as_ref()
            .map(|d| d.libraries.clone())
            .unwrap_or_default(),
        manifest,
        manifest_raw,
        versions: versions_resp.versions,
        deployments: deployments_resp.deployments,
        permissions,
        has_explicit_gcp_project,
    })
}

/// Assess collected evidence with a policy.
pub fn assess_project(
    gas_evidence: &GasProjectEvidence,
    policy_name: Option<&str>,
) -> Result<VerificationResult> {
    let bundle = adapter::build_project_bundle(gas_evidence);
    let evidence_arc = Arc::new(gas_evidence.clone());

    let extra_controls = controls::gas_controls(evidence_arc);

    assess_bundle(&bundle, policy_name, extra_controls)
}

/// Assess an `EvidenceBundle` with extra GAS controls.
pub fn assess_bundle(
    bundle: &EvidenceBundle,
    policy_name: Option<&str>,
    extra_controls: Vec<Box<dyn Control>>,
) -> Result<VerificationResult> {
    let effective = policy_name.unwrap_or("gas-default");

    // Only use GAS-specific controls (skip built-in controls that expect GitHub data)
    let report = if effective == "gas-default" {
        let inner = OpaProfile::from_rego("gas-default.rego", GAS_DEFAULT_REGO)
            .context("loading built-in gas-default policy")?;
        let profile = GasDefaultProfile(inner);
        libverify_core::assessment::assess(bundle, &extra_controls, &profile)
    } else {
        let profile = OpaProfile::from_preset_or_file(effective)?;
        libverify_core::assessment::assess(bundle, &extra_controls, &profile)
    };

    Ok(VerificationResult {
        report,
        evidence: Some(bundle.clone()),
    })
}

/// Convenience: collect + assess in one call.
#[allow(dead_code)]
pub fn verify_project(
    client: &GasClient,
    script_id: &str,
    policy_name: Option<&str>,
) -> Result<VerificationResult> {
    let evidence = collect_project_evidence(client, script_id)?;
    assess_project(&evidence, policy_name)
}
