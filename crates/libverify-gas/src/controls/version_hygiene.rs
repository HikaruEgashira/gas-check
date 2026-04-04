use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::evidence::GasProjectEvidence;
use crate::types::Deployment;

/// The GAS platform auto-creates a read-only @HEAD deployment with updateTime set to
/// the Unix epoch ("1970-01-01T00:00:00Z"). This deployment cannot be deleted or
/// reassigned via the API and should be excluded from version-hygiene checks.
fn is_system_head_deployment(d: &Deployment) -> bool {
    d.update_time.as_deref() == Some("1970-01-01T00:00:00Z")
}

pub struct VersionHygieneControl {
    gas: Arc<GasProjectEvidence>,
}

impl VersionHygieneControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

impl Control for VersionHygieneControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-version-hygiene")
    }

    fn description(&self) -> &'static str {
        "Deployments must reference a specific version, not HEAD"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some("Pin each deployment to a specific version number instead of using HEAD")
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        if self.gas.deployments.is_empty() {
            return vec![ControlFinding::not_applicable(
                self.id(),
                "No deployments found",
            )];
        }

        // The system-generated @HEAD deployment has updateTime = "1970-01-01T00:00:00Z"
        // (Unix epoch sentinel). It cannot be deleted or reassigned via the API, so
        // exclude it from this check to avoid a permanent false positive.
        let head_deployments: Vec<String> = self
            .gas
            .deployments
            .iter()
            .filter(|d| !is_system_head_deployment(d))
            .filter(|d| matches!(&d.deployment_config, Some(c) if c.version_number.is_none()))
            .map(|d| d.deployment_id.clone())
            .collect();

        if head_deployments.is_empty() {
            vec![ControlFinding::satisfied(
                self.id(),
                format!(
                    "All {} deployment(s) reference a specific version",
                    self.gas.deployments.len()
                ),
                self.gas
                    .deployments
                    .iter()
                    .map(|d| d.deployment_id.clone())
                    .collect(),
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                format!(
                    "{} deployment(s) reference HEAD instead of a pinned version",
                    head_deployments.len()
                ),
                head_deployments,
            )]
        }
    }
}
