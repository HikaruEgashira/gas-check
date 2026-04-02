use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::gas::evidence::GasProjectEvidence;

pub struct DeploymentVersionLinkageControl {
    gas: Arc<GasProjectEvidence>,
}

impl DeploymentVersionLinkageControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

impl Control for DeploymentVersionLinkageControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-deployment-version-linkage")
    }

    fn description(&self) -> &'static str {
        "Every active deployment must be linked to an existing version"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some("Create a version for each deployment and link deployments to valid version numbers")
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        if self.gas.deployments.is_empty() {
            return vec![ControlFinding::not_applicable(
                self.id(),
                "No deployments found",
            )];
        }

        let version_numbers: Vec<i64> = self
            .gas
            .versions
            .iter()
            .filter_map(|v| v.version_number)
            .collect();

        let unlinked: Vec<String> = self
            .gas
            .deployments
            .iter()
            .filter(|d| {
                let ver = d
                    .deployment_config
                    .as_ref()
                    .and_then(|c| c.version_number);
                match ver {
                    Some(v) => !version_numbers.contains(&v),
                    None => true,
                }
            })
            .map(|d| d.deployment_id.clone())
            .collect();

        if unlinked.is_empty() {
            vec![ControlFinding::satisfied(
                self.id(),
                "All deployments linked to valid versions",
                self.gas
                    .deployments
                    .iter()
                    .map(|d| d.deployment_id.clone())
                    .collect(),
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                format!("{} deployment(s) not linked to a valid version", unlinked.len()),
                unlinked,
            )]
        }
    }
}
