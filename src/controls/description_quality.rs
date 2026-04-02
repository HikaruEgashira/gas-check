use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::gas::evidence::GasProjectEvidence;

const MIN_DESCRIPTION_LEN: usize = 10;

pub struct DescriptionQualityControl {
    gas: Arc<GasProjectEvidence>,
}

impl DescriptionQualityControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

impl Control for DescriptionQualityControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-description-quality")
    }

    fn description(&self) -> &'static str {
        "Versions should have meaningful descriptions"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some("Add a meaningful description (10+ chars) to each version when creating it")
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        if self.gas.versions.is_empty() {
            return vec![ControlFinding::not_applicable(
                self.id(),
                "No versions found",
            )];
        }

        let missing: Vec<String> = self
            .gas
            .versions
            .iter()
            .filter(|v| {
                v.description
                    .as_ref()
                    .is_none_or(|d| d.trim().len() < MIN_DESCRIPTION_LEN)
            })
            .map(|v| format!("v{}", v.version_number.unwrap_or(0)))
            .collect();

        if missing.is_empty() {
            vec![ControlFinding::satisfied(
                self.id(),
                format!(
                    "All {} version(s) have meaningful descriptions",
                    self.gas.versions.len()
                ),
                vec![],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                format!(
                    "{} version(s) lack meaningful descriptions",
                    missing.len()
                ),
                missing,
            )]
        }
    }
}
