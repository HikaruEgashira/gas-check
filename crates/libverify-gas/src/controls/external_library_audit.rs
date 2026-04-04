use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::evidence::GasProjectEvidence;

pub struct ExternalLibraryAuditControl {
    gas: Arc<GasProjectEvidence>,
}

impl ExternalLibraryAuditControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

impl Control for ExternalLibraryAuditControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-external-library-audit")
    }

    fn description(&self) -> &'static str {
        "External libraries must be pinned to specific versions (not development mode)"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some("Disable development mode on all library dependencies and pin to specific versions")
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        if self.gas.libraries.is_empty() {
            return vec![ControlFinding::not_applicable(
                self.id(),
                "No external libraries declared",
            )];
        }

        let dev_mode: Vec<String> = self
            .gas
            .libraries
            .iter()
            .filter(|lib| lib.development_mode)
            .map(|lib| format!("{} ({})", lib.user_symbol, lib.library_id))
            .collect();

        if dev_mode.is_empty() {
            vec![ControlFinding::satisfied(
                self.id(),
                format!(
                    "All {} library(ies) pinned to specific versions",
                    self.gas.libraries.len()
                ),
                self.gas
                    .libraries
                    .iter()
                    .map(|l| format!("{}@{}", l.user_symbol, l.version))
                    .collect(),
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                format!(
                    "{} library(ies) in development mode (unpinned)",
                    dev_mode.len()
                ),
                dev_mode,
            )]
        }
    }
}
