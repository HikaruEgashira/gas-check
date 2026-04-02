use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::gas::evidence::GasProjectEvidence;

pub struct SharingRestrictionControl {
    gas: Arc<GasProjectEvidence>,
}

impl SharingRestrictionControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

impl Control for SharingRestrictionControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-sharing-restriction")
    }

    fn description(&self) -> &'static str {
        "Project must not be shared broadly (no 'anyone' or 'domain' permissions)"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some("Remove 'anyone' and 'domain' sharing permissions from the GAS project in Google Drive")
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let broad_shares: Vec<String> = self
            .gas
            .permissions
            .iter()
            .filter(|p| p.permission_type == "anyone" || p.permission_type == "domain")
            .map(|p| format!("type={}, role={}", p.permission_type, p.role))
            .collect();

        if broad_shares.is_empty() {
            vec![ControlFinding::satisfied(
                self.id(),
                "No broad sharing permissions found",
                vec![self.gas.script_id.clone()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                format!(
                    "Project has {} broad sharing permission(s): {}",
                    broad_shares.len(),
                    broad_shares.join(", ")
                ),
                vec![self.gas.script_id.clone()],
            )]
        }
    }
}
