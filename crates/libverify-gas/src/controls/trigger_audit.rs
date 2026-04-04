use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::evidence::GasProjectEvidence;

/// Scopes that represent elevated privilege for triggers.
const ELEVATED_TRIGGER_SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/script.external_request",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/drive",
];

pub struct TriggerAuditControl {
    gas: Arc<GasProjectEvidence>,
}

impl TriggerAuditControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

impl Control for TriggerAuditControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-trigger-audit")
    }

    fn description(&self) -> &'static str {
        "Audit OAuth scopes available to triggers for appropriate privilege level"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some("Review and reduce OAuth scopes that are accessible via triggers to minimize automated privilege")
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        // GAS triggers run with the project's full OAuth scopes.
        // If the project has elevated scopes, any trigger gets those privileges.
        let elevated: Vec<String> = self
            .gas
            .oauth_scopes
            .iter()
            .filter(|s| ELEVATED_TRIGGER_SCOPES.iter().any(|e| s.contains(e)))
            .cloned()
            .collect();

        if elevated.is_empty() {
            vec![ControlFinding::satisfied(
                self.id(),
                "No elevated scopes available to triggers",
                vec![],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                format!(
                    "{} elevated scope(s) available to triggers",
                    elevated.len()
                ),
                elevated,
            )]
        }
    }
}
