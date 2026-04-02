use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::gas::evidence::GasProjectEvidence;

const MAX_EDITORS: usize = 5;

pub struct EditorCountAuditControl {
    gas: Arc<GasProjectEvidence>,
}

impl EditorCountAuditControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

impl Control for EditorCountAuditControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-editor-count-audit")
    }

    fn description(&self) -> &'static str {
        "Number of editors on the project should be limited"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some("Reduce the number of editors to 5 or fewer by removing unnecessary collaborators")
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let editors: Vec<String> = self
            .gas
            .permissions
            .iter()
            .filter(|p| p.role == "writer" || p.role == "owner")
            .map(|p| {
                p.email_address
                    .clone()
                    .unwrap_or_else(|| p.id.clone())
            })
            .collect();

        if editors.len() <= MAX_EDITORS {
            vec![ControlFinding::satisfied(
                self.id(),
                format!("{} editor(s) (max {MAX_EDITORS})", editors.len()),
                editors,
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                format!(
                    "{} editors exceed limit of {MAX_EDITORS}",
                    editors.len()
                ),
                editors,
            )]
        }
    }
}
