use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::evidence::GasProjectEvidence;

pub struct GcpProjectLinkageControl {
    gas: Arc<GasProjectEvidence>,
}

impl GcpProjectLinkageControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

impl Control for GcpProjectLinkageControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-gcp-project-linkage")
    }

    fn description(&self) -> &'static str {
        "Project should be linked to an explicit GCP project (not the default invisible project)"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some("Link the GAS project to a managed GCP project via the Apps Script settings")
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        if self.gas.has_explicit_gcp_project {
            vec![ControlFinding::satisfied(
                self.id(),
                format!(
                    "Project linked to GCP project: {}",
                    self.gas.parent_id.as_deref().unwrap_or("unknown")
                ),
                vec![self.gas.script_id.clone()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                "Project uses default invisible GCP project",
                vec![self.gas.script_id.clone()],
            )]
        }
    }
}
