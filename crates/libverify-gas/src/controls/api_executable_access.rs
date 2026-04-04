use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::evidence::GasProjectEvidence;

pub struct ApiExecutableAccessControl {
    gas: Arc<GasProjectEvidence>,
}

impl ApiExecutableAccessControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

impl Control for ApiExecutableAccessControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-api-executable-access")
    }

    fn description(&self) -> &'static str {
        "API executable deployments must restrict access"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some("Set executionApi access to 'MYSELF' or 'DOMAIN' instead of 'ANYONE'")
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let Some(exec_api) = &self.gas.execution_api_config else {
            return vec![ControlFinding::not_applicable(
                self.id(),
                "No API executable configuration in manifest",
            )];
        };

        let access = exec_api.access.as_deref().unwrap_or("UNKNOWN");

        match access {
            "MYSELF" | "DOMAIN" => vec![ControlFinding::satisfied(
                self.id(),
                format!("API executable access restricted to: {access}"),
                vec![self.gas.script_id.clone()],
            )],
            "ANYONE" | "ANYONE_ANONYMOUS" => vec![ControlFinding::violated(
                self.id(),
                format!("API executable is accessible by: {access}"),
                vec![self.gas.script_id.clone()],
            )],
            _ => vec![ControlFinding::violated(
                self.id(),
                format!("Unknown API executable access level: {access}"),
                vec![self.gas.script_id.clone()],
            )],
        }
    }
}
