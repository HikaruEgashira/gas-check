use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::gas::evidence::GasProjectEvidence;

pub struct WebappAccessControl {
    gas: Arc<GasProjectEvidence>,
}

impl WebappAccessControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

impl Control for WebappAccessControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-webapp-access-control")
    }

    fn description(&self) -> &'static str {
        "Web app deployments must restrict access (not 'ANYONE_ANONYMOUS')"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some("Set web app access to 'MYSELF' or 'DOMAIN' instead of 'ANYONE' or 'ANYONE_ANONYMOUS'")
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let Some(webapp) = &self.gas.webapp_config else {
            return vec![ControlFinding::not_applicable(
                self.id(),
                "No web app configuration in manifest",
            )];
        };

        let access = webapp.access.as_deref().unwrap_or("UNKNOWN");

        match access {
            "MYSELF" | "DOMAIN" => vec![ControlFinding::satisfied(
                self.id(),
                format!("Web app access restricted to: {access}"),
                vec![self.gas.script_id.clone()],
            )],
            "ANYONE" | "ANYONE_ANONYMOUS" => vec![ControlFinding::violated(
                self.id(),
                format!("Web app is accessible by: {access}"),
                vec![self.gas.script_id.clone()],
            )],
            _ => vec![ControlFinding::violated(
                self.id(),
                format!("Unknown web app access level: {access}"),
                vec![self.gas.script_id.clone()],
            )],
        }
    }
}
