use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::gas::evidence::GasProjectEvidence;

/// Scopes that grant overly broad access and should be avoided.
const DANGEROUS_SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/script.external_request",
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/admin.directory.user",
    "https://www.googleapis.com/auth/script.send_mail",
];

pub struct OauthScopeMinimizationControl {
    gas: Arc<GasProjectEvidence>,
}

impl OauthScopeMinimizationControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

impl Control for OauthScopeMinimizationControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-oauth-scope-minimization")
    }

    fn description(&self) -> &'static str {
        "OAuth scopes in appsscript.json should follow least-privilege principle"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some("Replace broad OAuth scopes with narrower alternatives (e.g., use spreadsheets.currentonly instead of spreadsheets)")
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let flagged: Vec<String> = self
            .gas
            .oauth_scopes
            .iter()
            .filter(|s| DANGEROUS_SCOPES.iter().any(|d| s.contains(d)))
            .cloned()
            .collect();

        if flagged.is_empty() {
            vec![ControlFinding::satisfied(
                self.id(),
                format!(
                    "{} scope(s) declared, none flagged as overly broad",
                    self.gas.oauth_scopes.len()
                ),
                self.gas.oauth_scopes.clone(),
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                format!(
                    "{} overly broad scope(s) detected",
                    flagged.len()
                ),
                flagged,
            )]
        }
    }
}
