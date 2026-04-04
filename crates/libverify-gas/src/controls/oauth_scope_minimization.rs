use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::evidence::GasProjectEvidence;

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
        Some("Explicitly declare oauthScopes in appsscript.json with the narrowest alternatives (e.g., spreadsheets.currentonly instead of spreadsheets). Omitting oauthScopes causes GAS to auto-infer permissions at runtime.")
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        // No explicit scopes means GAS auto-infers scopes at runtime,
        // granting whatever permissions the code appears to need — this
        // bypasses any least-privilege review.
        if self.gas.oauth_scopes.is_empty() {
            return vec![ControlFinding::violated(
                self.id(),
                "No oauthScopes declared in appsscript.json; GAS will auto-infer broad scopes at runtime".to_string(),
                vec!["(implicit: auto-inferred by runtime)".to_string()],
            )];
        }

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
