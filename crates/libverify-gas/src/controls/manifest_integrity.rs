use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::evidence::GasProjectEvidence;

pub struct ManifestIntegrityControl {
    gas: Arc<GasProjectEvidence>,
}

impl ManifestIntegrityControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

impl Control for ManifestIntegrityControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-manifest-integrity")
    }

    fn description(&self) -> &'static str {
        "appsscript.json must be well-formed and declare expected runtime version"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some("Ensure appsscript.json is valid JSON with a runtimeVersion field set to 'V8'")
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        if self.gas.manifest_raw.is_none() {
            return vec![ControlFinding::violated(
                self.id(),
                "appsscript.json not found in project content",
                vec![self.gas.script_id.clone()],
            )];
        }

        let mut issues: Vec<String> = Vec::new();

        if self.gas.manifest.time_zone.is_none() {
            issues.push("missing timeZone".to_string());
        }

        if self.gas.manifest.runtime_version.is_none() {
            issues.push("missing runtimeVersion (should be V8)".to_string());
        } else if self.gas.manifest.runtime_version.as_deref() != Some("V8") {
            issues.push(format!(
                "runtimeVersion is '{}', expected 'V8'",
                self.gas.manifest.runtime_version.as_deref().unwrap_or("")
            ));
        }

        if issues.is_empty() {
            vec![ControlFinding::satisfied(
                self.id(),
                "appsscript.json is well-formed with V8 runtime",
                vec![self.gas.script_id.clone()],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                format!("Manifest issues: {}", issues.join("; ")),
                issues,
            )]
        }
    }
}
