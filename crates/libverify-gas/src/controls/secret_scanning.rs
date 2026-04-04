use std::collections::HashSet;
use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;
use libverify_secret_scan::Scanner;

use crate::evidence::GasProjectEvidence;

/// Scans GAS project source code for hardcoded secrets.
///
/// Delegates to `libverify-secret-scan` for the platform-agnostic scanning
/// engine and adds GAS-specific allowlist patterns (e.g., PropertiesService
/// calls which are the recommended remediation, not a leak).
///
/// Unlike libverify-core's `SecretScanningControl` which checks whether a
/// platform feature (GitHub secret scanning) is enabled, this control performs
/// actual content-based scanning — because GAS has no such platform protection.
pub struct SecretScanningControl {
    gas: Arc<GasProjectEvidence>,
}

impl SecretScanningControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

/// GAS-specific allowlist patterns that suppress false positives.
const GAS_ALLOWLIST_PATTERNS: &[&str] = &[
    // PropertiesService is the remediation, not a leak
    r"(?i)PropertiesService\.",
    // Common GAS boilerplate identifiers
    r"(?i)(?:spreadsheet|calendar|trigger|document)\.get",
];

impl Control for SecretScanningControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-secret-scanning")
    }

    fn description(&self) -> &'static str {
        "Source files must not contain hardcoded secrets (API keys, tokens, passwords, private keys)"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some(
            "Move secrets to PropertiesService (Script/User/Document properties) \
             and retrieve them at runtime with PropertiesService.getScriptProperties().getProperty(key). \
             Never commit credentials in source files.",
        )
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let mut scanner = Scanner::new();
        scanner.add_allowlist_patterns(GAS_ALLOWLIST_PATTERNS);

        let mut all_hits = Vec::new();
        for file in &self.gas.head_files {
            let source = match &file.source {
                Some(s) => s,
                None => continue,
            };
            all_hits.extend(scanner.scan(&file.name, source));
        }

        if all_hits.is_empty() {
            vec![ControlFinding::satisfied(
                self.id(),
                format!(
                    "Scanned {} file(s) against {} rules, no hardcoded secrets detected",
                    self.gas.head_files.len(),
                    scanner.rule_count(),
                ),
                self.gas
                    .head_files
                    .iter()
                    .map(|f| f.name.clone())
                    .collect(),
            )]
        } else {
            let subjects: Vec<String> = all_hits
                .iter()
                .map(|h| format!("{}:L{} [{}]", h.file, h.line, h.rule_id))
                .collect();
            let affected_files: HashSet<&str> =
                all_hits.iter().map(|h| h.file.as_str()).collect();
            vec![ControlFinding::violated(
                self.id(),
                format!(
                    "{} potential secret(s) detected in {} file(s)",
                    all_hits.len(),
                    affected_files.len(),
                ),
                subjects,
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Manifest, ScriptFile};
    use libverify_core::control::ControlStatus;

    fn evidence_with_files(files: Vec<ScriptFile>) -> Arc<GasProjectEvidence> {
        Arc::new(GasProjectEvidence {
            script_id: "test".to_string(),
            title: "test".to_string(),
            parent_id: None,
            manifest: Manifest::default(),
            manifest_raw: None,
            oauth_scopes: vec![],
            versions: vec![],
            deployments: vec![],
            permissions: vec![],
            webapp_config: None,
            execution_api_config: None,
            libraries: vec![],
            has_explicit_gcp_project: false,
            head_files: files,
            latest_version_files: None,
        })
    }

    fn script_file(name: &str, source: &str) -> ScriptFile {
        ScriptFile {
            name: name.to_string(),
            file_type: "SERVER_JS".to_string(),
            source: Some(source.to_string()),
            function_set: None,
            create_time: None,
            update_time: None,
        }
    }

    fn default_bundle() -> EvidenceBundle {
        EvidenceBundle::default()
    }

    fn evaluate(source: &str) -> Vec<ControlFinding> {
        let ev = evidence_with_files(vec![script_file("Test", source)]);
        SecretScanningControl::new(ev).evaluate(&default_bundle())
    }

    #[test]
    fn satisfied_when_no_secrets() {
        let findings = evaluate("function main() {\n  Logger.log('hello');\n}");
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn detects_google_api_key() {
        let findings =
            evaluate("var API_KEY = 'AIzaSyA1234567890abcdefghijklmnopqrstuvw';");
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects[0].contains("google-api-key"));
    }

    #[test]
    fn detects_aws_access_key() {
        let findings = evaluate("var key = 'AKIAIOSFODNN7EXAMPLE';");
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects[0].contains("aws-access-key-id"));
    }

    #[test]
    fn detects_private_key_pem() {
        let findings =
            evaluate("var pk = '-----BEGIN RSA PRIVATE KEY-----\\nMIIEow...';");
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn fp_suppressed_for_properties_service() {
        let findings = evaluate(
            r#"var key = PropertiesService.getScriptProperties().getProperty("API_KEY");"#,
        );
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn reports_multiple_hits_across_files() {
        let ev = evidence_with_files(vec![
            script_file(
                "Config",
                "var API_KEY = 'AIzaSyA1234567890abcdefghijklmnopqrstuvw';",
            ),
            script_file("Secrets", "var key = 'AKIAIOSFODNN7EXAMPLE';"),
        ]);
        let ctrl = SecretScanningControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("2 file(s)"));
    }

    #[test]
    fn skips_files_without_source() {
        let ev = evidence_with_files(vec![ScriptFile {
            name: "NoSource".to_string(),
            file_type: "SERVER_JS".to_string(),
            source: None,
            function_set: None,
            create_time: None,
            update_time: None,
        }]);
        let ctrl = SecretScanningControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }
}
