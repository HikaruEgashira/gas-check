use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::evidence::GasProjectEvidence;

use super::util::parse_epoch;

/// Maximum spread (in seconds) between file update timestamps to classify as
/// a batch push (clasp). Beyond this, we consider it manual editing.
const BATCH_THRESHOLD_SECS: i64 = 30;

/// Classify the edit source based on file update timestamp clustering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditSource {
    /// All file timestamps cluster within the threshold — likely clasp push.
    Batch,
    /// Timestamps are spread — likely manual editor changes.
    Manual,
    /// Insufficient data to determine.
    Unknown,
}

fn detect_edit_source(evidence: &GasProjectEvidence) -> (EditSource, i64) {
    let timestamps: Vec<i64> = evidence
        .head_files
        .iter()
        .filter_map(|f| f.update_time.as_deref().and_then(parse_epoch))
        .collect();

    if timestamps.len() < 2 {
        return (EditSource::Unknown, 0);
    }

    let min_ts = timestamps.iter().copied().min().unwrap_or(0);
    let max_ts = timestamps.iter().copied().max().unwrap_or(0);
    let spread = max_ts - min_ts;

    if spread <= BATCH_THRESHOLD_SECS {
        (EditSource::Batch, spread)
    } else {
        (EditSource::Manual, spread)
    }
}

/// Detects whether HEAD content was pushed via clasp (batch API) or
/// edited manually in the web IDE, by analysing file update timestamp
/// clustering.
///
/// Mapping to libverify-core concept: this is the GAS equivalent of
/// `hosted-build-platform` — clasp acts as a CLI pipeline (comparable
/// to CI) while the web editor is an uncontrolled workstation.
pub struct EditSourceDetectionControl {
    gas: Arc<GasProjectEvidence>,
}

impl EditSourceDetectionControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

impl Control for EditSourceDetectionControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-edit-source-detection")
    }

    fn description(&self) -> &'static str {
        "HEAD content should be pushed via clasp (batch API), not edited manually in the web IDE"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some(
            "Use `clasp push` to deploy code from a local repository. \
             Manual edits in the Apps Script web editor bypass version control \
             and code review workflows.",
        )
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let (source, spread) = detect_edit_source(&self.gas);

        match source {
            EditSource::Batch => {
                vec![ControlFinding::satisfied(
                    self.id(),
                    format!(
                        "File timestamps cluster within {}s — consistent with clasp push",
                        spread
                    ),
                    vec![format!("spread:{}s", spread)],
                )]
            }
            EditSource::Manual => {
                vec![ControlFinding::violated(
                    self.id(),
                    format!(
                        "File timestamps spread over {}s — indicates manual web editor changes",
                        spread
                    ),
                    vec![format!("spread:{}s", spread)],
                )]
            }
            EditSource::Unknown => {
                vec![ControlFinding::not_applicable(
                    self.id(),
                    "Insufficient file timestamp data to determine edit source",
                )]
            }
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

    fn file_with_time(name: &str, update_time: &str) -> ScriptFile {
        ScriptFile {
            name: name.to_string(),
            file_type: "SERVER_JS".to_string(),
            source: Some("function f() {}".to_string()),
            function_set: None,
            create_time: None,
            update_time: Some(update_time.to_string()),
        }
    }

    fn default_bundle() -> EvidenceBundle {
        EvidenceBundle::default()
    }

    #[test]
    fn batch_when_timestamps_cluster() {
        let ev = evidence_with_files(vec![
            file_with_time("Code", "2025-06-01T10:00:00.000Z"),
            file_with_time("Utils", "2025-06-01T10:00:05.000Z"),
            file_with_time("Config", "2025-06-01T10:00:02.000Z"),
        ]);
        let ctrl = EditSourceDetectionControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("clasp push"));
    }

    #[test]
    fn manual_when_timestamps_spread() {
        let ev = evidence_with_files(vec![
            file_with_time("Code", "2025-06-01T10:00:00.000Z"),
            file_with_time("Utils", "2025-06-01T10:05:00.000Z"),
            file_with_time("Config", "2025-06-02T14:30:00.000Z"),
        ]);
        let ctrl = EditSourceDetectionControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("manual"));
    }

    #[test]
    fn unknown_when_single_file() {
        let ev = evidence_with_files(vec![
            file_with_time("Code", "2025-06-01T10:00:00.000Z"),
        ]);
        let ctrl = EditSourceDetectionControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn unknown_when_no_timestamps() {
        let ev = evidence_with_files(vec![
            ScriptFile {
                name: "Code".to_string(),
                file_type: "SERVER_JS".to_string(),
                source: Some("x".to_string()),
                function_set: None,
                create_time: None,
                update_time: None,
            },
            ScriptFile {
                name: "Utils".to_string(),
                file_type: "SERVER_JS".to_string(),
                source: Some("y".to_string()),
                function_set: None,
                create_time: None,
                update_time: None,
            },
        ]);
        let ctrl = EditSourceDetectionControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn edge_case_exactly_at_threshold() {
        let ev = evidence_with_files(vec![
            file_with_time("A", "2025-06-01T10:00:00.000Z"),
            file_with_time("B", "2025-06-01T10:00:30.000Z"),
        ]);
        let ctrl = EditSourceDetectionControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        // 30s is exactly at threshold — classified as batch
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

}
