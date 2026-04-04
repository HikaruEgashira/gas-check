use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::evidence::GasProjectEvidence;

use super::util::parse_epoch;

/// Checks version history for anomalies: sequential numbering and
/// monotonically increasing timestamps.
///
/// Mapping to libverify-core concept: `branch-history-integrity`.
pub struct VersionHistoryIntegrityControl {
    gas: Arc<GasProjectEvidence>,
}

impl VersionHistoryIntegrityControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

impl Control for VersionHistoryIntegrityControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-version-history-integrity")
    }

    fn description(&self) -> &'static str {
        "Version history must be sequential and have monotonically increasing timestamps"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some(
            "Investigate gaps or timestamp anomalies in version history. \
             Version deletions or clock skew may indicate tampering or \
             operational issues.",
        )
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let versions = &self.gas.versions;

        if versions.len() <= 1 {
            return vec![ControlFinding::satisfied(
                self.id(),
                format!(
                    "Version history integrity trivially holds ({} version(s))",
                    versions.len()
                ),
                vec![],
            )];
        }

        // Collect versions that have a version_number, sorted by number
        let mut numbered: Vec<(i64, Option<&str>)> = versions
            .iter()
            .filter_map(|v| {
                v.version_number
                    .map(|n| (n, v.create_time.as_deref()))
            })
            .collect();
        numbered.sort_by_key(|(n, _)| *n);

        let mut anomalies: Vec<String> = Vec::new();

        // Check for gaps in version numbers
        for window in numbered.windows(2) {
            let (prev_num, _) = window[0];
            let (curr_num, _) = window[1];
            if curr_num != prev_num + 1 {
                anomalies.push(format!(
                    "gap: version {prev_num} -> {curr_num} (expected {})",
                    prev_num + 1
                ));
            }
        }

        // Check for monotonically increasing timestamps
        let timestamps: Vec<(i64, i64)> = numbered
            .iter()
            .filter_map(|(num, ts)| {
                ts.and_then(|t| parse_epoch(t).map(|epoch| (*num, epoch)))
            })
            .collect();

        for window in timestamps.windows(2) {
            let (prev_num, prev_epoch) = window[0];
            let (curr_num, curr_epoch) = window[1];
            if curr_epoch < prev_epoch {
                anomalies.push(format!(
                    "timestamp regression: version {curr_num} is earlier than version {prev_num}"
                ));
            }
        }

        if anomalies.is_empty() {
            vec![ControlFinding::satisfied(
                self.id(),
                format!(
                    "Version history is sequential and timestamps are monotonic ({} versions)",
                    versions.len()
                ),
                vec![],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                format!(
                    "{} anomaly(ies) found in version history: {}",
                    anomalies.len(),
                    anomalies.join("; ")
                ),
                anomalies,
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Manifest, Version};
    use libverify_core::control::ControlStatus;

    fn evidence_with_versions(versions: Vec<Version>) -> Arc<GasProjectEvidence> {
        Arc::new(GasProjectEvidence {
            script_id: "test".to_string(),
            title: "test".to_string(),
            parent_id: None,
            manifest: Manifest::default(),
            manifest_raw: None,
            oauth_scopes: vec![],
            versions,
            deployments: vec![],
            permissions: vec![],
            webapp_config: None,
            execution_api_config: None,
            libraries: vec![],
            has_explicit_gcp_project: false,
            head_files: vec![],
            latest_version_files: None,
        })
    }

    fn version(num: i64, time: &str) -> Version {
        Version {
            version_number: Some(num),
            description: None,
            create_time: Some(time.to_string()),
        }
    }

    fn default_bundle() -> EvidenceBundle {
        EvidenceBundle::default()
    }

    #[test]
    fn satisfied_with_zero_versions() {
        let ev = evidence_with_versions(vec![]);
        let ctrl = VersionHistoryIntegrityControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn satisfied_with_one_version() {
        let ev = evidence_with_versions(vec![
            version(1, "2025-06-01T10:00:00.000Z"),
        ]);
        let ctrl = VersionHistoryIntegrityControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn satisfied_with_sequential_versions() {
        let ev = evidence_with_versions(vec![
            version(1, "2025-06-01T10:00:00.000Z"),
            version(2, "2025-06-02T10:00:00.000Z"),
            version(3, "2025-06-03T10:00:00.000Z"),
        ]);
        let ctrl = VersionHistoryIntegrityControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_with_gap_in_versions() {
        let ev = evidence_with_versions(vec![
            version(1, "2025-06-01T10:00:00.000Z"),
            version(3, "2025-06-02T10:00:00.000Z"),
            version(5, "2025-06-03T10:00:00.000Z"),
        ]);
        let ctrl = VersionHistoryIntegrityControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects.iter().any(|s| s.contains("gap")));
    }

    #[test]
    fn violated_with_timestamp_regression() {
        let ev = evidence_with_versions(vec![
            version(1, "2025-06-03T10:00:00.000Z"),
            version(2, "2025-06-02T10:00:00.000Z"),
            version(3, "2025-06-04T10:00:00.000Z"),
        ]);
        let ctrl = VersionHistoryIntegrityControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects.iter().any(|s| s.contains("timestamp regression")));
    }

    #[test]
    fn violated_with_both_gap_and_regression() {
        let ev = evidence_with_versions(vec![
            version(1, "2025-06-03T10:00:00.000Z"),
            version(3, "2025-06-01T10:00:00.000Z"),
        ]);
        let ctrl = VersionHistoryIntegrityControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert_eq!(findings[0].subjects.len(), 2);
    }

    #[test]
    fn handles_unsorted_input() {
        // Versions provided out of order should still be checked correctly
        let ev = evidence_with_versions(vec![
            version(3, "2025-06-03T10:00:00.000Z"),
            version(1, "2025-06-01T10:00:00.000Z"),
            version(2, "2025-06-02T10:00:00.000Z"),
        ]);
        let ctrl = VersionHistoryIntegrityControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }
}
