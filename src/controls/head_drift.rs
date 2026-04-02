use std::collections::HashMap;
use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::gas::evidence::GasProjectEvidence;

pub struct HeadDriftControl {
    gas: Arc<GasProjectEvidence>,
}

impl HeadDriftControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

impl Control for HeadDriftControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-head-drift")
    }

    fn description(&self) -> &'static str {
        "HEAD must not diverge from the latest version (no unversioned changes in production)"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some("Create a new version to capture the current HEAD changes before they run in production")
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let version_files = match &self.gas.latest_version_files {
            Some(files) => files,
            None => {
                if self.gas.versions.is_empty() {
                    return vec![ControlFinding::violated(
                        self.id(),
                        "No versions exist; all execution runs unversioned HEAD code".to_string(),
                        vec![],
                    )];
                }
                return vec![ControlFinding::not_applicable(
                    self.id(),
                    "Could not retrieve latest version content for comparison",
                )];
            }
        };

        let version_map: HashMap<&str, Option<&str>> = version_files
            .iter()
            .map(|f| (f.name.as_str(), f.source.as_deref()))
            .collect();

        let head_map: HashMap<&str, Option<&str>> = self
            .gas
            .head_files
            .iter()
            .map(|f| (f.name.as_str(), f.source.as_deref()))
            .collect();

        let mut drifted: Vec<String> = Vec::new();

        // Files modified or added in HEAD
        for (name, head_source) in &head_map {
            match version_map.get(name) {
                Some(ver_source) if ver_source == head_source => {}
                _ => drifted.push((*name).to_string()),
            }
        }

        // Files deleted in HEAD (present in version but not in HEAD)
        for name in version_map.keys() {
            if !head_map.contains_key(name) {
                drifted.push(format!("{name} (deleted)"));
            }
        }

        drifted.sort();

        if drifted.is_empty() {
            vec![ControlFinding::satisfied(
                self.id(),
                "HEAD matches the latest version".to_string(),
                vec![],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                format!(
                    "{} file(s) differ between HEAD and latest version: {}",
                    drifted.len(),
                    drifted.join(", ")
                ),
                drifted,
            )]
        }
    }
}
