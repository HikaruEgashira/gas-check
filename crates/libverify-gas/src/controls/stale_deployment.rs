use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::evidence::GasProjectEvidence;

/// Number of versions behind the latest before a deployment is considered stale.
const STALENESS_THRESHOLD: i64 = 2;

/// Detects deployments that point to versions significantly behind
/// the latest, indicating forgotten or abandoned deployments that
/// may expose outdated (and potentially vulnerable) code.
///
/// Mapping to libverify-core concept: `stale-review`.
pub struct StaleDeploymentControl {
    gas: Arc<GasProjectEvidence>,
}

impl StaleDeploymentControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

impl Control for StaleDeploymentControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-stale-deployment")
    }

    fn description(&self) -> &'static str {
        "Deployments should not point to versions that are 2+ versions behind the latest"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some(
            "Update stale deployments to point to a recent version, or remove \
             them if they are no longer needed. Stale deployments may expose \
             outdated code with known vulnerabilities.",
        )
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let versions = &self.gas.versions;
        let deployments = &self.gas.deployments;

        if deployments.is_empty() || versions.is_empty() {
            return vec![ControlFinding::not_applicable(
                self.id(),
                "No deployments or no versions to evaluate",
            )];
        }

        let max_version = versions
            .iter()
            .filter_map(|v| v.version_number)
            .max()
            .unwrap_or(0);

        let mut stale: Vec<String> = Vec::new();

        for deployment in deployments {
            let config = match &deployment.deployment_config {
                Some(c) => c,
                None => continue, // HEAD deployment — skip
            };
            let dep_version = match config.version_number {
                Some(v) => v,
                None => continue, // HEAD deployment — skip
            };

            let gap = max_version - dep_version;
            if gap >= STALENESS_THRESHOLD {
                stale.push(format!(
                    "{} (version {dep_version}, {gap} behind latest {max_version})",
                    deployment.deployment_id
                ));
            }
        }

        if stale.is_empty() {
            vec![ControlFinding::satisfied(
                self.id(),
                format!(
                    "All deployments are within {STALENESS_THRESHOLD} version(s) of the latest (v{max_version})"
                ),
                vec![],
            )]
        } else {
            vec![ControlFinding::violated(
                self.id(),
                format!(
                    "{} stale deployment(s) found: {}",
                    stale.len(),
                    stale.join(", ")
                ),
                stale,
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Deployment, DeploymentConfig, Manifest, Version};
    use libverify_core::control::ControlStatus;

    fn evidence_with_deployments_and_versions(
        deployments: Vec<Deployment>,
        versions: Vec<Version>,
    ) -> Arc<GasProjectEvidence> {
        Arc::new(GasProjectEvidence {
            script_id: "test".to_string(),
            title: "test".to_string(),
            parent_id: None,
            manifest: Manifest::default(),
            manifest_raw: None,
            oauth_scopes: vec![],
            versions,
            deployments,
            permissions: vec![],
            webapp_config: None,
            execution_api_config: None,
            libraries: vec![],
            has_explicit_gcp_project: false,
            head_files: vec![],
            latest_version_files: None,
        })
    }

    fn version(num: i64) -> Version {
        Version {
            version_number: Some(num),
            description: None,
            create_time: None,
        }
    }

    fn deployment(id: &str, version_number: Option<i64>) -> Deployment {
        Deployment {
            deployment_id: id.to_string(),
            deployment_config: version_number.map(|v| DeploymentConfig {
                script_id: None,
                version_number: Some(v),
                manifest_file_name: None,
                description: None,
            }),
            update_time: None,
        }
    }

    fn default_bundle() -> EvidenceBundle {
        EvidenceBundle::default()
    }

    #[test]
    fn not_applicable_when_no_deployments() {
        let ev = evidence_with_deployments_and_versions(
            vec![],
            vec![version(1)],
        );
        let ctrl = StaleDeploymentControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn not_applicable_when_no_versions() {
        let ev = evidence_with_deployments_and_versions(
            vec![deployment("dep-1", Some(1))],
            vec![],
        );
        let ctrl = StaleDeploymentControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn satisfied_when_deployments_are_current() {
        let ev = evidence_with_deployments_and_versions(
            vec![
                deployment("dep-1", Some(5)),
                deployment("dep-2", Some(4)),
            ],
            vec![version(3), version(4), version(5)],
        );
        let ctrl = StaleDeploymentControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn violated_when_deployment_is_stale() {
        let ev = evidence_with_deployments_and_versions(
            vec![
                deployment("dep-current", Some(5)),
                deployment("dep-stale", Some(2)),
            ],
            vec![version(1), version(2), version(3), version(4), version(5)],
        );
        let ctrl = StaleDeploymentControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].subjects.iter().any(|s| s.contains("dep-stale")));
        assert!(findings[0].subjects.iter().all(|s| !s.contains("dep-current")));
    }

    #[test]
    fn skips_head_deployments_without_config() {
        let ev = evidence_with_deployments_and_versions(
            vec![
                Deployment {
                    deployment_id: "head-dep".to_string(),
                    deployment_config: None,
                    update_time: None,
                },
                deployment("versioned-dep", Some(5)),
            ],
            vec![version(5)],
        );
        let ctrl = StaleDeploymentControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn skips_head_deployments_without_version_number() {
        let ev = evidence_with_deployments_and_versions(
            vec![
                Deployment {
                    deployment_id: "head-dep".to_string(),
                    deployment_config: Some(DeploymentConfig {
                        script_id: None,
                        version_number: None,
                        manifest_file_name: None,
                        description: None,
                    }),
                    update_time: None,
                },
                deployment("versioned-dep", Some(5)),
            ],
            vec![version(5)],
        );
        let ctrl = StaleDeploymentControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn exactly_at_threshold_is_stale() {
        // Gap of exactly 2 should be stale
        let ev = evidence_with_deployments_and_versions(
            vec![deployment("dep-1", Some(3))],
            vec![version(3), version(4), version(5)],
        );
        let ctrl = StaleDeploymentControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn gap_of_one_is_not_stale() {
        let ev = evidence_with_deployments_and_versions(
            vec![deployment("dep-1", Some(4))],
            vec![version(4), version(5)],
        );
        let ctrl = StaleDeploymentControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }
}
