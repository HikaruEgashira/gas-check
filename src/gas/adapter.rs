use libverify_core::evidence::{EvidenceBundle, EvidenceState};

use crate::gas::evidence::GasProjectEvidence;
use crate::gas::types::Manifest;

/// Build a minimal `EvidenceBundle` from GAS project evidence.
///
/// Most fields are `NotApplicable` since GAS has no native PR/CI/build system.
/// The bundle is used by the core assessment engine; GAS-specific controls
/// receive data through `Arc<GasProjectEvidence>` instead.
pub fn build_project_bundle(evidence: &GasProjectEvidence) -> EvidenceBundle {
    let mut bundle = EvidenceBundle {
        artifact_attestations: EvidenceState::not_applicable(),
        check_runs: EvidenceState::not_applicable(),
        build_platform: EvidenceState::not_applicable(),
        ..Default::default()
    };

    // Map library dependencies to dependency signatures (partial — no signing)
    if !evidence.libraries.is_empty() {
        let deps = evidence
            .libraries
            .iter()
            .map(|lib| libverify_core::evidence::DependencySignatureEvidence {
                name: lib.user_symbol.clone(),
                version: lib.version.clone(),
                registry: Some("apps-script-library".to_string()),
                verification: libverify_core::evidence::VerificationOutcome::AttestationAbsent {
                    detail: "GAS libraries have no cryptographic signing".to_string(),
                },
                signature_mechanism: None,
                signer_identity: None,
                source_repo: Some(lib.library_id.clone()),
                source_commit: None,
                pinned_digest: None,
                actual_digest: None,
                transparency_log_uri: None,
                is_direct: true,
            })
            .collect();
        bundle.dependency_signatures = EvidenceState::complete(deps);
    }

    // Map posture from permissions
    let posture = build_posture(evidence);
    bundle.repository_posture = EvidenceState::complete(posture);

    bundle
}

fn build_posture(evidence: &GasProjectEvidence) -> libverify_core::evidence::RepositoryPosture {
    let mut posture = libverify_core::evidence::RepositoryPosture::default();

    // Map permission counts
    let editors = evidence
        .permissions
        .iter()
        .filter(|p| p.role == "writer" || p.role == "owner")
        .count();
    posture.admin_count = evidence
        .permissions
        .iter()
        .filter(|p| p.role == "owner")
        .count() as u32;
    posture.direct_collaborator_count = editors as u32;

    posture
}

/// Parse appsscript.json from script file source.
pub fn parse_manifest(source: &str) -> Result<Manifest, serde_json::Error> {
    serde_json::from_str(source)
}
