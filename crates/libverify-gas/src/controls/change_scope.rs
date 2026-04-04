use std::collections::HashMap;
use std::sync::Arc;

use libverify_core::control::{Control, ControlFinding, ControlId};
use libverify_core::evidence::EvidenceBundle;

use crate::evidence::GasProjectEvidence;

/// Maximum number of changed files before the change is considered too broad.
const MAX_FILES_CHANGED: usize = 5;
/// Maximum number of changed lines before the change is considered too broad.
const MAX_LINES_CHANGED: usize = 500;

/// Count line-level differences between two sources using a simple
/// line-by-line comparison (not a proper diff algorithm, but sufficient
/// for an approximation of change magnitude).
fn count_line_diff(old: &str, new: &str) -> usize {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();

    let mut changes = 0;
    let max_len = old_lines.len().max(new_lines.len());
    for i in 0..max_len {
        let ol = old_lines.get(i).copied();
        let nl = new_lines.get(i).copied();
        if ol != nl {
            changes += 1;
        }
    }
    changes
}

/// Measures the scope of changes between HEAD and the latest versioned
/// snapshot to ensure changes are incremental and reviewable.
///
/// Mapping to libverify-core concept: `change-request-size` / `scoped-change`.
pub struct ChangeScopeControl {
    gas: Arc<GasProjectEvidence>,
}

impl ChangeScopeControl {
    pub fn new(gas: Arc<GasProjectEvidence>) -> Self {
        Self { gas }
    }
}

impl Control for ChangeScopeControl {
    fn id(&self) -> ControlId {
        ControlId::new("gas-change-scope")
    }

    fn description(&self) -> &'static str {
        "Changes between HEAD and the latest version should be small and scoped"
    }

    fn remediation_hint(&self) -> Option<&'static str> {
        Some(
            "Break large changes into smaller, incremental versions. \
             Each version should represent a focused, reviewable unit of work.",
        )
    }

    fn evaluate(&self, _evidence: &EvidenceBundle) -> Vec<ControlFinding> {
        let version_files = match &self.gas.latest_version_files {
            Some(files) => files,
            None => {
                return vec![ControlFinding::not_applicable(
                    self.id(),
                    "No versions exist; cannot compare HEAD against a baseline",
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

        let mut changed_files: Vec<String> = Vec::new();
        let mut total_lines_changed: usize = 0;

        // Files added or modified in HEAD
        for (name, head_source) in &head_map {
            match version_map.get(name) {
                Some(ver_source) if ver_source == head_source => {
                    // Identical — no change
                }
                Some(ver_source) => {
                    // Modified
                    let old = ver_source.unwrap_or("");
                    let new = head_source.unwrap_or("");
                    let lines = count_line_diff(old, new);
                    total_lines_changed += lines;
                    changed_files.push(format!("{name} (modified, {lines} lines)"));
                }
                None => {
                    // Added
                    let lines = head_source.map_or(0, |s| s.lines().count());
                    total_lines_changed += lines;
                    changed_files.push(format!("{name} (added, {lines} lines)"));
                }
            }
        }

        // Files deleted in HEAD
        for (name, ver_source) in &version_map {
            if !head_map.contains_key(name) {
                let lines = ver_source.map_or(0, |s| s.lines().count());
                total_lines_changed += lines;
                changed_files.push(format!("{name} (deleted, {lines} lines)"));
            }
        }

        changed_files.sort();
        let files_changed = changed_files.len();

        if files_changed == 0 {
            return vec![ControlFinding::satisfied(
                self.id(),
                "No changes between HEAD and latest version".to_string(),
                vec![],
            )];
        }

        let mut subjects = changed_files.clone();
        subjects.push(format!("total_lines:{total_lines_changed}"));
        subjects.push(format!("files_changed:{files_changed}"));

        if files_changed > MAX_FILES_CHANGED || total_lines_changed > MAX_LINES_CHANGED {
            vec![ControlFinding::violated(
                self.id(),
                format!(
                    "Change scope too broad: {files_changed} file(s), {total_lines_changed} line(s) changed \
                     (thresholds: {MAX_FILES_CHANGED} files, {MAX_LINES_CHANGED} lines)"
                ),
                subjects,
            )]
        } else {
            vec![ControlFinding::satisfied(
                self.id(),
                format!(
                    "Change scope within bounds: {files_changed} file(s), {total_lines_changed} line(s) changed"
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

    fn make_file(name: &str, source: &str) -> ScriptFile {
        ScriptFile {
            name: name.to_string(),
            file_type: "SERVER_JS".to_string(),
            source: Some(source.to_string()),
            function_set: None,
            create_time: None,
            update_time: None,
        }
    }

    fn evidence_with_head_and_version(
        head: Vec<ScriptFile>,
        version: Option<Vec<ScriptFile>>,
    ) -> Arc<GasProjectEvidence> {
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
            head_files: head,
            latest_version_files: version,
        })
    }

    fn default_bundle() -> EvidenceBundle {
        EvidenceBundle::default()
    }

    #[test]
    fn not_applicable_when_no_versions() {
        let ev = evidence_with_head_and_version(
            vec![make_file("Code", "function f() {}")],
            None,
        );
        let ctrl = ChangeScopeControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::NotApplicable);
    }

    #[test]
    fn satisfied_when_no_changes() {
        let files = vec![make_file("Code", "function f() {}")];
        let ev = evidence_with_head_and_version(files.clone(), Some(files));
        let ctrl = ChangeScopeControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
    }

    #[test]
    fn satisfied_when_small_change() {
        let head = vec![make_file("Code", "function f() { return 1; }")];
        let version = vec![make_file("Code", "function f() { return 0; }")];
        let ev = evidence_with_head_and_version(head, Some(version));
        let ctrl = ChangeScopeControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        assert!(findings[0].rationale.contains("1 file(s)"));
    }

    #[test]
    fn violated_when_too_many_files() {
        let mut head = Vec::new();
        let mut version = Vec::new();
        for i in 0..7 {
            head.push(make_file(&format!("File{i}"), &format!("v2_{i}")));
            version.push(make_file(&format!("File{i}"), &format!("v1_{i}")));
        }
        let ev = evidence_with_head_and_version(head, Some(version));
        let ctrl = ChangeScopeControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Violated);
        assert!(findings[0].rationale.contains("7 file(s)"));
    }

    #[test]
    fn violated_when_too_many_lines() {
        // Create a file with >500 lines of changes
        let old_src = (0..600).map(|i| format!("line_old_{i}")).collect::<Vec<_>>().join("\n");
        let new_src = (0..600).map(|i| format!("line_new_{i}")).collect::<Vec<_>>().join("\n");
        let ev = evidence_with_head_and_version(
            vec![make_file("BigFile", &new_src)],
            Some(vec![make_file("BigFile", &old_src)]),
        );
        let ctrl = ChangeScopeControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Violated);
    }

    #[test]
    fn detects_added_and_deleted_files() {
        let head = vec![
            make_file("Existing", "same"),
            make_file("NewFile", "added content"),
        ];
        let version = vec![
            make_file("Existing", "same"),
            make_file("OldFile", "removed content"),
        ];
        let ev = evidence_with_head_and_version(head, Some(version));
        let ctrl = ChangeScopeControl::new(ev);
        let findings = ctrl.evaluate(&default_bundle());
        assert_eq!(findings[0].status, ControlStatus::Satisfied);
        // Should mention both the added and deleted files
        let subjects = &findings[0].subjects;
        assert!(subjects.iter().any(|s| s.contains("NewFile") && s.contains("added")));
        assert!(subjects.iter().any(|s| s.contains("OldFile") && s.contains("deleted")));
    }

    #[test]
    fn count_line_diff_basic() {
        assert_eq!(count_line_diff("a\nb\nc", "a\nb\nc"), 0);
        assert_eq!(count_line_diff("a\nb\nc", "a\nx\nc"), 1);
        assert_eq!(count_line_diff("a\nb", "a\nb\nc"), 1);
        assert_eq!(count_line_diff("a\nb\nc", "a\nb"), 1);
    }
}
