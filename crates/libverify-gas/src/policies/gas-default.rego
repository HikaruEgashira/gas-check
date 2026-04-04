package verify.profile

import rego.v1

# GAS Default Policy
# Maps GAS-specific controls to severity and gate decisions.
# Built-in libverify controls that are not applicable will produce
# NotApplicable findings and are skipped by the assessment engine.

map := {"severity": severity, "decision": decision} if {
    gas_rule
    severity := gas_severity
    decision := gas_decision
}

# Fallback: any control not explicitly mapped gets default handling
default gas_rule := false
default gas_severity := "info"
default gas_decision := "pass"

# --- Pass ---
gas_rule if { input.control_id == "gas-description-quality" }
gas_severity := "info" if { input.control_id == "gas-description-quality"; input.status == "violated" }
gas_decision := "pass" if { input.control_id == "gas-description-quality"; input.status == "violated" }

gas_rule if { input.control_id == "gas-library-inventory" }
# Always info/pass — informational only

# --- Review ---
gas_rule if { input.control_id == "gas-editor-count-audit" }
gas_severity := "warning" if { input.control_id == "gas-editor-count-audit"; input.status == "violated" }
gas_decision := "review" if { input.control_id == "gas-editor-count-audit"; input.status == "violated" }

gas_rule if { input.control_id == "gas-oauth-scope-minimization" }
gas_severity := "warning" if { input.control_id == "gas-oauth-scope-minimization"; input.status == "violated" }
gas_decision := "review" if { input.control_id == "gas-oauth-scope-minimization"; input.status == "violated" }

gas_rule if { input.control_id == "gas-trigger-audit" }
gas_severity := "warning" if { input.control_id == "gas-trigger-audit"; input.status == "violated" }
gas_decision := "review" if { input.control_id == "gas-trigger-audit"; input.status == "violated" }

gas_rule if { input.control_id == "gas-gcp-project-linkage" }
gas_severity := "warning" if { input.control_id == "gas-gcp-project-linkage"; input.status == "violated" }
gas_decision := "review" if { input.control_id == "gas-gcp-project-linkage"; input.status == "violated" }

# --- Fail ---
gas_rule if { input.control_id == "gas-sharing-restriction" }
gas_severity := "error" if { input.control_id == "gas-sharing-restriction"; input.status == "violated" }
gas_decision := "fail" if { input.control_id == "gas-sharing-restriction"; input.status == "violated" }

gas_rule if { input.control_id == "gas-version-hygiene" }
gas_severity := "error" if { input.control_id == "gas-version-hygiene"; input.status == "violated" }
gas_decision := "fail" if { input.control_id == "gas-version-hygiene"; input.status == "violated" }

gas_rule if { input.control_id == "gas-deployment-version-linkage" }
gas_severity := "error" if { input.control_id == "gas-deployment-version-linkage"; input.status == "violated" }
gas_decision := "fail" if { input.control_id == "gas-deployment-version-linkage"; input.status == "violated" }

gas_rule if { input.control_id == "gas-external-library-audit" }
gas_severity := "error" if { input.control_id == "gas-external-library-audit"; input.status == "violated" }
gas_decision := "fail" if { input.control_id == "gas-external-library-audit"; input.status == "violated" }

gas_rule if { input.control_id == "gas-manifest-integrity" }
gas_severity := "error" if { input.control_id == "gas-manifest-integrity"; input.status == "violated" }
gas_decision := "fail" if { input.control_id == "gas-manifest-integrity"; input.status == "violated" }

gas_rule if { input.control_id == "gas-webapp-access-control" }
gas_severity := "error" if { input.control_id == "gas-webapp-access-control"; input.status == "violated" }
gas_decision := "fail" if { input.control_id == "gas-webapp-access-control"; input.status == "violated" }

gas_rule if { input.control_id == "gas-api-executable-access" }
gas_severity := "error" if { input.control_id == "gas-api-executable-access"; input.status == "violated" }
gas_decision := "fail" if { input.control_id == "gas-api-executable-access"; input.status == "violated" }

# --- Head Drift ---
gas_rule if { input.control_id == "gas-head-drift" }
gas_severity := "error" if { input.control_id == "gas-head-drift"; input.status == "violated" }
gas_decision := "fail" if { input.control_id == "gas-head-drift"; input.status == "violated" }

# --- Secret Scanning ---
gas_rule if { input.control_id == "gas-secret-scanning" }
gas_severity := "error" if { input.control_id == "gas-secret-scanning"; input.status == "violated" }
gas_decision := "fail" if { input.control_id == "gas-secret-scanning"; input.status == "violated" }

# --- Edit Source Detection ---
gas_rule if { input.control_id == "gas-edit-source-detection" }
gas_severity := "warning" if { input.control_id == "gas-edit-source-detection"; input.status == "violated" }
gas_decision := "review" if { input.control_id == "gas-edit-source-detection"; input.status == "violated" }
