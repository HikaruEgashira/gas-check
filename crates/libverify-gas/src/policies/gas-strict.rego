package verify.profile

import rego.v1

# GAS Strict Policy
# All violated controls produce errors and fail the gate.

map := {"severity": severity, "decision": decision} if {
    startswith(input.control_id, "gas-")
    severity := strict_severity
    decision := strict_decision
}

default strict_severity := "info"
default strict_decision := "pass"

strict_severity := "error" if { input.status == "violated" }
strict_decision := "fail" if { input.status == "violated" }

strict_severity := "warning" if { input.status == "indeterminate" }
strict_decision := "review" if { input.status == "indeterminate" }
