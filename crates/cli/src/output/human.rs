use colored::Colorize;
use libverify_core::assessment::VerificationResult;
use libverify_core::control::ControlStatus;
use libverify_core::profile::{FindingSeverity, GateDecision};

pub fn render(result: &VerificationResult, only_failures: bool) {
    let report = &result.report;

    println!(
        "\n{} (policy: {})\n",
        "GAS Project Verification".bold(),
        &report.profile_name
    );

    let mut pass_count = 0u32;
    let mut fail_count = 0u32;
    let mut review_count = 0u32;
    let mut na_count = 0u32;

    for outcome in &report.outcomes {
        // Check if this outcome corresponds to a NotApplicable finding
        let is_na = report.findings.iter().any(|f| {
            f.control_id == outcome.control_id && f.status == ControlStatus::NotApplicable
        });

        if is_na {
            na_count += 1;
        } else {
            match outcome.decision {
                GateDecision::Pass => pass_count += 1,
                GateDecision::Fail => fail_count += 1,
                GateDecision::Review => review_count += 1,
            }
        }

        let is_failure = outcome.decision == GateDecision::Fail
            || outcome.decision == GateDecision::Review;

        if only_failures && !is_failure {
            continue;
        }

        let icon = match outcome.decision {
            GateDecision::Pass => "✓".green(),
            GateDecision::Fail => "✗".red(),
            GateDecision::Review => "⚠".yellow(),
        };

        let severity = match outcome.severity {
            FindingSeverity::Error => "error".red(),
            FindingSeverity::Warning => "warning".yellow(),
            FindingSeverity::Info => "info".dimmed(),
        };

        println!("  {icon} {id}  [{severity}]", id = outcome.control_id);

        if let Some(finding) = report
            .findings
            .iter()
            .find(|f| f.control_id == outcome.control_id)
        {
            println!("    {}", finding.rationale.dimmed());
            if !finding.subjects.is_empty() && finding.subjects.len() <= 5 {
                for s in &finding.subjects {
                    println!("      → {s}");
                }
            } else if finding.subjects.len() > 5 {
                for s in &finding.subjects[..3] {
                    println!("      → {s}");
                }
                println!(
                    "      … and {} more",
                    finding.subjects.len() - 3
                );
            }
        }
    }

    println!();
    println!(
        "  {} passed, {} failed, {} review, {} n/a",
        pass_count.to_string().green(),
        fail_count.to_string().red(),
        review_count.to_string().yellow(),
        na_count.to_string().dimmed(),
    );

    if fail_count > 0 {
        println!(
            "\n{}",
            "  Verification FAILED — see above for details".red().bold()
        );
    } else if review_count > 0 {
        println!(
            "\n{}",
            "  Verification requires REVIEW — see above".yellow().bold()
        );
    } else {
        println!("\n{}", "  Verification PASSED".green().bold());
    }
    println!();
}
