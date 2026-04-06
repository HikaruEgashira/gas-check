mod output;

use std::path::PathBuf;
use std::process;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use libverify_gas::auth;
use libverify_gas::client::GasClient;
use libverify_gas::config::GasConfig;
use libverify_gas::verify;

#[derive(Parser)]
#[command(name = "gas-check", version, about = "Verify security, compliance, and best practices of Google Apps Script projects")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Policy preset or path to .rego file
    #[arg(long, default_value = "gas-default", global = true)]
    policy: String,

    /// Path to clasp credentials (~/.clasprc.json by default)
    #[arg(long, global = true)]
    credentials: Option<PathBuf>,

    /// Suppress progress messages
    #[arg(long, short, global = true)]
    quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify a GAS project's governance posture
    Project {
        /// Apps Script project ID (found in Apps Script > Project Settings > IDs)
        script_id: String,

        /// Output format
        #[arg(long, default_value = "human")]
        format: OutputFormat,

        /// Include raw evidence in output (only affects --format json)
        #[arg(long)]
        with_evidence: bool,

        /// Show only failing controls
        #[arg(long)]
        only_failures: bool,
    },
    /// List available controls
    Controls,
    /// List available policy presets
    Policies,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
    Sarif,
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("Error: {e:#}");
        process::exit(2);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Project { ref script_id, ref format, with_evidence, only_failures } => {
            run_project(&cli, script_id, format, with_evidence, only_failures)
        }
        Commands::Controls => {
            list_controls();
            Ok(())
        }
        Commands::Policies => {
            list_policies();
            Ok(())
        }
    }
}

fn run_project(
    cli: &Cli,
    script_id: &str,
    format: &OutputFormat,
    with_evidence: bool,
    only_failures: bool,
) -> Result<()> {
    // Deployment IDs start with "AKfyc" — give a clear hint before hitting the API.
    if script_id.starts_with("AKfyc") {
        anyhow::bail!(
            "invalid argument: deployment ID given, but script project ID expected\n\n\
             hint: open the project in script.google.com and copy the ID from the URL:\n\
             \x20      https://script.google.com/home/projects/<SCRIPT_ID>/edit"
        );
    }

    if script_id.is_empty() {
        anyhow::bail!("script ID cannot be empty. Find your script ID in Apps Script > Project Settings.");
    }

    const KNOWN_POLICIES: &[&str] = &["gas-default", "gas-strict", "default", "oss", "soc2"];
    if !KNOWN_POLICIES.contains(&cli.policy.as_str()) && !std::path::Path::new(&cli.policy).exists() {
        anyhow::bail!(
            "unknown policy '{}'. Run `gas-check policies` for available presets, or provide a path to a .rego file.",
            cli.policy
        );
    }

    if !cli.quiet {
        eprintln!("Resolving clasp credentials…");
    }

    let config = GasConfig::new(cli.credentials.clone());
    let token = auth::resolve_access_token(&config).context("failed to resolve access token")?;
    let client = GasClient::new(&token)?;

    if !cli.quiet {
        eprintln!("Collecting evidence for {script_id}…");
    }

    let evidence = verify::collect_project_evidence(&client, script_id)
        .with_context(|| format!(
            "failed to verify project '{script_id}'. Ensure the script ID is correct (find it in Apps Script > Project Settings > IDs)"
        ))?;

    if !cli.quiet {
        eprintln!("Assessing with policy '{}'…", cli.policy);
    }

    let result = verify::assess_project(&evidence, Some(&cli.policy))?;

    match format {
        OutputFormat::Human => {
            output::human::render(&result, only_failures);
        }
        OutputFormat::Json => {
            if with_evidence {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&result.report)?);
            }
        }
        OutputFormat::Sarif => {
            let opts = libverify_output::OutputOptions {
                format: libverify_output::Format::Sarif,
                only_failures,
                tool_name: "gas-check".to_string(),
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
            };
            let output = libverify_output::render(&opts, &result)?;
            println!("{output}");
        }
    }

    // Exit 1 if any gate decision is Fail or Review
    let has_failures = result.report.outcomes.iter().any(|o| {
        o.decision == libverify_core::profile::GateDecision::Fail
            || o.decision == libverify_core::profile::GateDecision::Review
    });

    if has_failures {
        process::exit(1);
    }

    Ok(())
}

fn list_controls() {
    let controls = libverify_gas::controls::CONTROL_DESCRIPTIONS;
    println!("GAS-specific controls ({}):\n", controls.len());
    for (id, desc) in controls {
        println!("  {id}");
        println!("    {desc}\n");
    }
}

fn list_policies() {
    println!("Available policy presets:\n");
    println!("  gas-default — GAS-tuned defaults, balanced severity (default)");
    println!("  gas-strict  — All GAS controls fail on violation");
    println!("  default     — Built-in libverify default (all controls strict)");
    println!("  oss         — Tolerant for open-source projects");
    println!("  soc2        — SOC2 Trust Services mapping");
    println!();
    println!("Use --policy <name> or --policy path/to/custom.rego");
    println!();
}
