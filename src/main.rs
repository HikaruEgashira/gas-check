mod controls;
mod gas;
mod output;

use std::path::PathBuf;
use std::process;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use gas::auth;
use gas::client::GasClient;
use gas::config::GasConfig;
use gas::verify;

#[derive(Parser)]
#[command(name = "gas-check", version, about = "GAS project governance verification CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format
    #[arg(long, default_value = "human", global = true)]
    format: OutputFormat,

    /// Policy preset or path to .rego file
    #[arg(long, default_value = "gas-default", global = true)]
    policy: String,

    /// Path to clasp credentials (~/.clasprc.json by default)
    #[arg(long, global = true)]
    credentials: Option<PathBuf>,

    /// Include raw evidence in output
    #[arg(long, global = true)]
    with_evidence: bool,

    /// Show only failing controls
    #[arg(long, global = true)]
    only_failures: bool,

    /// Suppress progress messages
    #[arg(long, short, global = true)]
    quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify a GAS project's governance posture
    Project {
        /// Apps Script project ID (script ID)
        script_id: String,
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
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Project { ref script_id } => run_project(&cli, script_id),
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

fn run_project(cli: &Cli, script_id: &str) -> Result<()> {
    if !cli.quiet {
        eprintln!("Resolving clasp credentials…");
    }

    let config = GasConfig::new(cli.credentials.clone());
    let token = auth::resolve_access_token(&config).context("failed to resolve access token")?;
    let client = GasClient::new(&token)?;

    if !cli.quiet {
        eprintln!("Collecting evidence for {script_id}…");
    }

    let evidence = verify::collect_project_evidence(&client, script_id)?;

    if !cli.quiet {
        eprintln!("Assessing with policy '{}'…", cli.policy);
    }

    let result = verify::assess_project(&evidence, Some(&cli.policy))?;

    match cli.format {
        OutputFormat::Human => {
            output::human::render(&result, cli.only_failures);
        }
        OutputFormat::Json => {
            if cli.with_evidence {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&result.report)?);
            }
        }
        OutputFormat::Sarif => {
            let opts = libverify_output::OutputOptions {
                format: libverify_output::Format::Sarif,
                only_failures: cli.only_failures,
                tool_name: "gas-check".to_string(),
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
            };
            let output = libverify_output::render(&opts, &result)?;
            println!("{output}");
        }
    }

    // Exit with non-zero if any gate decision is Fail
    let has_failures = result.report.outcomes.iter().any(|o| {
        o.decision == libverify_core::profile::GateDecision::Fail
    });

    if has_failures {
        process::exit(1);
    }

    Ok(())
}

fn list_controls() {
    println!("GAS-specific controls ({}):\n", controls::ALL_GAS_CONTROLS.len());
    for id in controls::ALL_GAS_CONTROLS {
        println!("  {id}");
    }
    println!();
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
