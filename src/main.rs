mod firebase;
mod report;
mod scan;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use report::{FileError, Finding, Severity};

/// Security checks for apps built with AI coding tools.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check a whole project: exposed secrets, database security, Firebase
    /// rules, leaked keys (gitleaks) and vulnerable packages (trivy).
    Scan {
        /// Project directory. Defaults to the current directory.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Only run dwarpal's own checks, not gitleaks or trivy.
        #[arg(long)]
        no_external: bool,
        #[command(flatten)]
        output: Output,
    },
    /// Check Firebase security rules (Firestore, Cloud Storage, Realtime Database).
    Firebase {
        /// Project directory or rules files. Defaults to the current directory.
        paths: Vec<PathBuf>,
        #[command(flatten)]
        output: Output,
    },
}

#[derive(Args)]
struct Output {
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
    /// Exit with status 1 if there are findings at or above this severity.
    #[arg(long, value_enum, default_value_t = FailOn::High)]
    fail_on: FailOn,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
enum FailOn {
    Critical,
    High,
    Medium,
    Low,
    Never,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Scan {
            path,
            no_external,
            output,
        } => {
            if !path.is_dir() {
                eprintln!("{} is not a directory.", path.display());
                return ExitCode::from(2);
            }
            let result = scan::run(&path, !no_external);
            if matches!(output.format, Format::Text) {
                let stack = if result.stack.is_empty() {
                    "no known frameworks".into()
                } else {
                    result.stack.join(" · ")
                };
                println!("dwarpal scan: {stack}");
                for (check, state) in &result.checks {
                    println!("  {check}: {state}");
                }
                println!();
            }
            finish(
                &result.findings,
                &result.errors,
                "Scan complete",
                output,
                || serde_json::json!({ "stack": result.stack, "checks": result.checks }),
            )
        }
        Command::Firebase { paths, output } => {
            let paths = if paths.is_empty() {
                vec![PathBuf::from(".")]
            } else {
                paths
            };
            let files: Vec<_> = paths.iter().flat_map(|p| firebase::discover(p)).collect();
            if files.is_empty() {
                eprintln!(
                    "No Firebase rules files found (looked for firebase.json, *.rules and database.rules.json)."
                );
                return ExitCode::from(2);
            }
            let mut findings = Vec::new();
            let mut errors = Vec::new();
            for (path, kind) in &files {
                let display = path
                    .strip_prefix("./")
                    .unwrap_or(path)
                    .display()
                    .to_string();
                match firebase::check_file(path, *kind, &display) {
                    Ok(found) => findings.extend(found),
                    Err(e) => errors.push(e),
                }
            }
            findings.sort_by(|a, b| {
                b.severity
                    .cmp(&a.severity)
                    .then(a.file.cmp(&b.file))
                    .then(a.line.cmp(&b.line))
            });
            finish(
                &findings,
                &errors,
                &format!("{} file(s) checked", files.len()),
                output,
                || serde_json::json!({}),
            )
        }
    }
}

fn finish(
    findings: &[Finding],
    errors: &[FileError],
    scope: &str,
    output: Output,
    extra: impl FnOnce() -> serde_json::Value,
) -> ExitCode {
    let text = match output.format {
        Format::Text => report::text(findings, errors, scope),
        Format::Json => {
            let mut json = extra();
            json["findings"] = serde_json::to_value(findings).unwrap();
            json["errors"] = serde_json::to_value(errors).unwrap();
            serde_json::to_string_pretty(&json).unwrap()
        }
        Format::Sarif => report::sarif(findings),
    };
    println!("{}", text.trim_end());
    let threshold = match output.fail_on {
        FailOn::Critical => Some(Severity::Critical),
        FailOn::High => Some(Severity::High),
        FailOn::Medium => Some(Severity::Medium),
        FailOn::Low => Some(Severity::Low),
        FailOn::Never => None,
    };
    if !errors.is_empty() {
        ExitCode::from(2)
    } else if threshold.is_some_and(|t| findings.iter().any(|f| f.severity >= t)) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
