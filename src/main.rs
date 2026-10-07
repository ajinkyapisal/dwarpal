mod firebase;
mod report;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use report::Severity;

/// Security checks for apps built with AI coding tools.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check Firebase security rules (Firestore, Cloud Storage, Realtime Database).
    Firebase {
        /// Project directory or rules files. Defaults to the current directory.
        paths: Vec<PathBuf>,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Exit with status 1 if there are findings at or above this severity.
        #[arg(long, value_enum, default_value_t = FailOn::High)]
        fail_on: FailOn,
    },
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
    let Command::Firebase {
        paths,
        format,
        fail_on,
    } = Cli::parse().command;
    let paths = if paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        paths
    };

    let mut files = Vec::new();
    for path in &paths {
        files.extend(firebase::discover(path));
    }
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

    let output = match format {
        Format::Text => report::text(&findings, &errors, files.len()),
        Format::Json => report::json(&findings, &errors),
        Format::Sarif => report::sarif(&findings),
    };
    print!("{output}");

    let threshold = match fail_on {
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
