//! `dwarpal scan`: every check for a project, in one report.

pub mod external;
pub mod project;
pub mod secrets;
pub mod supabase;

use std::collections::HashSet;
use std::path::Path;

use crate::firebase;
use crate::report::{FileError, Finding};
use project::Project;

pub struct ScanResult {
    pub stack: Vec<&'static str>,
    pub checks: Vec<(String, String)>,
    pub findings: Vec<Finding>,
    pub errors: Vec<FileError>,
}

pub fn run(root: &Path, use_external: bool) -> ScanResult {
    let project = Project::load(root);
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let mut checks = Vec::new();

    let mut status = |name: &str, state: String| checks.push((name.to_string(), state));

    findings.extend(secrets::check(&project));
    status("secrets in config", "checked".into());

    if project.has("supabase") {
        findings.extend(supabase::check(&project));
        status("Supabase tables", "checked".into());
    }

    let rules = firebase::discover(root);
    if !rules.is_empty() {
        for (path, kind) in &rules {
            let display = path
                .strip_prefix(root)
                .unwrap_or(path)
                .display()
                .to_string();
            match firebase::check_file(path, *kind, &display) {
                Ok(found) => findings.extend(found),
                Err(e) => errors.push(e),
            }
        }
        status("Firebase rules", format!("{} file(s)", rules.len()));
    }

    if use_external {
        let mut external = Vec::new();
        let leaks = external::gitleaks(&project, &mut external);
        let vulns = external::trivy(&project, &mut external);
        for scanner in [leaks, vulns] {
            status(
                scanner.name,
                scanner
                    .skipped
                    .unwrap_or_else(|| format!("checked {}", scanner.purpose)),
            );
        }
        // Skip what dwarpal already reported more specifically.
        let covered: HashSet<(String, usize)> =
            findings.iter().map(|f| (f.file.clone(), f.line)).collect();
        let committed_env: HashSet<String> = findings
            .iter()
            .filter(|f| f.rule == "EX003")
            .map(|f| f.file.clone())
            .collect();
        findings.extend(external.into_iter().filter(|f| {
            !covered.contains(&(f.file.clone(), f.line)) && !committed_env.contains(&f.file)
        }));
    }

    // Within a severity, problems in the app itself come before dependencies.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then((a.source == "trivy").cmp(&(b.source == "trivy")))
            .then(a.file.cmp(&b.file))
            .then(a.line.cmp(&b.line))
    });
    ScanResult {
        stack: project.stack_labels(),
        checks,
        findings,
        errors,
    }
}
