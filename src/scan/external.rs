//! Existing scanners, run for you, with their results translated into
//! plain-language findings and filtered for the project's stack.

use std::collections::BTreeMap;
use std::fs;
use std::process::Command;

use serde_json::Value;

use crate::report::{Finding, Severity};
use crate::scan::project::Project;
use crate::scan::secrets::jwt_role;

pub struct Scanner {
    pub name: &'static str,
    pub purpose: &'static str,
    /// None if it ran; otherwise why not.
    pub skipped: Option<String>,
}

fn installed(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn install_hint(tool: &str) -> String {
    format!("not installed (brew install {tool})")
}

// gitleaks: secrets in files and in git history.

pub fn gitleaks(project: &Project, findings: &mut Vec<Finding>) -> Scanner {
    let mut scanner = Scanner {
        name: "gitleaks",
        purpose: "secrets in code and git history",
        skipped: None,
    };
    if !installed("gitleaks") {
        scanner.skipped = Some(install_hint("gitleaks"));
        return scanner;
    }
    // In a git repo, scan the history: a secret deleted later is still leaked.
    // Otherwise scan the files, minus local env files and dependencies.
    let config = std::env::temp_dir().join(format!("dwarpal-gitleaks-{}.toml", std::process::id()));
    let mut cmd = Command::new("gitleaks");
    if project.tracked.is_some() {
        cmd.arg("git");
    } else {
        let _ = fs::write(
            &config,
            "[extend]\nuseDefault = true\n[allowlist]\npaths = ['''(^|/)(node_modules|\\.next|dist|build|\\.git)/''', '''(^|/)\\.env[^/]*$''']\n",
        );
        cmd.arg("dir").arg("--config").arg(&config);
    }
    let output = cmd
        .arg(&project.root)
        .args([
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--no-banner",
            "--exit-code",
            "0",
            "--log-level",
            "error",
        ])
        .output();
    let _ = fs::remove_file(&config);
    let Ok(output) = output else {
        scanner.skipped = Some("failed to run".into());
        return scanner;
    };
    let Ok(Value::Array(results)) = serde_json::from_slice::<Value>(&output.stdout) else {
        scanner.skipped = Some(format!(
            "unexpected output: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
        return scanner;
    };
    // The same secret often shows up in many commits; report it once, at its
    // most recent location (gitleaks lists newest commits first).
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for r in &results {
        let secret = r.get("Secret").and_then(Value::as_str).unwrap_or("");
        *seen.entry(secret.to_string()).or_default() += 1;
    }
    let mut reported = std::collections::HashSet::new();
    for r in results {
        let get = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let (rule_id, secret, file) = (get("RuleID"), get("Secret"), get("File"));
        let line = r.get("StartLine").and_then(Value::as_u64).unwrap_or(1) as usize;
        let commit = get("Commit");
        let role = jwt_role(&secret);
        if not_a_secret(&secret, role.as_deref(), &rule_id, project)
            || !reported.insert(secret.clone())
        {
            continue;
        }
        let elsewhere = seen.get(&secret).copied().unwrap_or(1) - 1;
        let file = file
            .strip_prefix(&format!("{}/", project.root.display()))
            .unwrap_or(&file)
            .to_string();
        let what = match role.as_deref() {
            Some("service_role") => "Supabase service_role key".to_string(),
            _ if secret.starts_with("sb_secret_") => "Supabase secret key".to_string(),
            _ => plain_description(&rule_id, &get("Description")),
        };
        let critical = role.as_deref() == Some("service_role")
            || secret.starts_with("sb_secret_")
            || [
                "stripe",
                "openai",
                "anthropic",
                "private-key",
                "aws",
                "gcp-service-account",
            ]
            .iter()
            .any(|k| rule_id.contains(k));
        let masked: String = secret.chars().take(4).collect::<String>() + "…";
        let where_ = if commit.is_empty() {
            format!("{file}:{line}")
        } else {
            format!("{file}:{line} in commit {}", &commit[..commit.len().min(8)])
        };
        findings.push(Finding {
            rule: "GL001",
            source: "gitleaks",
            severity: if critical { Severity::Critical } else { Severity::High },
            file: file.clone(),
            line,
            title: format!("{what} in your code ({masked})"),
            detail: format!(
                "A secret was found at {where_}{}. Anyone who can read the code{} can use it as you.",
                if elsewhere > 0 { format!(" (and in {elsewhere} more place(s) or commits)") } else { String::new() },
                if commit.is_empty() { "" } else { " or its git history" }
            ),
            fix: "Rotate the secret first (create a new one, revoke the old one), then move it to an environment variable that \
                  isn't committed. Deleting it from the code alone isn't enough: it stays in git history."
                .into(),
            prompt: format!(
                "gitleaks found a {what} hard-coded at {where_}. Replace it with a server-side environment variable (not committed \
                 to git, no public prefix), update the code that uses it, add the variable name to .env.example, and remind me to \
                 rotate the old secret."
            ),
        });
    }
    scanner
}

/// Values gitleaks flags that aren't secrets: keys that are public by design,
/// documentation placeholders, and variable names.
fn not_a_secret(secret: &str, role: Option<&str>, rule_id: &str, project: &Project) -> bool {
    let lower = secret.to_lowercase();
    role == Some("anon")
        || secret.starts_with("sb_publishable_")
        || (rule_id == "gcp-api-key" && project.has("firebase") && secret.starts_with("AIza"))
        // A JWT header with no payload: a truncated example such as "eyJhbGciOi...".
        || (secret.starts_with("eyJ") && secret.split('.').filter(|p| p.len() > 4).count() < 2)
        // An environment variable name, not a value, as in "NAME" or "NAME=...".
        || secret.split('=').next().is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
        || ["your", "example", "placeholder", "changeme", "xxxx", "<", "***", "..."].iter().any(|p| lower.contains(p))
}

/// gitleaks' descriptions are long ("Detected a Generic API Key, potentially
/// exposing..."); keep the noun.
fn plain_description(rule_id: &str, description: &str) -> String {
    match rule_id {
        "generic-api-key" => "Possible API key or password".into(),
        "jwt" => "JSON Web Token".into(),
        "private-key" => "Private key".into(),
        _ => description
            .split(',')
            .next()
            .unwrap_or(description)
            .trim_start_matches("Detected a ")
            .trim_start_matches("Uncovered a ")
            .trim_end_matches('.')
            .to_string(),
    }
}

// Trivy: vulnerable dependencies, one finding per package.

pub fn trivy(project: &Project, findings: &mut Vec<Finding>) -> Scanner {
    let mut scanner = Scanner {
        name: "trivy",
        purpose: "vulnerable packages",
        skipped: None,
    };
    if !installed("trivy") {
        scanner.skipped = Some(install_hint("trivy"));
        return scanner;
    }
    let output = Command::new("trivy")
        .args(["fs", "--scanners", "vuln", "--format", "json", "--quiet"])
        .args([
            "--skip-dirs",
            "**/node_modules",
            "--skip-dirs",
            "**/.next",
            "--skip-dirs",
            "**/dist",
            "--skip-dirs",
            "**/build",
        ])
        .arg(&project.root)
        .output();
    let Ok(output) = output else {
        scanner.skipped = Some("failed to run".into());
        return scanner;
    };
    let Ok(report) = serde_json::from_slice::<Value>(&output.stdout) else {
        scanner.skipped = Some(format!(
            "unexpected output: {}",
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .last()
                .unwrap_or("")
        ));
        return scanner;
    };
    // (lockfile, package, installed version) -> vulnerabilities
    let mut groups: BTreeMap<(String, String, String), Vec<&Value>> = BTreeMap::new();
    for result in report
        .get("Results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let target = result
            .get("Target")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        for v in result
            .get("Vulnerabilities")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            groups
                .entry((target.clone(), s("PkgName"), s("InstalledVersion")))
                .or_default()
                .push(v);
        }
    }
    let (direct, dev) = declared_packages(project);
    let mut indirect: Vec<(String, String, Severity, Option<String>, String)> = Vec::new();
    for ((target, package, installed_version), vulns) in groups {
        let js_lockfile = [
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "bun.lock",
            "bun.lockb",
        ]
        .iter()
        .any(|l| target.ends_with(l));
        let kind = if !js_lockfile || direct.contains(&package) {
            Kind::Direct
        } else if dev.contains(&package) {
            Kind::Dev
        } else {
            Kind::Indirect
        };
        let severity_of = |v: &Value| match v.get("Severity").and_then(Value::as_str).unwrap_or("")
        {
            "CRITICAL" => Some(Severity::Critical),
            "HIGH" => Some(Severity::High),
            "MEDIUM" => Some(Severity::Medium),
            _ => None,
        };
        let Some(worst) = vulns.iter().filter_map(|v| severity_of(v)).max() else {
            continue;
        };
        let count = |s: Severity| vulns.iter().filter(|v| severity_of(v) == Some(s)).count();
        let fixed = vulns
            .iter()
            .filter_map(|v| v.get("FixedVersion").and_then(Value::as_str))
            .filter_map(|list| pick_fix(&installed_version, list))
            .max_by(|a, b| compare_versions(a, b));
        // If fixing everything needs a new major version, also say what the
        // current major line can reach, and how much that fixes.
        let major = |v: &str| v.split('.').next().unwrap_or("").to_string();
        let same_major_note = fixed.as_ref().filter(|f| major(f) != major(&installed_version)).and_then(|_| {
            let in_line: Vec<String> = vulns
                .iter()
                .filter_map(|v| v.get("FixedVersion").and_then(Value::as_str))
                .filter_map(|list| {
                    list.split(',').map(str::trim).find(|c| major(c) == major(&installed_version) && compare_versions(c, &installed_version).is_gt()).map(String::from)
                })
                .collect();
            let best = in_line.iter().max_by(|a, b| compare_versions(a, b))?.clone();
            Some(format!(
                " Fixing all of them needs a new major version. If you can't upgrade yet, {best} fixes {} of {}.",
                in_line.len(),
                vulns.len()
            ))
        });
        if kind == Kind::Indirect && worst < Severity::Critical {
            indirect.push((package, installed_version, worst, fixed, target));
            continue;
        }
        let worst_titles: Vec<String> = vulns
            .iter()
            .filter(|v| severity_of(v) == Some(worst))
            .filter_map(|v| {
                v.get("Title")
                    .and_then(Value::as_str)
                    .map(|t| clean_title(&package, t))
            })
            .take(2)
            .collect();
        let counts = [
            (Severity::Critical, "critical"),
            (Severity::High, "high"),
            (Severity::Medium, "medium"),
        ]
        .iter()
        .filter(|(s, _)| count(*s) > 0)
        .map(|(s, label)| format!("{} {label}", count(*s)))
        .collect::<Vec<_>>()
        .join(", ");
        let (title, fix) = match &fixed {
            Some(version) => (
                format!("Upgrade {package} from {installed_version} to {version}"),
                format!(
                    "Update {package} to {version} or later in your package manager, then run your tests."
                ),
            ),
            None => (
                format!("{package} {installed_version} has known vulnerabilities with no fix yet"),
                format!(
                    "Check whether your app uses the affected parts of {package}, and watch for a fixed release."
                ),
            ),
        };
        let (severity, title, note) = match kind {
            Kind::Direct => (worst, title, String::new()),
            Kind::Dev => (
                Severity::Low,
                format!("{title} (build tool only)"),
                " It's a devDependency, so it runs on your machine and in CI, not in your users' browsers.".to_string(),
            ),
            Kind::Indirect => (
                worst,
                title,
                format!(" You don't install {package} directly; another package does. `{}` usually pulls in the fix.", update_command(&target)),
            ),
        };
        findings.push(Finding {
            rule: "DV001",
            source: "trivy",
            severity,
            file: target.clone(),
            line: 1,
            title,
            detail: format!(
                "{} known vulnerabilit{} ({counts}), for example: {}.{}{note}",
                vulns.len(),
                if vulns.len() == 1 { "y" } else { "ies" },
                worst_titles.join("; "),
                same_major_note.unwrap_or_default()
            ),
            fix,
            prompt: format!(
                "Upgrade {package} from {installed_version} to {} in this project (lockfile {target}), fix anything the upgrade \
                 breaks, and run the build and tests.",
                fixed.as_deref().unwrap_or("the latest version")
            ),
        });
    }
    if !indirect.is_empty() {
        indirect.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
        let target = indirect[0].4.clone();
        let list: Vec<String> = indirect
            .iter()
            .take(6)
            .map(|(package, version, _, fixed, _)| match fixed {
                Some(f) => format!("{package} {version} → {f}"),
                None => format!("{package} {version} (no fix yet)"),
            })
            .collect();
        let more = indirect.len().saturating_sub(list.len());
        let command = update_command(&target);
        findings.push(Finding {
            rule: "DV002",
            source: "trivy",
            severity: Severity::Medium,
            file: target.clone(),
            line: 1,
            title: format!("{} indirect package(s) have known vulnerabilities", indirect.len()),
            detail: format!(
                "These come in through your other packages, not your own package.json: {}{}. Most are only reachable in unusual setups, so they rank below problems in your own code.",
                list.join(", "),
                if more > 0 { format!(", and {more} more") } else { String::new() }
            ),
            fix: format!("Run `{command}` to pull in fixed versions, then run dwarpal again."),
            prompt: format!(
                "Update this project's dependencies with `{command}` so indirect packages pick up security fixes, then run the build and tests and tell me if anything broke."
            ),
        });
    }
    scanner
}

#[derive(PartialEq)]
enum Kind {
    Direct,
    Dev,
    Indirect,
}

/// Packages named in package.json files: (runtime dependencies, devDependencies).
fn declared_packages(
    project: &Project,
) -> (
    std::collections::HashSet<String>,
    std::collections::HashSet<String>,
) {
    let mut direct = std::collections::HashSet::new();
    let mut dev = std::collections::HashSet::new();
    for rel in project
        .files
        .iter()
        .filter(|p| p.file_name().is_some_and(|n| n == "package.json"))
    {
        let Some(json) = project
            .read(rel)
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        else {
            continue;
        };
        let names = |key: &str| -> Vec<String> {
            json.get(key)
                .and_then(Value::as_object)
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default()
        };
        for key in ["dependencies", "peerDependencies", "optionalDependencies"] {
            direct.extend(names(key));
        }
        dev.extend(names("devDependencies"));
    }
    dev.retain(|p| !direct.contains(p));
    (direct, dev)
}

fn update_command(lockfile: &str) -> &'static str {
    if lockfile.ends_with("bun.lock") || lockfile.ends_with("bun.lockb") {
        "bun update"
    } else if lockfile.ends_with("pnpm-lock.yaml") {
        "pnpm update"
    } else if lockfile.ends_with("yarn.lock") {
        "yarn upgrade"
    } else {
        "npm update"
    }
}

/// Trivy titles repeat the package name ("seroval: Seroval: `fromJSON()`..."):
/// drop those prefixes and cut long titles at a word boundary.
fn clean_title(package: &str, title: &str) -> String {
    let simple = |s: &str| s.to_lowercase().replace(|c: char| !c.is_alphanumeric(), "");
    let names_package = |head: &str| {
        let (h, p) = (simple(head), simple(package));
        !h.is_empty() && head.len() < 30 && (h.contains(&p) || p.contains(&h))
    };
    let mut t = title.trim();
    while let Some((_, rest)) = t.split_once(": ").filter(|(head, _)| names_package(head)) {
        t = rest.trim();
    }
    if t.chars().count() <= 90 {
        return t.to_string();
    }
    let cut: String = t.chars().take(90).collect();
    format!("{}…", cut.rsplit_once(' ').map(|(a, _)| a).unwrap_or(&cut))
}

/// From "13.5.9, 14.2.25, 15.2.3", pick the smallest fixed version in the same
/// major line as the installed version, or else the smallest newer one.
fn pick_fix(installed: &str, list: &str) -> Option<String> {
    let mut candidates: Vec<&str> = list
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty() && compare_versions(v, installed).is_gt())
        .collect();
    candidates.sort_by(|a, b| compare_versions(a, b));
    let major = |v: &str| v.split('.').next().map(str::to_string);
    candidates
        .iter()
        .find(|v| major(v) == major(installed))
        .or(candidates.first())
        .map(|v| v.to_string())
}

fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parts = |v: &str| -> Vec<u64> {
        v.split(['.', '-', '+'])
            .map_while(|p| p.parse().ok())
            .collect()
    };
    parts(a).cmp(&parts(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_fix_in_same_major() {
        assert_eq!(
            pick_fix("14.1.0", "13.5.9, 14.2.25, 15.2.3").as_deref(),
            Some("14.2.25")
        );
        assert_eq!(
            pick_fix("12.0.0", "13.5.9, 14.2.25").as_deref(),
            Some("13.5.9")
        );
        assert_eq!(pick_fix("15.3.0", "14.2.25, 15.2.3"), None);
        assert!(compare_versions("1.10.0", "1.9.9").is_gt());
    }

    #[test]
    fn cleans_trivy_titles() {
        assert_eq!(
            clean_title("seroval", "seroval: Seroval: `fromJSON()` is unsafe"),
            "`fromJSON()` is unsafe"
        );
        assert_eq!(
            clean_title("next", "Next.js: middleware bypass"),
            "middleware bypass"
        );
        assert_eq!(clean_title("axios", "SSRF: in axios"), "SSRF: in axios");
        assert!(clean_title("x", &"word ".repeat(40)).ends_with("word…"));
    }
}
