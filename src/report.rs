//! Findings and output formats (text, JSON, SARIF).

use serde::Serialize;
use std::io::IsTerminal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    fn color(self) -> &'static str {
        match self {
            Severity::Low => "\x1b[2m",
            Severity::Medium => "\x1b[33m",
            Severity::High => "\x1b[31m",
            Severity::Critical => "\x1b[1;31m",
        }
    }

    fn sarif_level(self) -> &'static str {
        match self {
            Severity::Low => "note",
            Severity::Medium => "warning",
            Severity::High | Severity::Critical => "error",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule: &'static str,
    /// "dwarpal", or the external scanner that found it.
    pub source: &'static str,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    /// One-line summary in plain language.
    pub title: String,
    /// What can go wrong, and for whom.
    pub detail: String,
    /// How to fix it, with an example where possible.
    pub fix: String,
    /// A ready-to-paste prompt for a coding agent.
    pub prompt: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileError {
    pub file: String,
    pub message: String,
}

pub fn text(findings: &[Finding], errors: &[FileError], files_checked: usize) -> String {
    let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let paint = |code: &str, s: &str| {
        if color {
            format!("{code}{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    let mut out = String::new();
    for f in findings {
        out.push_str(&format!(
            "{}  {}\n          {}:{}\n          {}\n          Fix: {}\n\n",
            paint(f.severity.color(), &format!("{:<8}", f.severity.label())),
            paint("\x1b[1m", &f.title),
            f.file,
            f.line,
            f.detail,
            f.fix.replace('\n', "\n               "),
        ));
    }
    for e in errors {
        out.push_str(&format!(
            "{}  {}: {}\n\n",
            paint("\x1b[35m", "ERROR   "),
            e.file,
            e.message
        ));
    }
    let count = |s: Severity| findings.iter().filter(|f| f.severity == s).count();
    out.push_str(&format!(
        "{} file(s) checked: {} critical, {} high, {} medium, {} low{}\n",
        files_checked,
        count(Severity::Critical),
        count(Severity::High),
        count(Severity::Medium),
        count(Severity::Low),
        if errors.is_empty() {
            String::new()
        } else {
            format!(", {} could not be read", errors.len())
        },
    ));
    out
}

pub fn json(findings: &[Finding], errors: &[FileError]) -> String {
    serde_json::to_string_pretty(&serde_json::json!({ "findings": findings, "errors": errors }))
        .unwrap()
}

pub fn sarif(findings: &[Finding]) -> String {
    let mut rule_ids: Vec<&str> = findings.iter().map(|f| f.rule).collect();
    rule_ids.sort();
    rule_ids.dedup();
    let rules: Vec<_> = rule_ids
        .iter()
        .map(|id| {
            let f = findings.iter().find(|f| f.rule == *id).unwrap();
            serde_json::json!({ "id": id, "shortDescription": { "text": f.title } })
        })
        .collect();
    let results: Vec<_> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "ruleId": f.rule,
                "level": f.severity.sarif_level(),
                "message": { "text": format!("{} {} Fix: {}", f.title, f.detail, f.fix) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file },
                        "region": { "startLine": f.line }
                    }
                }],
                "properties": { "severity": f.severity }
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "dwarpal",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/ajinkyapisal/dwarpal",
                "rules": rules
            }},
            "results": results
        }]
    }))
    .unwrap()
}
