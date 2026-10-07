//! Secrets exposed to the browser, and secrets committed to git.

use std::collections::HashSet;
use std::path::Path;

use crate::report::{Finding, Severity};
use crate::scan::project::Project;

/// Prefixes that make an environment variable part of the client bundle.
const PUBLIC_PREFIXES: [(&str, &str); 7] = [
    ("NEXT_PUBLIC_", "Next.js"),
    ("VITE_", "Vite"),
    ("EXPO_PUBLIC_", "Expo"),
    ("REACT_APP_", "Create React App"),
    ("NUXT_PUBLIC_", "Nuxt"),
    ("GATSBY_", "Gatsby"),
    ("PUBLIC_", "SvelteKit/Astro"),
];

/// Name fragments that mean a variable is a secret; checked in order.
const SECRET_NAMES: [&str; 28] = [
    "SERVICE_ROLE",
    "SERVICEROLE",
    "SECRET",
    "PRIVATE_KEY",
    "PASSWORD",
    "PASSWD",
    "OPENAI",
    "ANTHROPIC",
    "CLAUDE",
    "GROQ",
    "GEMINI_API_KEY",
    "DEEPSEEK",
    "MISTRAL",
    "REPLICATE",
    "RESEND",
    "SENDGRID",
    "MAILGUN",
    "TWILIO_AUTH",
    "DATABASE_URL",
    "DB_URL",
    "POSTGRES",
    "MONGODB_URI",
    "MONGO_URI",
    "REDIS_URL",
    "AWS_SECRET",
    "WEBHOOK",
    "ADMIN_KEY",
    "ACCESS_TOKEN",
];

/// Secrets that give full database access or run up a bill when leaked.
const CRITICAL_NAMES: [&str; 13] = [
    "SERVICE_ROLE",
    "SECRET",
    "DATABASE_URL",
    "OPENAI",
    "ANTHROPIC",
    "CLAUDE",
    "GEMINI",
    "GROQ",
    "DEEPSEEK",
    "MISTRAL",
    "REPLICATE",
    "AWS_SECRET",
    "PRIVATE_KEY",
];

/// Name fragments for values that are public by design.
const PUBLIC_BY_DESIGN: [&str; 6] = [
    "ANON_KEY",
    "PUBLISHABLE",
    "SITE_KEY",
    "MEASUREMENT_ID",
    "DSN",
    "PUBLIC_KEY",
];

const SOURCE_EXTENSIONS: [&str; 11] = [
    "js", "jsx", "ts", "tsx", "mjs", "cjs", "vue", "svelte", "astro", "html", "env",
];

pub fn check(project: &Project) -> Vec<Finding> {
    let mut findings = Vec::new();
    public_env_secrets(project, &mut findings);
    service_role_in_client(project, &mut findings);
    committed_env_files(project, &mut findings);
    findings
}

fn is_env_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    (name == ".env" || name.starts_with(".env.") || name.ends_with(".env"))
        && !["example", "sample", "template", "dist", "defaults"]
            .iter()
            .any(|s| name.ends_with(s))
}

/// The public prefix and framework of a variable name, if it has one.
fn public_prefix(name: &str) -> Option<(&'static str, &'static str)> {
    PUBLIC_PREFIXES
        .iter()
        .find(|(prefix, _)| name.starts_with(prefix) && name.len() > prefix.len())
        .copied()
}

/// Identifier-like words in a line, with their byte offsets.
fn words(line: &str) -> impl Iterator<Item = (usize, &str)> {
    line.match_indices(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map(|(i, sep)| i + sep.len())
        .chain(std::iter::once(0))
        .filter_map(move |start| {
            let rest = &line[start..];
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            (end > 0).then(|| (start, &rest[..end]))
        })
}

/// Why a value looks like a server-side secret, judging by its format.
fn secret_value_kind(value: &str) -> Option<&'static str> {
    let v = value.trim().trim_matches(|c| c == '"' || c == '\'');
    if v.starts_with("sk_live_") || v.starts_with("rk_live_") {
        Some("a Stripe secret key")
    } else if v.starts_with("sk-ant-") {
        Some("an Anthropic API key")
    } else if v.starts_with("sk-proj-") || (v.starts_with("sk-") && v.len() > 40) {
        Some("an OpenAI API key")
    } else if jwt_role(v).as_deref() == Some("service_role") {
        Some("a Supabase service_role key")
    } else if v.starts_with("postgres://")
        || v.starts_with("postgresql://")
        || v.starts_with("mongodb+srv://")
    {
        Some("a database connection string")
    } else {
        None
    }
}

/// The `role` claim of a Supabase-style JWT, if the value is one.
pub fn jwt_role(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let (_, payload, _) = (parts.next()?, parts.next()?, parts.next()?);
    if !token.starts_with("eyJ") {
        return None;
    }
    let bytes = base64url_decode(payload)?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    json.get("role")?.as_str().map(String::from)
}

fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut bits: u32 = 0;
    let mut count = 0;
    let mut out = Vec::new();
    for c in input.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(v);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    Some(out)
}

fn secret_name_kind(name: &str) -> Option<&'static str> {
    let upper = name.to_uppercase();
    if PUBLIC_BY_DESIGN.iter().any(|p| upper.contains(p)) {
        return None;
    }
    SECRET_NAMES.iter().find(|s| upper.contains(*s)).copied()
}

/// Finds NEXT_PUBLIC_*, VITE_* (and so on) variables that hold secrets, in
/// env files (by name or value) and in source (by name).
fn public_env_secrets(project: &Project, findings: &mut Vec<Finding>) {
    let mut reported: HashSet<String> = HashSet::new();
    for rel in &project.files {
        let ext = rel
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();
        let env_file = is_env_file(rel);
        if !env_file && !SOURCE_EXTENSIONS.contains(&ext.as_str()) {
            continue;
        }
        let Some(text) = project.read(rel) else {
            continue;
        };
        for (number, line) in text.lines().enumerate() {
            for (offset, name) in words(line) {
                let Some((prefix, framework)) = public_prefix(name) else {
                    continue;
                };
                // In an env file, `NAME=value` lets us judge the value too.
                let value = (env_file && line[..offset].trim().is_empty())
                    .then(|| line[offset + name.len()..].trim_start().strip_prefix('='))
                    .flatten()
                    .map(str::trim);
                let why = value
                    .and_then(secret_value_kind)
                    .map(|k| format!("its value is {k}"))
                    .or_else(|| {
                        secret_name_kind(name)
                            .map(|k| format!("the name says it is a secret ({k})"))
                    });
                let Some(why) = why else { continue };
                if !reported.insert(name.to_string()) {
                    continue;
                }
                let critical =
                    why.starts_with("its value") || CRITICAL_NAMES.iter().any(|s| name.contains(s));
                let server_name = &name[prefix.len()..];
                let file = rel.display().to_string();
                findings.push(Finding {
                    rule: "EX001",
                    source: "dwarpal",
                    severity: if critical { Severity::Critical } else { Severity::High },
                    file: file.clone(),
                    line: number + 1,
                    title: format!("Secret exposed to the browser: {name}"),
                    detail: format!(
                        "{framework} puts every variable starting with its public prefix into the JavaScript sent to visitors, and {why}. \
                         Anyone can open your site, read it from the page source, and use it as you."
                    ),
                    fix: format!(
                        "Rename it to {server_name} (no public prefix), use it only in server code (API routes, server actions, \
                         edge functions), and rotate the key: the current one may already have leaked."
                    ),
                    prompt: format!(
                        "The environment variable {name} (found in {file}, line {}) holds a secret but has a public prefix, so \
                         {framework} ships it to the browser. Rename it to {server_name}, move every use of it into server-side code \
                         (API route, server action or edge function) and have the client call that instead. Update .env files and \
                         deployment settings, and list the places you changed. Remind me to rotate the key.",
                        number + 1
                    ),
                });
            }
        }
    }
}

/// Whether an env file entry holds a secret, by name or value.
fn looks_secret(name: &str, value: &str) -> bool {
    let upper = name.to_uppercase();
    secret_value_kind(value).is_some()
        || secret_name_kind(name).is_some()
        || ((upper.contains("KEY") || upper.contains("TOKEN"))
            && public_prefix(name).is_none()
            && !PUBLIC_BY_DESIGN.iter().any(|p| upper.contains(p)))
}

/// Client code is anything that runs in the browser: "use client" files in
/// Next.js, and everything under src/ in Vite, Create React App and Expo apps.
fn is_client_file(project: &Project, rel: &Path, text: &str) -> bool {
    let path = rel.to_string_lossy();
    let server_path = [
        "/api/",
        "app/api/",
        "pages/api/",
        "server/",
        "supabase/functions/",
        "functions/",
        ".server.",
        "middleware.",
    ]
    .iter()
    .any(|p| path.contains(p));
    if server_path || text.contains("\"use server\"") || text.contains("'use server'") {
        return false;
    }
    if text.contains("\"use client\"") || text.contains("'use client'") {
        return true;
    }
    let spa = (project.has("vite") || project.has("expo") || text.contains("import.meta.env"))
        && !project.has("nextjs");
    spa && (path.starts_with("src/") || path.starts_with("app/") || path.starts_with("components/"))
}

fn service_role_in_client(project: &Project, findings: &mut Vec<Finding>) {
    if !project.has("supabase") {
        return;
    }
    for rel in &project.files {
        let ext = rel
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();
        if !["js", "jsx", "ts", "tsx", "mjs", "vue", "svelte"].contains(&ext.as_str()) {
            continue;
        }
        let Some(text) = project.read(rel) else {
            continue;
        };
        if !is_client_file(project, rel, &text) {
            continue;
        }
        let Some((number, line)) = text.lines().enumerate().find(|(_, l)| {
            let upper = l.to_uppercase();
            upper.contains("SERVICE_ROLE") || upper.contains("SERVICEROLE")
        }) else {
            continue;
        };
        let file = rel.display().to_string();
        findings.push(Finding {
            rule: "EX002",
            source: "dwarpal",
            severity: Severity::Critical,
            file: file.clone(),
            line: number + 1,
            title: "Supabase service_role key used in browser code".into(),
            detail: format!(
                "`{}` runs in visitors' browsers. The service_role key bypasses all row-level security: whoever has it can read, \
                 change and delete every row in your database.",
                line.trim().chars().take(100).collect::<String>()
            ),
            fix: "Use the anon key in browser code and rely on row-level security policies. Do privileged work in a server action, \
                  API route or Supabase Edge Function that reads the service_role key from a server-only variable. Rotate the key."
                .into(),
            prompt: format!(
                "{file} (line {}) uses the Supabase service_role key in code that runs in the browser. Move that privileged \
                 operation into server-side code (Next.js server action or API route, or a Supabase Edge Function) that reads the \
                 key from a server-only environment variable, and make the client use the anon key plus row-level security. \
                 Show me the changes and remind me to rotate the service_role key.",
                number + 1
            ),
        });
    }
}

fn committed_env_files(project: &Project, findings: &mut Vec<Finding>) {
    let Some(tracked) = &project.tracked else {
        return;
    };
    for rel in tracked.iter().filter(|p| is_env_file(p)) {
        // Lovable and others commit a .env with only public values (the
        // Supabase URL and publishable key) on purpose; that's fine.
        let secrets: Vec<String> = project
            .read(rel)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split_once('='))
            .filter(|(k, v)| {
                !k.trim().starts_with('#')
                    && !v.trim().is_empty()
                    && looks_secret(k.trim(), v.trim())
            })
            .map(|(k, _)| k.trim().to_string())
            .collect();
        if secrets.is_empty() {
            continue;
        }
        let file = rel.display().to_string();
        findings.push(Finding {
            rule: "EX003",
            source: "dwarpal",
            severity: Severity::High,
            file: file.clone(),
            line: 1,
            title: format!("{file} with secrets is committed to git ({})", secrets.join(", ")),
            detail: "Everyone who can see this repository can read these values, including in old commits after you delete the \
                     file. If the repository is public, assume they are already leaked."
                .into(),
            fix: format!(
                "Run `git rm --cached {file}`, add it to .gitignore, commit, and rotate every secret it contained. Keep a \
                 {file}.example with empty values for others to copy."
            ),
            prompt: format!(
                "{file} is committed to git. Remove it from the repository without deleting my local copy (git rm --cached), add \
                 it to .gitignore, create {file}.example with the same keys and empty values, and list every secret in it that I \
                 need to rotate."
            ),
        });
    }
    // An env file that git would pick up on the next `git add .`.
    for rel in project
        .files
        .iter()
        .filter(|p| is_env_file(p) && !tracked.contains(*p))
    {
        if project.is_ignored_by_git(rel) {
            continue;
        }
        let file = rel.display().to_string();
        findings.push(Finding {
            rule: "EX004",
            source: "dwarpal",
            severity: Severity::Medium,
            file: file.clone(),
            line: 1,
            title: format!("{file} is not ignored by git"),
            detail: "It isn't committed yet, but the next `git add .` will include it.".into(),
            fix: "Add `.env*` (and `!.env.example`) to .gitignore.".into(),
            prompt: format!("Add {file} and other .env files to .gitignore (keeping .env.example tracked), so secrets can't be committed by accident."),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_jwt_roles() {
        // {"alg":"HS256"} . {"role":"service_role"} . signature
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.sig";
        assert_eq!(jwt_role(token).as_deref(), Some("service_role"));
        assert_eq!(
            jwt_role("eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.sig").as_deref(),
            Some("anon")
        );
        assert_eq!(jwt_role("not.a.jwt"), None);
    }

    #[test]
    fn env_entries_that_are_secret() {
        assert!(!looks_secret(
            "VITE_SUPABASE_PUBLISHABLE_KEY",
            "sb_publishable_abc"
        ));
        assert!(!looks_secret(
            "SUPABASE_PUBLISHABLE_KEY",
            "sb_publishable_abc"
        ));
        assert!(!looks_secret("VITE_SUPABASE_URL", "https://x.supabase.co"));
        assert!(looks_secret("STRIPE_SECRET_KEY", "x"));
        assert!(looks_secret("RESEND_API_KEY", "re_123"));
        assert!(looks_secret("VITE_GEMINI_API_KEY", "AIza123"));
    }

    #[test]
    fn classifies_names_and_values() {
        assert_eq!(
            secret_name_kind("NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY"),
            Some("SERVICE_ROLE")
        );
        assert_eq!(secret_name_kind("NEXT_PUBLIC_SUPABASE_ANON_KEY"), None);
        assert_eq!(secret_name_kind("VITE_STRIPE_PUBLISHABLE_KEY"), None);
        assert_eq!(
            secret_value_kind("\"sk-ant-api03-abc\""),
            Some("an Anthropic API key")
        );
        assert_eq!(secret_value_kind("pk_live_123"), None);
    }
}
