//! Checks for Realtime Database rules (database.rules.json).

use serde_json::Value;

use crate::report::{Finding, Severity};

pub fn check(src: &str, file: &str) -> Result<Vec<Finding>, String> {
    // Twice: comments are gone after the first pass, so commas that were
    // followed by a comment are recognised as trailing in the second.
    let root: Value =
        serde_json::from_str(&relax(&relax(src))).map_err(|e| format!("invalid JSON: {e}"))?;
    let rules = root.get("rules").ok_or("no top-level \"rules\" key")?;
    let mut findings = Vec::new();
    let mut locator = Locator::new(src);
    walk(rules, &mut Vec::new(), &mut locator, file, &mut findings);
    Ok(findings)
}

/// Firebase accepts // and /* */ comments and trailing commas in these
/// files; remove them (outside strings, keeping line breaks) so strict JSON
/// parsing works and line numbers stay correct.
fn relax(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut in_string = false;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 1;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                if chars[i] == '\n' {
                    out.push('\n');
                }
                i += 1;
            }
            i += 2;
            continue;
        } else if c == ',' {
            let next = chars[i + 1..].iter().find(|ch| !ch.is_whitespace());
            if !matches!(next, Some('}') | Some(']')) {
                out.push(c);
            }
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

/// Finds the line of each `".read"` / `".write"` key, in document order.
struct Locator {
    lines: Vec<(usize, String)>,
    cursor: usize,
}

impl Locator {
    fn new(src: &str) -> Self {
        Locator {
            lines: src
                .lines()
                .enumerate()
                .map(|(i, l)| (i + 1, l.to_string()))
                .collect(),
            cursor: 0,
        }
    }

    fn find(&mut self, key: &str) -> usize {
        let needle = format!("\"{key}\"");
        for idx in self.cursor..self.lines.len() {
            if self.lines[idx].1.contains(&needle) {
                self.cursor = idx + 1;
                return self.lines[idx].0;
            }
        }
        1
    }
}

fn walk(
    node: &Value,
    path: &mut Vec<String>,
    locator: &mut Locator,
    file: &str,
    findings: &mut Vec<Finding>,
) {
    let Value::Object(map) = node else { return };
    for (key, value) in map {
        match key.as_str() {
            ".read" | ".write" => {
                let line = locator.find(key);
                if let Some(f) = check_rule(key == ".write", value, path, line, file) {
                    findings.push(f);
                }
            }
            k if k.starts_with('.') => {
                locator.find(k);
            }
            _ => {
                locator.find(key);
                path.push(key.clone());
                walk(value, path, locator, file, findings);
                path.pop();
            }
        }
    }
}

fn check_rule(
    write: bool,
    value: &Value,
    path: &[String],
    line: usize,
    file: &str,
) -> Option<Finding> {
    let expr = match value {
        Value::Bool(b) => b.to_string(),
        Value::String(s) => s.trim().to_string(),
        _ => return None,
    };
    let at = format!("/{}", path.join("/"));
    let verb = if write { "write to" } else { "read" };
    let scope = if path.is_empty() {
        "your whole database".to_string()
    } else {
        at.clone()
    };
    let owner = path.iter().rev().find(|p| p.starts_with('$')).cloned();
    let make = |rule, severity, title: String, detail: &str| {
        let fix = match &owner {
            Some(var) => format!(
                "Only let the owner in, for example:\n\"{}\": \"auth != null && auth.uid === {var}\"",
                if write { ".write" } else { ".read" }
            ),
            None => format!(
                "Move per-user data under /users/$uid and use:\n\"{}\": \"auth != null && auth.uid === $uid\"",
                if write { ".write" } else { ".read" }
            ),
        };
        Some(Finding {
            rule,
            source: "dwarpal",
            severity,
            file: file.to_string(),
            line,
            prompt: format!(
                "In {file} (line {line}), the Realtime Database rule at {at} is `{expr}`: {title}. {detail} Change the rules so \
                 that each user can only {verb} their own data (auth.uid must match the path), keeping other rules the same, \
                 and explain the change."
            ),
            title,
            detail: detail.to_string(),
            fix,
        })
    };

    let compact: String = expr.chars().filter(|c| !c.is_whitespace()).collect();
    if compact == "true" {
        return make(
            "RT001",
            if write || path.is_empty() {
                Severity::Critical
            } else {
                Severity::High
            },
            format!("Anyone on the internet can {verb} {scope}"),
            "The rule is `true`, so it always allows access, even without signing in. Rules cascade: this also covers everything below this path.",
        );
    }
    if compact == "false" {
        return None;
    }
    if compact.contains("now<") && !compact.contains("auth") {
        return make(
            "RT002",
            Severity::Critical,
            format!("Test-mode rule left in place for {scope}"),
            "This is Firebase's temporary \"test mode\" rule, which only checks the date: until then, anyone can access it without signing in.",
        );
    }
    // `auth == null` only lets in people who are NOT signed in: anyone can be.
    let allows_anonymous = compact.contains("auth==null") || compact.contains("auth===null");
    if !compact.contains("auth") || allows_anonymous {
        if write || !(compact.contains("data.") || compact.contains("data.child")) {
            return make(
                "RT003",
                if write && path.is_empty() {
                    Severity::Critical
                } else {
                    Severity::High
                },
                format!("People who are not signed in can {verb} {scope}"),
                if allows_anonymous {
                    "The condition lets requests through when `auth` is null, that is, without signing in."
                } else {
                    "The condition doesn't involve `auth`, so requests without signing in can pass."
                },
            );
        }
        return None;
    }
    let ties_to_user = compact.contains("auth.uid") || compact.contains("auth.token.");
    if ties_to_user {
        return None;
    }
    let severity = match (write, path.is_empty() || owner.is_some()) {
        (true, true) => Severity::Critical,
        (true, false) | (false, true) => Severity::High,
        (false, false) => Severity::Medium,
    };
    make(
        "RT004",
        severity,
        match &owner {
            Some(var) => format!(
                "Any signed-in user can {verb} other users' data at {at} ({var} is not checked)"
            ),
            None => format!("Any signed-in user can {verb} {scope}"),
        },
        "The only check is that the caller is signed in. Anyone can create an account, and with anonymous sign-in enabled, anyone at all.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(json: &str) -> Vec<(&'static str, Severity, usize)> {
        check(json, "database.rules.json")
            .unwrap()
            .into_iter()
            .map(|f| (f.rule, f.severity, f.line))
            .collect()
    }

    #[test]
    fn public_root() {
        assert_eq!(
            rules("{\n  \"rules\": {\n    \".read\": true,\n    \".write\": \"true\"\n  }\n}"),
            vec![
                ("RT001", Severity::Critical, 3),
                ("RT001", Severity::Critical, 4)
            ]
        );
    }

    #[test]
    fn test_mode_and_comments() {
        let src = "{\n // test mode\n \"rules\": {\n  \".read\": \"now < 1767225600000\",\n  \".write\": false\n }\n}";
        assert_eq!(rules(src), vec![("RT002", Severity::Critical, 4)]);
    }

    #[test]
    fn comments_and_trailing_commas() {
        let src = "{\n  \"rules\": {\n    \".read\": true, // public\n    /* note, with comma */\n  },\n}";
        assert_eq!(rules(src), vec![("RT001", Severity::Critical, 3)]);
    }

    #[test]
    fn owner_checks() {
        let src = r#"{"rules": {"users": {"$uid": {
            ".read": "auth != null",
            ".write": "auth != null && auth.uid === $uid"
        }}}}"#;
        assert_eq!(rules(src), vec![("RT004", Severity::High, 2)]);
    }
}
