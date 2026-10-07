//! Supabase: tables without row-level security, and policies that let
//! everyone in, read from the SQL migrations.

use std::collections::{BTreeMap, HashSet};

use crate::report::{Finding, Severity};
use crate::scan::project::Project;

struct Statement {
    /// Lowercased, whitespace collapsed, comments removed.
    sql: String,
    file: String,
    line: usize,
}

pub fn check(project: &Project) -> Vec<Finding> {
    if !project.has("supabase") {
        return vec![];
    }
    let mut migrations: Vec<_> = project
        .files
        .iter()
        .filter(|p| {
            p.extension().is_some_and(|e| e == "sql") && p.to_string_lossy().contains("supabase/")
        })
        .collect();
    migrations.sort();
    if migrations.is_empty() {
        return vec![Finding {
            rule: "SB000",
            source: "dwarpal",
            severity: Severity::Low,
            file: "supabase/migrations".into(),
            line: 1,
            title: "Can't check your Supabase tables: no migrations in the repository".into(),
            detail: "This project uses Supabase, but its schema isn't in supabase/migrations, so dwarpal can't see whether \
                     row-level security is on."
                .into(),
            fix: "Run `supabase db pull` to save your current schema as a migration, then run dwarpal again. Also check \
                  Supabase's Security Advisor in the dashboard."
                .into(),
            prompt: "Set up the Supabase CLI for this project and run `supabase db pull` so the database schema is saved in \
                     supabase/migrations."
                .into(),
        }];
    }
    let statements: Vec<Statement> = migrations
        .iter()
        .filter_map(|rel| {
            project
                .read(rel)
                .map(|text| (rel.display().to_string(), text))
        })
        .flat_map(|(file, text)| split_statements(&text, &file))
        .collect();
    analyse(&statements)
}

fn split_statements(text: &str, file: &str) -> Vec<Statement> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut start_line = 1;
    let mut line = 1;
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    let mut in_quote = false;
    let mut dollar: Option<String> = None;
    while i < chars.len() {
        let c = chars[i];
        if c == '\n' {
            line += 1;
        }
        if dollar.is_none() && !in_quote {
            if c == '-' && chars.get(i + 1) == Some(&'-') {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            if c == '/' && chars.get(i + 1) == Some(&'*') {
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    if chars[i] == '\n' {
                        line += 1;
                    }
                    i += 1;
                }
                i += 2;
                continue;
            }
        }
        if c == '\'' && dollar.is_none() {
            in_quote = !in_quote;
        } else if c == '$' && !in_quote {
            // $$ or $tag$ quoting, used for function bodies.
            let rest: String = chars[i..].iter().take(64).collect();
            if let Some(end) = rest[1..].find('$') {
                let tag = &rest[..end + 2];
                if tag[1..tag.len() - 1]
                    .chars()
                    .all(|ch| ch.is_alphanumeric() || ch == '_')
                {
                    match &dollar {
                        Some(open) if open == tag => dollar = None,
                        None => dollar = Some(tag.to_string()),
                        _ => {}
                    }
                    current.push_str(tag);
                    i += tag.chars().count();
                    continue;
                }
            }
        }
        if c == ';' && !in_quote && dollar.is_none() {
            push(&mut statements, &current, file, start_line);
            current.clear();
            start_line = line;
        } else {
            if current.trim().is_empty() && !c.is_whitespace() {
                start_line = line;
            }
            current.push(c);
        }
        i += 1;
    }
    push(&mut statements, &current, file, start_line);
    statements
}

fn push(statements: &mut Vec<Statement>, raw: &str, file: &str, line: usize) {
    let sql = raw
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    if !sql.is_empty() {
        statements.push(Statement {
            sql,
            file: file.to_string(),
            line,
        });
    }
}

/// `public.profiles`, `"profiles"` or `profiles` -> Some("profiles") when the
/// table is in the public schema.
fn public_table(name: &str) -> Option<String> {
    let name = name.trim_matches(|c| c == '(' || c == ';');
    let cleaned = name.replace('"', "");
    match cleaned.split_once('.') {
        Some(("public", table)) => Some(table.to_string()),
        Some(_) => None,
        None => Some(cleaned),
    }
}

/// The word after `prefix` in a statement, e.g. the table after "create table".
fn word_after<'a>(sql: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = sql.strip_prefix(prefix)?.trim_start();
    let rest = rest
        .strip_prefix("if not exists ")
        .or_else(|| rest.strip_prefix("if exists "))
        .unwrap_or(rest);
    let rest = rest.strip_prefix("only ").unwrap_or(rest);
    rest.split(|c: char| c.is_whitespace() || c == '(')
        .next()
        .filter(|w| !w.is_empty())
}

fn analyse(statements: &[Statement]) -> Vec<Finding> {
    let mut created: BTreeMap<String, &Statement> = BTreeMap::new();
    let mut rls_on: HashSet<String> = HashSet::new();
    let mut open_policies: BTreeMap<(String, String), Finding> = BTreeMap::new();
    let mut findings = Vec::new();

    for st in statements {
        let sql = st.sql.as_str();
        if let Some(name) = word_after(sql, "create table").and_then(public_table) {
            created.entry(name).or_insert(st);
        } else if let Some(name) = word_after(sql, "drop table").and_then(public_table) {
            created.remove(&name);
        } else if sql.starts_with("alter table") {
            let Some(name) = word_after(sql, "alter table").and_then(public_table) else {
                continue;
            };
            if sql.contains("enable row level security") {
                rls_on.insert(name);
            } else if sql.contains("disable row level security") {
                rls_on.remove(&name);
                findings.push(finding(
                    "SB003",
                    Severity::Critical,
                    st,
                    format!("Row-level security is turned off for `{name}`"),
                    format!(
                        "Without row-level security, anyone with your anon key, which is in your frontend, can read and change \
                         every row of `{name}` through the Supabase API."
                    ),
                    format!("Remove this statement, run `alter table {name} enable row level security;` and add policies."),
                ));
            }
        } else if sql.starts_with("create policy") {
            if let Some(f) = policy_finding(st) {
                open_policies.insert(policy_key(sql, "create policy"), f);
            }
        } else if sql.starts_with("drop policy") {
            open_policies.remove(&policy_key(sql, "drop policy"));
        }
    }
    findings.extend(open_policies.into_values());
    for (name, st) in &created {
        if rls_on.contains(name) {
            continue;
        }
        findings.push(finding(
            "SB001",
            Severity::Critical,
            st,
            format!("Table `{name}` has no row-level security"),
            format!(
                "Supabase exposes every table in the public schema through its API. Without row-level security, anyone with \
                 your anon key, which is in your frontend, can read, change and delete every row of `{name}`."
            ),
            format!(
                "Add a migration with:\nalter table public.{name} enable row level security;\nthen add policies, for example:\n\
                 create policy \"Owners can read\" on public.{name} for select to authenticated using (auth.uid() = user_id);"
            ),
        ));
    }
    findings
}

/// (table, policy name) from `create policy "name" on table ...` or
/// `drop policy if exists "name" on table`.
fn policy_key(sql: &str, prefix: &str) -> (String, String) {
    let rest = sql.strip_prefix(prefix).unwrap_or(sql).trim_start();
    let rest = rest.strip_prefix("if exists ").unwrap_or(rest);
    let (name, after) = match rest.strip_prefix('"') {
        Some(quoted) => quoted.split_once('"').unwrap_or((quoted, "")),
        None => rest.split_once(' ').unwrap_or((rest, "")),
    };
    let table = after
        .trim_start()
        .strip_prefix("on ")
        .and_then(|r| r.split_whitespace().next())
        .and_then(public_table);
    (table.unwrap_or_default(), name.to_string())
}

fn policy_finding(st: &Statement) -> Option<Finding> {
    let sql = st.sql.as_str();
    let table = sql
        .split(" on ")
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .and_then(public_table)?;
    let command = ["select", "insert", "update", "delete", "all"]
        .into_iter()
        .find(|c| sql.contains(&format!(" for {c}")))
        .unwrap_or("all");
    let roles = sql
        .split(" to ")
        .nth(1)
        .map(|r| {
            r.split(" using")
                .next()
                .unwrap_or(r)
                .split(" with check")
                .next()
                .unwrap_or(r)
        })
        .unwrap_or("public");
    let anyone = roles.contains("anon") || roles.contains("public");
    let always_true = |clause: &str| {
        sql.split(clause).nth(1).is_some_and(|rest| {
            let inner: String = rest
                .trim_start()
                .chars()
                .skip_while(|c| *c == '(')
                .take_while(|c| *c != ')')
                .collect();
            inner.trim() == "true"
        })
    };
    if !(always_true("using") || always_true("with check")) {
        return None;
    }
    let who = if anyone {
        "Anyone, even without signing in,"
    } else {
        "Any signed-in user"
    };
    let action = match command {
        "select" => "read every row of",
        "insert" => "add rows to",
        "update" => "change every row of",
        "delete" => "delete every row of",
        _ => "read, add, change and delete every row of",
    };
    let severity = match (command, anyone) {
        ("select", true) => Severity::High,
        ("select", false) => Severity::Medium,
        (_, true) => Severity::Critical,
        (_, false) => Severity::High,
    };
    let note = if command == "select" {
        " If this data is meant to be public, you can ignore this."
    } else {
        ""
    };
    Some(finding(
        "SB002",
        severity,
        st,
        format!("{who} can {action} `{table}`"),
        format!(
            "This policy's condition is `true`, so it doesn't check who is asking or whose row it is.{note}"
        ),
        format!(
            "Tie the policy to the row's owner, for example:\nusing (auth.uid() = user_id){}",
            if command == "select" {
                ""
            } else {
                "\nwith check (auth.uid() = user_id)"
            }
        ),
    ))
}

fn finding(
    rule: &'static str,
    severity: Severity,
    st: &Statement,
    title: String,
    detail: String,
    fix: String,
) -> Finding {
    Finding {
        rule,
        source: "dwarpal",
        severity,
        file: st.file.clone(),
        line: st.line,
        prompt: format!(
            "In my Supabase migrations ({}, line {}): {title}. {detail} Write a new migration that fixes this (do not edit old \
             migrations), following this approach: {}. Make sure the app's existing queries still work for the rightful users, \
             and explain the policies you added.",
            st.file,
            st.line,
            fix.lines().next().unwrap_or(&fix)
        ),
        title,
        detail,
        fix,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(sql: &str) -> Vec<(&'static str, Severity, usize)> {
        let mut found: Vec<_> = analyse(&split_statements(sql, "m.sql"))
            .into_iter()
            .map(|f| (f.rule, f.severity, f.line))
            .collect();
        found.sort_by_key(|f| f.2);
        found
    }

    #[test]
    fn tables_without_rls() {
        let sql = "create table public.profiles (id uuid primary key);\n\
                   create table notes (id int);\n\
                   alter table notes enable row level security;\n\
                   create table private.audit (id int);\n";
        assert_eq!(run(sql), vec![("SB001", Severity::Critical, 1)]);
    }

    #[test]
    fn policies_and_disabled_rls() {
        let sql = "create table posts (id int);\nalter table posts enable row level security;\n\
                   create policy \"read\" on posts for select using (true);\n\
                   create policy \"write\" on public.posts for insert to authenticated with check (true);\n\
                   create policy \"own\" on posts for update using (auth.uid() = user_id);\n\
                   alter table posts disable row level security;\n";
        assert_eq!(
            run(sql),
            vec![
                ("SB001", Severity::Critical, 1),
                ("SB002", Severity::High, 3),
                ("SB002", Severity::High, 4),
                ("SB003", Severity::Critical, 6)
            ]
        );
    }

    #[test]
    fn dropped_policies_are_forgotten() {
        let sql = "create table posts (id int);\nalter table posts enable row level security;\n\
                   create policy \"Allow all for demo\" on public.posts for all using (true);\n\
                   drop policy if exists \"Allow all for demo\" on posts;\n";
        assert_eq!(run(sql), vec![]);
    }

    #[test]
    fn ignores_function_bodies_and_comments() {
        let sql = "-- create table nope (id int);\ncreate function f() returns void as $$ begin create table tmp (id int); end; $$ language plpgsql;\n";
        assert_eq!(run(sql), vec![]);
    }
}
