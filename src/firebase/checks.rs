//! Security checks for Firestore and Cloud Storage rules.
//!
//! Each `allow` statement is analysed with user-defined functions inlined, to
//! answer: can someone who is not signed in get through? Can any signed-in
//! user get through, or does the condition tie access to *this* user (their
//! uid, a custom claim, or a role looked up by their uid)?

use std::collections::HashMap;

use super::ast::*;
use crate::report::{Finding, Severity};

/// One `allow` statement with its full match path and inlined condition.
struct Site {
    service: String,
    path: Vec<Segment>,
    methods: Vec<String>,
    condition: Option<Expr>,
    line: usize,
}

const OWNER_WILDCARDS: [&str; 12] = [
    "userid",
    "uid",
    "user",
    "useruid",
    "ownerid",
    "owner",
    "accountid",
    "memberid",
    "profileid",
    "authorid",
    "creatorid",
    "customerid",
];

pub fn check(rules: &Ruleset, file: &str) -> Vec<Finding> {
    let mut sites = Vec::new();
    for service in &rules.services {
        collect(
            &service.name,
            &service.items,
            &[],
            &HashMap::new(),
            &mut sites,
        );
    }
    let role_lookups = role_lookups(&sites);
    let mut findings = Vec::new();
    for site in &sites {
        if let Some(f) = access_finding(site, file) {
            findings.push(f);
        }
        if let Some(f) = escalation_finding(site, &role_lookups, file) {
            findings.push(f);
        }
        if let Some(f) = upload_limits_finding(site, file) {
            findings.push(f);
        }
    }
    findings
}

// Flattening and function inlining.

fn collect(
    service: &str,
    items: &[Item],
    path: &[Segment],
    outer_functions: &HashMap<String, Function>,
    sites: &mut Vec<Site>,
) {
    let mut functions = outer_functions.clone();
    for item in items {
        if let Item::Function(f) = item {
            functions.insert(f.name.clone(), f.clone());
        }
    }
    for item in items {
        match item {
            Item::Match(m) => {
                let mut sub = path.to_vec();
                sub.extend(m.path.iter().cloned());
                collect(service, &m.items, &sub, &functions, sites);
            }
            Item::Allow(a) => sites.push(Site {
                service: service.to_string(),
                path: path.to_vec(),
                methods: a.methods.clone(),
                condition: a.condition.as_ref().map(|c| inline(c, &functions, 0)),
                line: a.line,
            }),
            Item::Function(_) => {}
        }
    }
}

fn inline(expr: &Expr, functions: &HashMap<String, Function>, depth: usize) -> Expr {
    map(expr, &mut |e| {
        if depth > 8 {
            return None;
        }
        let Expr::Call(callee, args) = e else {
            return None;
        };
        let Expr::Ident(name) = callee.as_ref() else {
            return None;
        };
        let f = functions.get(name)?;
        if f.params.len() != args.len() {
            return None;
        }
        let mut bindings: HashMap<String, Expr> = f
            .params
            .iter()
            .cloned()
            .zip(args.iter().map(|a| inline(a, functions, depth + 1)))
            .collect();
        for (var, value) in &f.lets {
            let bound = substitute(value, &bindings);
            bindings.insert(var.clone(), bound);
        }
        Some(inline(
            &substitute(&f.body, &bindings),
            functions,
            depth + 1,
        ))
    })
}

fn substitute(expr: &Expr, bindings: &HashMap<String, Expr>) -> Expr {
    map(expr, &mut |e| match e {
        Expr::Ident(name) => bindings.get(name).cloned(),
        _ => None,
    })
}

/// Rebuild an expression bottom-up; `f` may replace any node.
fn map(expr: &Expr, f: &mut dyn FnMut(&Expr) -> Option<Expr>) -> Expr {
    let rebuilt = match expr {
        Expr::Member(base, field) => Expr::Member(Box::new(map(base, f)), field.clone()),
        Expr::Index(base, index) => Expr::Index(Box::new(map(base, f)), Box::new(map(index, f))),
        Expr::Call(callee, args) => Expr::Call(
            Box::new(map(callee, f)),
            args.iter().map(|a| map(a, f)).collect(),
        ),
        Expr::Unary(op, e) => Expr::Unary(op, Box::new(map(e, f))),
        Expr::Binary(op, l, r) => Expr::Binary(op, Box::new(map(l, f)), Box::new(map(r, f))),
        Expr::Ternary(c, a, b) => Expr::Ternary(
            Box::new(map(c, f)),
            Box::new(map(a, f)),
            Box::new(map(b, f)),
        ),
        Expr::List(items) => Expr::List(items.iter().map(|e| map(e, f)).collect()),
        Expr::Map(entries) => Expr::Map(
            entries
                .iter()
                .map(|(k, v)| (map(k, f), map(v, f)))
                .collect(),
        ),
        Expr::Path(parts) => Expr::Path(
            parts
                .iter()
                .map(|p| match p {
                    PathPart::Expr(e) => PathPart::Expr(map(e, f)),
                    other => other.clone(),
                })
                .collect(),
        ),
        other => other.clone(),
    };
    f(&rebuilt).unwrap_or(rebuilt)
}

// Condition analysis.

/// True if every way of satisfying `e` passes through a part where `leaf`
/// holds. `a || b` needs both sides; `a && b` needs either side.
fn always(e: &Expr, leaf: &dyn Fn(&Expr) -> bool) -> bool {
    match e {
        Expr::Binary("||", l, r) => always(l, leaf) && always(r, leaf),
        Expr::Binary("&&", l, r) => always(l, leaf) || always(r, leaf),
        Expr::Ternary(c, a, b) => always(c, leaf) || (always(a, leaf) && always(b, leaf)),
        _ => leaf(e),
    }
}

fn is_const_true(e: &Expr) -> bool {
    match e {
        Expr::Bool(true) => true,
        Expr::Binary("||", l, r) => is_const_true(l) || is_const_true(r),
        Expr::Binary("&&", l, r) => is_const_true(l) && is_const_true(r),
        Expr::Binary("==", l, r) => {
            l == r && !matches!(**l, Expr::Ident(_) | Expr::Member(..) | Expr::Call(..))
        }
        _ => false,
    }
}

fn is_const_false(e: &Expr) -> bool {
    match e {
        Expr::Bool(false) => true,
        Expr::Binary("&&", l, r) => is_const_false(l) || is_const_false(r),
        Expr::Binary("||", l, r) => is_const_false(l) && is_const_false(r),
        Expr::Unary("!", inner) => is_const_true(inner),
        _ => false,
    }
}

fn starts_with(e: &Expr, prefix: &str) -> bool {
    e.dotted()
        .is_some_and(|d| d == prefix || d.starts_with(&format!("{prefix}.")))
}

fn mentions(e: &Expr, prefix: &str) -> bool {
    e.any(&|x| starts_with(x, prefix))
}

fn requires_auth(e: &Expr) -> bool {
    always(e, &|leaf| mentions(leaf, "request.auth"))
}

/// The condition ties access to the caller's identity: compares their uid,
/// checks a custom claim, or looks up a document by their uid.
fn has_authz(e: &Expr) -> bool {
    e.any(&|x| match x {
        Expr::Binary(op, l, r) if matches!(*op, "==" | "!=" | "in") => {
            let uid_side = |a: &Expr, b: &Expr| mentions(a, "request.auth.uid") && !matches!(b, Expr::Null);
            uid_side(l, r) || uid_side(r, l)
        }
        Expr::Call(callee, args) => {
            matches!(callee.as_ref(), Expr::Ident(n) if matches!(n.as_str(), "get" | "exists" | "getAfter" | "existsAfter"))
                && args.iter().any(|a| mentions(a, "request.auth.uid"))
        }
        _ => starts_with(x, "request.auth.token") && x.dotted().is_some_and(|d| d != "request.auth.token"),
    })
}

/// `request.resource.data.diff(resource.data).affectedKeys().hasOnly([...])`:
/// the caller may only change the listed fields, a deliberate pattern for
/// counters such as likeCount.
fn limits_changed_fields(e: &Expr) -> bool {
    e.any(&|x| matches!(x, Expr::Call(callee, _) if matches!(callee.as_ref(), Expr::Member(inner, m)
        if m == "hasOnly" && inner.any(&|y| matches!(y, Expr::Member(_, k) if k == "affectedKeys")))))
}

fn authorized(e: &Expr) -> bool {
    always(e, &|leaf| has_authz(leaf) || limits_changed_fields(leaf))
}

/// `request.time < timestamp.date(2026, 11, 5)`: Firebase's "test mode".
fn test_mode_expiry(e: &Expr) -> Option<Option<String>> {
    if !mentions(e, "request.time") || mentions(e, "request.auth") {
        return None;
    }
    let mut date = None;
    e.walk(&mut |x| {
        if let Expr::Call(callee, args) = x {
            if callee.dotted().as_deref() == Some("timestamp.date") {
                if let [Expr::Int(y), Expr::Int(m), Expr::Int(d)] = args.as_slice() {
                    date = Some(format!("{y:04}-{m:02}-{d:02}"));
                }
            }
        }
    });
    Some(date)
}

fn owner_wildcard(path: &[Segment]) -> Option<&str> {
    path.iter().rev().find_map(|s| match s {
        Segment::Wildcard {
            name,
            recursive: false,
        } if OWNER_WILDCARDS.contains(&name.to_lowercase().replace('_', "").as_str()) => {
            Some(name.as_str())
        }
        _ => None,
    })
}

fn compares_uid_with(e: &Expr, wildcard: &str) -> bool {
    e.any(&|x| match x {
        Expr::Binary(op, l, r) if matches!(*op, "==" | "!=") => {
            let is_wildcard = |a: &Expr| matches!(a, Expr::Ident(n) if n == wildcard);
            (mentions(l, "request.auth.uid") && is_wildcard(r))
                || (mentions(r, "request.auth.uid") && is_wildcard(l))
        }
        _ => false,
    })
}

/// A rule like `match /{document=**}` directly under the database root,
/// which applies to every path.
fn is_catch_all(path: &[Segment]) -> bool {
    matches!(
        path.last(),
        Some(Segment::Wildcard {
            recursive: true,
            ..
        })
    ) && display_path(path).matches('/').count() == 1
}

// Findings.

fn writes(methods: &[String]) -> bool {
    methods
        .iter()
        .any(|m| matches!(m.as_str(), "write" | "create" | "update" | "delete"))
}

fn access_finding(site: &Site, file: &str) -> Option<Finding> {
    let path = display_path(&site.path);
    let what = describe_methods(&site.methods);
    let store = store_name(&site.service);
    let scope = if is_catch_all(&site.path) {
        format!(
            "every {} in your {store}",
            if store == "Storage bucket" {
                "file"
            } else {
                "document"
            }
        )
    } else {
        path.clone()
    };
    let finding = |rule, severity, title: String, detail: String, fix: String| {
        Some(Finding {
            rule,
            source: "dwarpal",
            severity,
            file: file.to_string(),
            line: site.line,
            prompt: format!(
                "In {file} (line {line}), the {store} security rule for {path} has this problem: {title}. {detail} \
                 Rewrite that rule so that {fix_goal}. Keep every other rule's behaviour the same, and explain what you changed.",
                line = site.line,
                fix_goal = fix_goal(&fix),
            ),
            title,
            detail,
            fix,
        })
    };

    // Public reads of one path are often intentional (avatars, published
    // posts); public writes, or anything on a catch-all path, never are.
    let public_severity = if writes(&site.methods) || is_catch_all(&site.path) {
        Severity::Critical
    } else {
        Severity::High
    };
    let public_note = if public_severity == Severity::High {
        " If this data is meant to be public, you can ignore this."
    } else {
        ""
    };
    let always_true = match &site.condition {
        None => {
            Some("This rule has no condition, so it always allows access, even without signing in.")
        }
        Some(cond) if is_const_true(cond) => {
            Some("The condition is always true, so it allows access even without signing in.")
        }
        Some(_) => None,
    };
    if let Some(reason) = always_true {
        return finding(
            "FB001",
            public_severity,
            format!("Anyone on the internet can {what} {scope}"),
            format!("{reason}{public_note}"),
            owner_fix(site),
        );
    }
    let cond = site.condition.as_ref()?;
    if is_const_false(cond) {
        return None; // Denies everything.
    }
    if let Some(expiry) = test_mode_expiry(cond) {
        let when = match &expiry {
            Some(date) if date.as_str() < today().as_str() => {
                format!(
                    "It expired on {date}: since then every request is denied, so your app is probably broken."
                )
            }
            Some(date) => format!("Until {date}, anyone can {what} without signing in."),
            None => format!("Until the date in the rule, anyone can {what} without signing in."),
        };
        return finding(
            "FB002",
            Severity::Critical,
            format!("Test-mode rule left in place for {scope}"),
            format!(
                "This is Firebase's temporary \"test mode\" rule, which only checks the date. {when}"
            ),
            owner_fix(site),
        );
    }
    if !requires_auth(cond) {
        let data_dependent = mentions(cond, "resource");
        if writes(&site.methods) {
            return finding(
                "FB003",
                Severity::High,
                format!("People who are not signed in can {what} {scope}"),
                "At least one way to satisfy this condition does not involve request.auth, so requests without signing in can pass."
                    .into(),
                owner_fix(site),
            );
        }
        if !data_dependent {
            return finding(
                "FB003",
                public_severity,
                format!("Anyone on the internet can {what} {scope}"),
                format!(
                    "The condition doesn't depend on who is asking or on the document's data, so it allows access without signing in.{public_note}"
                ),
                owner_fix(site),
            );
        }
        return None; // Public data by design, such as `resource.data.published == true`.
    }
    if authorized(cond) {
        return None;
    }
    let anonymous = "Signing in is not much of a barrier: anyone can create an account, and with anonymous sign-in enabled, anyone at all.";
    if let Some(wildcard) = owner_wildcard(&site.path).filter(|w| !compares_uid_with(cond, w)) {
        return finding(
            "FB004",
            if writes(&site.methods) {
                Severity::Critical
            } else {
                Severity::Medium
            },
            format!("Any signed-in user can {what} other users' data at {path}"),
            format!(
                "The rule checks that the caller is signed in, but not that {{{wildcard}}} is their own uid. {anonymous}{}",
                if writes(&site.methods) {
                    ""
                } else {
                    " If profiles are meant to be visible to other users, you can ignore this."
                }
            ),
            format!(
                "Also require the caller to be the owner, for example:\nallow {}: if request.auth != null && request.auth.uid == {wildcard};",
                site.methods.join(", ")
            ),
        );
    }
    let severity = match (is_catch_all(&site.path), writes(&site.methods)) {
        (true, true) => Severity::Critical,
        (true, false) | (false, true) => Severity::High,
        (false, false) => Severity::Medium,
    };
    finding(
        "FB005",
        severity,
        format!("Any signed-in user can {what} {scope}"),
        format!(
            "The only check is that the caller is signed in. {anonymous}{}",
            if is_catch_all(&site.path) {
                " Because this rule matches every path, it also overrides stricter rules elsewhere: Firebase allows a request if any rule allows it."
            } else {
                ""
            }
        ),
        owner_fix(site),
    )
}

fn owner_fix(site: &Site) -> String {
    let methods = site.methods.join(", ");
    match owner_wildcard(&site.path) {
        Some(w) => format!(
            "Only let the owner in, for example:\nallow {methods}: if request.auth != null && request.auth.uid == {w};"
        ),
        None if site.service.contains("storage") => format!(
            "Limit access to the signed-in owner, for example by storing files under /users/{{userId}}/... and using:\nallow {methods}: if request.auth != null && request.auth.uid == userId;"
        ),
        None => format!(
            "Tie access to the document's owner, for example:\nallow {methods}: if request.auth != null && resource.data.ownerId == request.auth.uid;\n(for create, check request.resource.data.ownerId instead)"
        ),
    }
}

fn fix_goal(fix: &str) -> String {
    let first = fix
        .lines()
        .next()
        .unwrap_or(fix)
        .trim_end_matches([':', '.']);
    let lower = first[..1].to_lowercase() + &first[1..];
    format!("it follows this advice: {lower}")
}

/// Rules that trust a field from a document looked up by the caller's uid,
/// such as get(/.../users/$(request.auth.uid)).data.role.
fn role_lookups(sites: &[Site]) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for site in sites {
        let Some(cond) = &site.condition else {
            continue;
        };
        cond.walk(&mut |e| {
            let Expr::Member(base, field) = e else { return };
            let Expr::Member(call, data) = base.as_ref() else {
                return;
            };
            if data != "data" {
                return;
            }
            let Expr::Call(callee, args) = call.as_ref() else {
                return;
            };
            if !matches!(callee.as_ref(), Expr::Ident(n) if n == "get" || n == "getAfter") {
                return;
            }
            let Some(Expr::Path(parts)) = args.first() else {
                return;
            };
            if let [.., PathPart::Literal(collection), PathPart::Expr(id)] = parts.as_slice() {
                if mentions(id, "request.auth.uid") {
                    found.push((collection.clone(), field.clone()));
                }
            }
        });
    }
    found.sort();
    found.dedup();
    found
}

fn restricts_fields(e: &Expr, field: &str) -> bool {
    e.any(&|x| match x {
        Expr::Member(_, name) => matches!(name.as_str(), "affectedKeys" | "hasOnly" | "diff" | "changedKeys"),
        Expr::Call(callee, _) => callee.dotted().is_some_and(|d| d.ends_with("hasOnly") || d.ends_with("affectedKeys")),
        _ => false,
    }) || e.any(&|x| {
        x.dotted().is_some_and(|d| d == format!("request.resource.data.{field}"))
            || matches!(x, Expr::Index(base, key) if base.dotted().as_deref() == Some("request.resource.data") && **key == Expr::Str(field.into()))
    })
}

fn escalation_finding(site: &Site, lookups: &[(String, String)], file: &str) -> Option<Finding> {
    if !site
        .methods
        .iter()
        .any(|m| matches!(m.as_str(), "write" | "create" | "update"))
    {
        return None;
    }
    let [
        ..,
        Segment::Literal(collection),
        Segment::Wildcard {
            name: wildcard,
            recursive: false,
        },
    ] = site.path.as_slice()
    else {
        return None;
    };
    let cond = site.condition.as_ref()?;
    if !compares_uid_with(cond, wildcard) {
        return None; // Not owner-editable; other checks cover open writes.
    }
    let (_, field) = lookups
        .iter()
        .find(|(c, field)| c == collection && !restricts_fields(cond, field))?;
    let path = display_path(&site.path);
    Some(Finding {
        rule: "FB006",
        source: "dwarpal",
        severity: Severity::Critical,
        file: file.to_string(),
        line: site.line,
        title: format!("Users can make themselves admin by editing their own `{field}`"),
        detail: format!(
            "Other rules trust the `{field}` field of the caller's own document in {collection}, but this rule lets users write \
             their own document at {path} without restricting which fields change. Anyone can set `{field}` to the value \
             that grants extra access."
        ),
        fix: format!(
            "Stop users from changing `{field}`, for example:\nallow {}: if request.auth.uid == {wildcard}\n  && !request.resource.data.diff(resource.data).affectedKeys().hasAny(['{field}']);\n(for create, also require request.resource.data.{field} to be the default value)",
            site.methods.join(", ")
        ),
        prompt: format!(
            "In {file} (line {}), users can update their own document at {path} including the `{field}` field, but other \
             Firestore rules use that field to grant access (privilege escalation). Change the rule so users can still edit \
             their own document but can never set or change `{field}` (on create, require it to be the default value). \
             Keep the rest of the rules the same and explain the change.",
            site.line
        ),
    })
}

fn upload_limits_finding(site: &Site, file: &str) -> Option<Finding> {
    if !site.service.contains("storage")
        || !site
            .methods
            .iter()
            .any(|m| matches!(m.as_str(), "write" | "create" | "update"))
    {
        return None;
    }
    let cond = site.condition.as_ref()?;
    if !authorized(cond) {
        return None; // The access finding is the bigger problem.
    }
    let size = mentions(cond, "request.resource.size");
    let kind = mentions(cond, "request.resource.contentType");
    if size && kind {
        return None;
    }
    let missing = match (size, kind) {
        (false, false) => "size or file type",
        (false, true) => "size",
        _ => "file type",
    };
    let path = display_path(&site.path);
    Some(Finding {
        rule: "FB007",
        source: "dwarpal",
        severity: Severity::Medium,
        file: file.to_string(),
        line: site.line,
        title: format!("Uploads to {path} have no {missing} limit"),
        detail: "Users can upload files of any size or type, which can run up your storage bill and let your bucket host malware or abusive content.".into(),
        fix: "Add limits, for example:\n&& request.resource.size < 5 * 1024 * 1024\n&& request.resource.contentType.matches('image/.*')".into(),
        prompt: format!(
            "In {file} (line {}), the Cloud Storage rule for {path} allows uploads without a {missing} limit. Add a size limit \
             (for example 5 MB) and restrict the content type to what the app actually uploads, keeping the existing access checks.",
            site.line
        ),
    })
}

// Display helpers.

fn display_path(path: &[Segment]) -> String {
    let mut segments: Vec<String> = path
        .iter()
        .map(|s| match s {
            Segment::Literal(l) => l.clone(),
            Segment::Wildcard {
                name,
                recursive: true,
            } => format!("{{{name}=**}}"),
            Segment::Wildcard {
                name,
                recursive: false,
            } => format!("{{{name}}}"),
        })
        .collect();
    // Drop the standard prefixes: /databases/{database}/documents and /b/{bucket}/o.
    let standard_prefix = segments.len() >= 3
        && matches!(
            (segments[0].as_str(), segments[2].as_str()),
            ("databases", "documents") | ("b", "o")
        );
    if standard_prefix {
        segments.drain(..3);
    }
    format!("/{}", segments.join("/"))
}

fn describe_methods(methods: &[String]) -> String {
    let has = |m: &str| methods.iter().any(|x| x == m);
    let read = has("read") || (has("get") && has("list"));
    let write = has("write") || (has("create") && has("update") && has("delete"));
    let mut words = Vec::new();
    if read {
        words.push("read");
    } else {
        if has("get") {
            words.push("read single items in");
        }
        if has("list") {
            words.push("list");
        }
    }
    if write {
        words.extend(["create", "change", "delete"]);
    } else {
        for (m, w) in [
            ("create", "create"),
            ("update", "change"),
            ("delete", "delete"),
        ] {
            if has(m) {
                words.push(w);
            }
        }
    }
    match words.as_slice() {
        [] => "access".into(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

fn store_name(service: &str) -> &'static str {
    if service.contains("storage") {
        "Storage bucket"
    } else {
        "Firestore database"
    }
}

/// Today's date as YYYY-MM-DD (UTC), without a date library.
pub fn today() -> String {
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0) as i64;
    // Howard Hinnant's civil-from-days algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}
