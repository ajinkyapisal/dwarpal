use std::process::Command;

use serde_json::Value;

fn run(args: &[&str]) -> (Option<i32>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_dwarpal"))
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    (
        output.status.code(),
        String::from_utf8(output.stdout).unwrap(),
    )
}

/// (rule, severity, line) for every finding in a file.
fn findings(path: &str) -> Vec<(String, String, u64)> {
    let (_, out) = run(&["firebase", path, "--format", "json"]);
    let json: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json["errors"], Value::Array(vec![]), "{out}");
    let mut found: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["rule"].as_str().unwrap().to_string(),
                f["severity"].as_str().unwrap().to_string(),
                f["line"].as_u64().unwrap(),
            )
        })
        .collect();
    found.sort_by_key(|f| f.2);
    found
}

fn expect(path: &str, expected: &[(&str, &str, u64)]) {
    let expected: Vec<_> = expected
        .iter()
        .map(|(r, s, l)| (r.to_string(), s.to_string(), *l))
        .collect();
    assert_eq!(findings(path), expected, "{path}");
}

#[test]
fn test_mode() {
    expect(
        "tests/fixtures/insecure/test_mode.rules",
        &[("FB002", "critical", 16)],
    );
}

#[test]
fn open_rules() {
    expect(
        "tests/fixtures/insecure/open.rules",
        &[
            ("FB001", "critical", 5),
            ("FB001", "high", 8),
            ("FB003", "high", 9),
        ],
    );
}

#[test]
fn signed_in_only() {
    expect(
        "tests/fixtures/insecure/signed_in.rules",
        &[
            ("FB004", "critical", 5),
            ("FB005", "medium", 8),
            ("FB005", "critical", 11),
        ],
    );
}

#[test]
fn privilege_escalation() {
    expect(
        "tests/fixtures/insecure/escalation.rules",
        &[("FB006", "critical", 15)],
    );
}

#[test]
fn storage() {
    expect(
        "tests/fixtures/insecure/storage.rules",
        &[
            ("FB001", "high", 5),
            ("FB007", "medium", 6),
            ("FB005", "critical", 9),
        ],
    );
}

#[test]
fn realtime_database() {
    expect(
        "tests/fixtures/insecure/database.rules.json",
        &[
            ("RT002", "critical", 4),
            ("RT002", "critical", 5),
            ("RT004", "high", 8),
            ("RT004", "critical", 9),
            ("RT001", "high", 13),
        ],
    );
}

#[test]
fn secure_rules_have_no_findings() {
    let (code, out) = run(&["firebase", "tests/fixtures/secure"]);
    assert!(
        out.contains("3 file(s) checked: 0 critical, 0 high, 0 medium, 0 low"),
        "{out}"
    );
    assert_eq!(code, Some(0));
}

#[test]
fn finds_rules_through_firebase_json() {
    let (code, out) = run(&["firebase", "tests/fixtures/project", "--format", "json"]);
    let json: Value = serde_json::from_str(&out).unwrap();
    let files: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["file"].as_str().unwrap())
        .collect();
    assert!(
        files.iter().all(|f| f.ends_with("config/firestore.rules")),
        "{files:?}"
    );
    assert_eq!(files.len(), 3);
    assert_eq!(code, Some(1));
}

#[test]
fn exit_codes_follow_fail_on() {
    let file = "tests/fixtures/insecure/signed_in.rules";
    assert_eq!(run(&["firebase", file]).0, Some(1));
    assert_eq!(run(&["firebase", file, "--fail-on", "never"]).0, Some(0));
    assert_eq!(
        run(&["firebase", "tests/fixtures/secure", "--fail-on", "low"]).0,
        Some(0)
    );
}

#[test]
fn parse_errors_are_reported() {
    let dir = std::env::temp_dir().join("dwarpal-broken-rules");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("firestore.rules"),
        "service cloud.firestore {\n  match /a {\n    allow read: if ;\n",
    )
    .unwrap();
    let (code, out) = run(&["firebase", dir.to_str().unwrap()]);
    assert_eq!(code, Some(2));
    assert!(out.contains("could not parse: line 3"), "{out}");
}

#[test]
fn sarif_output() {
    let (_, out) = run(&[
        "firebase",
        "tests/fixtures/insecure/escalation.rules",
        "--format",
        "sarif",
    ]);
    let sarif: Value = serde_json::from_str(&out).unwrap();
    let result = &sarif["runs"][0]["results"][0];
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(result["ruleId"], "FB006");
    assert_eq!(result["level"], "error");
    assert_eq!(
        result["locations"][0]["physicalLocation"]["region"]["startLine"],
        15
    );
}

#[test]
fn findings_include_fix_and_agent_prompt() {
    let (_, out) = run(&[
        "firebase",
        "tests/fixtures/insecure/signed_in.rules",
        "--format",
        "json",
    ]);
    let json: Value = serde_json::from_str(&out).unwrap();
    let users = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule"] == "FB004")
        .unwrap();
    assert!(
        users["fix"]
            .as_str()
            .unwrap()
            .contains("request.auth.uid == userId")
    );
    assert!(
        users["prompt"]
            .as_str()
            .unwrap()
            .contains("signed_in.rules (line 5)")
    );
}

// Regressions found by running the checker on real rules files from GitHub.

#[test]
fn if_false_denies_everything() {
    expect("tests/fixtures/edge/denied.rules", &[]);
}

#[test]
fn or_branch_without_auth_is_open() {
    expect("tests/fixtures/edge/uploads.rules", &[("FB003", "high", 5)]);
}

#[test]
fn auth_equals_null_is_public() {
    expect(
        "tests/fixtures/edge/database.rules.json",
        &[("RT003", "critical", 3), ("RT003", "high", 5)],
    );
}

#[test]
fn field_limited_updates_are_deliberate() {
    expect("tests/fixtures/edge/counters.rules", &[]);
}
