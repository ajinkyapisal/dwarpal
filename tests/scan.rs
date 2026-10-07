//! End-to-end: build a small "vibe-coded" Next.js + Supabase app with the
//! usual mistakes in a temporary git repository, run `dwarpal scan` on it,
//! and check what it reports. Fake keys are assembled at runtime so no
//! secret-looking strings live in this repository.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

fn b64url(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fn supabase_key(role: &str) -> String {
    let header = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = b64url(
        json!({"iss": "supabase", "ref": "qwertyuiopasdfgh", "role": role, "iat": 1_700_000_000, "exp": 2_000_000_000})
            .to_string()
            .as_bytes(),
    );
    format!(
        "{header}.{payload}.{}",
        "Xk2vR9pQ7mN4wL8zT1yH6bJ3cF5gD0sA_eUoIiKr2Wq"
    )
}

fn fake_stripe_secret() -> String {
    ["sk", "_live_", "51NxQ2vR9pQ7mN4wL8zT1yH6bJ3c"].concat()
}

fn fake_openai_key() -> String {
    [
        "sk",
        "-proj-",
        "Xk2vR9pQ7mN4wL8zT1yH6bJ3cF5gD0sAeUoIiKr2WqZx",
    ]
    .concat()
}

fn write(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
}

fn package_files(root: &Path, next_version: &str) {
    write(
        root,
        "package.json",
        &json!({"name": "shop", "dependencies": {"next": next_version, "react": "18.2.0", "@supabase/supabase-js": "2.39.0", "openai": "4.20.0"}})
            .to_string(),
    );
    write(
        root,
        "package-lock.json",
        &json!({
            "name": "shop", "lockfileVersion": 3, "requires": true,
            "packages": {
                "": {"name": "shop", "dependencies": {"next": next_version}},
                "node_modules/next": {"version": next_version},
                "node_modules/react": {"version": "18.2.0"}
            }
        })
        .to_string(),
    );
}

/// The app as an AI tool might generate it.
fn vibe_app(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("dwarpal-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    git(&root, &["init", "-q"]);
    package_files(&root, "14.1.0");
    write(&root, ".gitignore", "node_modules\n.next\n");
    write(
        &root,
        ".env.local",
        &format!(
            "NEXT_PUBLIC_SUPABASE_URL=https://qwertyuiopasdfgh.supabase.co\n\
             NEXT_PUBLIC_SUPABASE_ANON_KEY={}\n\
             NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY={}\n\
             NEXT_PUBLIC_OPENAI_API_KEY={}\n",
            supabase_key("anon"),
            supabase_key("service_role"),
            fake_openai_key()
        ),
    );
    write(
        &root,
        "app/admin/page.tsx",
        "\"use client\";\nimport { createClient } from \"@supabase/supabase-js\";\n\n\
         const admin = createClient(\n  process.env.NEXT_PUBLIC_SUPABASE_URL!,\n  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!\n);\n\n\
         export default function Admin() { return null; }\n",
    );
    write(
        &root,
        "lib/stripe.ts",
        &format!(
            "import Stripe from \"stripe\";\n\nexport const stripe = new Stripe(\"{}\");\n",
            fake_stripe_secret()
        ),
    );
    write(
        &root,
        "supabase/migrations/20260101000000_init.sql",
        "create table public.profiles (id uuid primary key, name text);\n\
         alter table public.profiles enable row level security;\n\
         create policy \"Own profile\" on public.profiles for select using (auth.uid() = id);\n\n\
         create table public.orders (id bigint primary key, user_id uuid, total int);\n\n\
         create policy \"Anyone can add reviews\" on public.profiles for insert with check (true);\n",
    );
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "init"]);
    root
}

/// The same app, done right.
fn secure_app(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("dwarpal-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    git(&root, &["init", "-q"]);
    package_files(&root, "15.5.7");
    write(
        &root,
        ".gitignore",
        "node_modules\n.next\n.env*\n!.env.example\n",
    );
    write(
        &root,
        ".env.example",
        "NEXT_PUBLIC_SUPABASE_URL=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\nSUPABASE_SERVICE_ROLE_KEY=\nOPENAI_API_KEY=\n",
    );
    write(
        &root,
        ".env.local",
        &format!(
            "NEXT_PUBLIC_SUPABASE_ANON_KEY={}\nSUPABASE_SERVICE_ROLE_KEY={}\n",
            supabase_key("anon"),
            supabase_key("service_role")
        ),
    );
    write(
        &root,
        "app/page.tsx",
        "\"use client\";\nimport { createClient } from \"@supabase/supabase-js\";\n\
         const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);\n",
    );
    write(
        &root,
        "app/api/admin/route.ts",
        "import { createClient } from \"@supabase/supabase-js\";\n\
         const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n",
    );
    write(
        &root,
        "supabase/migrations/20260101000000_init.sql",
        "create table public.orders (id bigint primary key, user_id uuid, total int);\n\
         alter table public.orders enable row level security;\n\
         create policy \"Own orders\" on public.orders for select to authenticated using (auth.uid() = user_id);\n",
    );
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "init"]);
    root
}

fn scan(root: &Path, extra: &[&str]) -> (Option<i32>, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_dwarpal"))
        .args(["scan", root.to_str().unwrap(), "--format", "json"])
        .args(extra)
        .output()
        .unwrap();
    let json = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&output.stdout)));
    (output.status.code(), json)
}

fn rules(json: &Value) -> Vec<(String, String, String)> {
    json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["rule"].as_str().unwrap().into(),
                f["severity"].as_str().unwrap().into(),
                f["title"].as_str().unwrap().into(),
            )
        })
        .collect()
}

fn tool_works(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

#[test]
fn finds_the_usual_mistakes_with_own_checks() {
    let root = vibe_app("own");
    let (code, json) = scan(&root, &["--no-external"]);
    let found = rules(&json);
    let has = |rule: &str, severity: &str, title_part: &str| {
        found
            .iter()
            .any(|(r, s, t)| r == rule && s == severity && t.contains(title_part))
    };
    assert!(
        has("EX001", "critical", "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY"),
        "{found:#?}"
    );
    assert!(
        has("EX001", "critical", "NEXT_PUBLIC_OPENAI_API_KEY"),
        "{found:#?}"
    );
    assert!(
        has("EX002", "critical", "service_role key used in browser code"),
        "{found:#?}"
    );
    assert!(
        has("EX003", "high", ".env.local with secrets is committed"),
        "{found:#?}"
    );
    assert!(
        has("SB001", "critical", "`orders` has no row-level security"),
        "{found:#?}"
    );
    assert!(
        has("SB002", "critical", "can add rows to `profiles`"),
        "{found:#?}"
    );
    assert!(
        !found.iter().any(|(_, _, t)| t.contains("ANON_KEY")),
        "anon key is public by design: {found:#?}"
    );
    assert_eq!(found.len(), 6, "{found:#?}");
    assert_eq!(
        json["stack"],
        json!(["Next.js", "React", "Supabase", "OpenAI"])
    );
    assert_eq!(code, Some(1));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn translates_gitleaks_and_trivy() {
    if !tool_works("gitleaks") || !tool_works("trivy") {
        eprintln!("skipped: gitleaks and trivy are not both installed");
        return;
    }
    let root = vibe_app("external");
    let (_, json) = scan(&root, &[]);
    let found = rules(&json);
    let sources: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["source"].as_str().unwrap())
        .collect();
    // The hard-coded Stripe key, found by gitleaks in git history.
    assert!(
        found
            .iter()
            .any(|(r, s, t)| r == "GL001" && s == "critical" && t.contains("Stripe")),
        "{found:#?}"
    );
    // Secrets inside the committed .env.local are covered by EX003, not repeated.
    assert!(
        !json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["source"] == "gitleaks" && f["file"] == ".env.local")
    );
    // One finding for next, with a concrete version to upgrade to.
    let next: Vec<_> = found
        .iter()
        .filter(|(r, _, t)| r == "DV001" && t.contains(" next "))
        .collect();
    assert_eq!(next.len(), 1, "{found:#?}");
    assert!(
        next[0].2.starts_with("Upgrade next from 14.1.0 to "),
        "{next:?}"
    );
    let detail = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule"] == "DV001" && f["title"].as_str().unwrap().contains(" next "))
        .unwrap()["detail"]
        .as_str()
        .unwrap();
    if !next[0].2.contains(" to 14.") {
        assert!(detail.contains("If you can't upgrade yet, 14."), "{detail}");
    }
    assert!(sources.contains(&"trivy") && sources.contains(&"gitleaks"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn secure_app_is_clean() {
    let root = secure_app("secure");
    let (_, json) = scan(&root, &[]);
    // Vulnerability databases keep growing, so any pinned version eventually
    // has advisories; trivy is tested on the vulnerable app instead.
    let found: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["source"] != "trivy")
        .collect();
    assert!(found.is_empty(), "{json:#}");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn messages_are_single_clean_lines() {
    let root = vibe_app("text");
    let (_, json) = scan(&root, &[]);
    for f in json["findings"].as_array().unwrap() {
        for field in ["title", "detail", "prompt"] {
            let text = f[field].as_str().unwrap();
            assert!(
                !text.contains('\n') && !text.contains("   "),
                "{} {field}: {text:?}",
                f["rule"]
            );
        }
    }
    fs::remove_dir_all(root).unwrap();
}
