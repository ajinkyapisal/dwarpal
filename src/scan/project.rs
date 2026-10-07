//! What a project is made of: its files, its stack, and what git tracks.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SKIP_DIRS: [&str; 16] = [
    "node_modules",
    ".git",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".vercel",
    ".netlify",
    ".turbo",
    "dist",
    "build",
    "out",
    "coverage",
    "vendor",
    "target",
    ".venv",
    "venv",
];
const MAX_FILE_BYTES: u64 = 1_000_000;

pub struct Project {
    pub root: PathBuf,
    /// Text files, relative to the root.
    pub files: Vec<PathBuf>,
    pub stack: BTreeSet<&'static str>,
    /// Paths tracked by git, relative to the root; None if not a git repo.
    pub tracked: Option<BTreeSet<PathBuf>>,
}

impl Project {
    pub fn load(root: &Path) -> Project {
        let mut files = Vec::new();
        walk(root, root, &mut files, 0);
        files.sort();
        let tracked = git_tracked(root);
        let mut project = Project {
            root: root.to_path_buf(),
            files,
            stack: BTreeSet::new(),
            tracked,
        };
        project.stack = detect_stack(&project);
        project
    }

    pub fn read(&self, rel: &Path) -> Option<String> {
        fs::read_to_string(self.root.join(rel)).ok()
    }

    pub fn has(&self, part: &str) -> bool {
        self.stack.contains(part)
    }

    pub fn is_ignored_by_git(&self, rel: &Path) -> bool {
        Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["check-ignore", "-q"])
            .arg(rel)
            .status()
            .is_ok_and(|s| s.success())
    }

    /// The labels shown at the top of a report, in a stable order.
    pub fn stack_labels(&self) -> Vec<&'static str> {
        STACK_ORDER
            .iter()
            .filter(|(key, _)| self.has(key))
            .map(|(_, label)| *label)
            .collect()
    }
}

fn walk(root: &Path, dir: &Path, files: &mut Vec<PathBuf>, depth: usize) {
    if depth > 12 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                walk(root, &path, files, depth + 1);
            }
        } else if meta.len() <= MAX_FILE_BYTES {
            if let Ok(rel) = path.strip_prefix(root) {
                files.push(rel.to_path_buf());
            }
        }
    }
}

fn git_tracked(root: &Path) -> Option<BTreeSet<PathBuf>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&output.stdout)
            .split('\0')
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .collect(),
    )
}

const STACK_ORDER: [(&str, &str); 17] = [
    ("nextjs", "Next.js"),
    ("vite", "Vite"),
    ("sveltekit", "SvelteKit"),
    ("nuxt", "Nuxt"),
    ("astro", "Astro"),
    ("expo", "Expo"),
    ("react", "React"),
    ("supabase", "Supabase"),
    ("firebase", "Firebase"),
    ("vercel", "Vercel"),
    ("netlify", "Netlify"),
    ("cloudflare", "Cloudflare"),
    ("stripe", "Stripe"),
    ("openai", "OpenAI"),
    ("anthropic", "Anthropic"),
    ("clerk", "Clerk"),
    ("python", "Python"),
];

fn detect_stack(project: &Project) -> BTreeSet<&'static str> {
    let mut stack = BTreeSet::new();
    let mut deps = String::new();
    for file in &project.files {
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        match name.as_str() {
            "package.json" => deps.push_str(&project.read(file).unwrap_or_default()),
            "requirements.txt" | "pyproject.toml" => {
                stack.insert("python");
                deps.push_str(&project.read(file).unwrap_or_default());
            }
            "firebase.json" | "firestore.rules" | "database.rules.json" => {
                stack.insert("firebase");
            }
            "vercel.json" => {
                stack.insert("vercel");
            }
            "netlify.toml" => {
                stack.insert("netlify");
            }
            "wrangler.toml" | "wrangler.jsonc" => {
                stack.insert("cloudflare");
            }
            _ => {}
        }
        if file.starts_with("supabase") {
            stack.insert("supabase");
        }
    }
    for (needle, part) in [
        ("\"next\"", "nextjs"),
        ("\"vite\"", "vite"),
        ("\"@sveltejs/kit\"", "sveltekit"),
        ("\"nuxt\"", "nuxt"),
        ("\"astro\"", "astro"),
        ("\"expo\"", "expo"),
        ("\"react\"", "react"),
        ("@supabase/", "supabase"),
        ("supabase", "supabase"),
        ("\"firebase\"", "firebase"),
        ("firebase-admin", "firebase"),
        ("\"stripe\"", "stripe"),
        ("@stripe/", "stripe"),
        ("\"openai\"", "openai"),
        ("@anthropic-ai/", "anthropic"),
        ("anthropic", "anthropic"),
        ("@clerk/", "clerk"),
        ("\"@vercel/", "vercel"),
    ] {
        if deps.contains(needle) {
            stack.insert(part);
        }
    }
    stack
}
