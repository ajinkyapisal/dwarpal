//! Firebase security rules: Firestore, Cloud Storage and Realtime Database.

pub mod ast;
pub mod checks;
pub mod lexer;
pub mod parser;
pub mod rtdb;

use std::fs;
use std::path::{Path, PathBuf};

use crate::report::{FileError, Finding};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    /// Firestore or Cloud Storage rules language.
    Rules,
    /// Realtime Database JSON rules.
    Database,
}

/// Find rules files: the ones firebase.json points to, plus any *.rules and
/// database.rules.json files.
pub fn discover(root: &Path) -> Vec<(PathBuf, Kind)> {
    if root.is_file() {
        return vec![(root.to_path_buf(), kind_of(root))];
    }
    let mut found = Vec::new();
    if let Ok(text) = fs::read_to_string(root.join("firebase.json")) {
        if let Ok(config) = serde_json::from_str::<serde_json::Value>(&text) {
            for (section, key, kind) in [
                ("firestore", "rules", Kind::Rules),
                ("storage", "rules", Kind::Rules),
                ("database", "rules", Kind::Database),
            ] {
                let entries = match config.get(section) {
                    Some(serde_json::Value::Array(items)) => items.clone(),
                    Some(other) => vec![other.clone()],
                    None => vec![],
                };
                for entry in entries {
                    if let Some(file) = entry.get(key).and_then(|v| v.as_str()) {
                        found.push((root.join(file), kind));
                    }
                }
            }
        }
    }
    walk(root, &mut found, 0);
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found.dedup_by(|a, b| a.0 == b.0);
    found.retain(|(p, _)| p.is_file());
    found
}

fn walk(dir: &Path, found: &mut Vec<(PathBuf, Kind)>, depth: usize) {
    if depth > 8 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if !name.starts_with('.')
                && !matches!(
                    name.as_str(),
                    "node_modules" | "target" | "dist" | "build" | "vendor"
                )
            {
                walk(&path, found, depth + 1);
            }
        } else if name.ends_with(".rules") || name == "database.rules.json" {
            found.push((path.clone(), kind_of(&path)));
        }
    }
}

fn kind_of(path: &Path) -> Kind {
    if path.extension().is_some_and(|e| e == "json") {
        Kind::Database
    } else {
        Kind::Rules
    }
}

pub fn check_file(path: &Path, kind: Kind, display: &str) -> Result<Vec<Finding>, FileError> {
    let error = |message: String| FileError {
        file: display.to_string(),
        message,
    };
    let src = fs::read_to_string(path).map_err(|e| error(e.to_string()))?;
    match kind {
        Kind::Rules => {
            let rules = parser::parse(&src).map_err(|e| error(format!("could not parse: {e}")))?;
            Ok(checks::check(&rules, display))
        }
        Kind::Database => rtdb::check(&src, display).map_err(error),
    }
}
