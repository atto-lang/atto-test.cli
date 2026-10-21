//! Conservative advisory exceptional-effect scanner, preserving PR #6's Rust logic.
use crate::common::{bounded_read, safe_path, Result};
use oreslang_test::effects;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

fn discover(root: &Path) -> Result<Vec<String>> {
    let mut found = Vec::new();
    let mut entries = 0usize;
    for e in WalkDir::new(root)
        .follow_links(false)
        .max_depth(65)
        .into_iter()
        .filter_entry(|e| {
            let n = e.file_name().to_string_lossy();
            e.depth() == 0 || (!n.starts_with('.') && n != "target" && n != "node_modules")
        })
    {
        let e = e.map_err(|e| e.to_string())?;
        entries += 1;
        if entries > 20000 {
            return Err("source discovery exceeds 20000 entries".into());
        }
        if e.file_type().is_symlink() {
            return Err("source discovery symlink refused".into());
        }
        if e.file_type().is_file() && e.path().extension().is_some_and(|ext| ext == "ores") {
            let name = e
                .path()
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("non-UTF-8 source path")?
                .to_owned();
            found.push(name);
            if found.len() > 512 {
                return Err("source discovery exceeds 512 files".into());
            }
        }
    }
    found.sort();
    Ok(found)
}
pub fn run(root: &Path, cfg: &toml::Value, provided: &[String], strict: bool) -> Result<u8> {
    if cfg.get("effects").is_some_and(|v| !v.is_table()) {
        return Err("[effects] must be a TOML table".into());
    }
    let files: Vec<String> = if !provided.is_empty() {
        provided.to_vec()
    } else if let Some(list) = cfg.get("effects").and_then(|v| v.get("files")) {
        let items = list
            .as_array()
            .ok_or("[effects].files must be an array of strings")?;
        if items.is_empty() {
            return Err("[effects].files must not be empty".into());
        }
        items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or("invalid [effects].files path".into())
            })
            .collect::<Result<_>>()?
    } else {
        discover(root)?
    };
    if files.is_empty() || files.len() > 512 {
        return Err("--effects requires 1..512 .ores sources".into());
    }
    let mut output = String::new();
    let (mut warnings, mut checked, mut shown, mut source_bytes) = (0usize, 0usize, 0usize, 0usize);
    let mut seen = BTreeSet::<PathBuf>::new();
    for name in files {
        let path = safe_path(root, &name)?;
        if path.extension().is_none_or(|x| x != "ores") || !path.is_file() {
            return Err(format!("not an .ores source: {name}"));
        }
        if !seen.insert(path.canonicalize().map_err(|e| e.to_string())?) {
            continue;
        }
        let bytes = bounded_read(&path, effects::MAX_SOURCE)?;
        let source = std::str::from_utf8(&bytes)
            .map_err(|_| format!("EFFECTS INCONCLUSIVE {name}: invalid UTF-8"))?;
        source_bytes += bytes.len();
        if source_bytes > 4 * 1024 * 1024 {
            return Err("aggregate effect-analysis source budget exceeds 4 MiB".into());
        }
        let report =
            effects::analyze(source).map_err(|e| format!("EFFECTS INCONCLUSIVE {name}: {e}"))?;
        if report.inspected == 0 {
            return Err(format!(
                "EFFECTS INCONCLUSIVE {name}: no named callable body inspected"
            ));
        }
        warnings += report.diagnostics.len();
        if warnings > 16_384 {
            return Err("effects diagnostics budget exceeded".into());
        }
        for diagnostic in &report.diagnostics {
            if shown < 100 {
                output.push_str(&format!(
                    "EFFECT WARNING {name}:{} [{}] {}\n",
                    diagnostic.line, diagnostic.code, diagnostic.message
                ));
                shown += 1;
            }
        }
        checked += report.inspected;
    }
    if warnings > shown {
        output.push_str(&format!(
            "EFFECT WARNINGS TRUNCATED shown={shown} total={warnings}\n"
        ));
    }
    output.push_str(&format!(
        "EFFECTS ADVISORY inspected={checked} warnings={warnings}; direct syntax only, no call-graph/catch/actor-runtime proof\n"
    ));
    print!("{output}");
    Ok((strict && warnings > 0) as u8)
}
