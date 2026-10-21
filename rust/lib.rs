pub mod effects;

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

const MAX_FILES: usize = 512;
const MAX_ENTRIES: usize = 20_000;

fn read_bounded(path: &Path) -> Result<String, String> {
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err(format!(
            "expected regular source/config file: {}",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    file.take(effects::MAX_SOURCE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > effects::MAX_SOURCE {
        return Err(format!(
            "file exceeds 256 KiB analysis bound: {}",
            path.display()
        ));
    }
    return String::from_utf8(bytes).map_err(|_| format!("invalid UTF-8: {}", path.display()));
}

fn source_path(root: &Path, name: &str) -> Result<PathBuf, String> {
    let path = Path::new(name);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return Err(format!("expected project-relative source path: {name}"));
    }
    let mut current = root.to_path_buf();
    for component in path.components() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|e| format!("{name}: {e}"))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("source symlink refused: {name}"));
        }
    }
    if current.extension().is_none_or(|ext| ext != "ores") || !current.is_file() {
        return Err(format!("expected regular .ores source file: {name}"));
    }
    return Ok(current);
}

fn discover(root: &Path) -> Result<Vec<String>, String> {
    let mut pending = vec![(root.to_path_buf(), 0)];
    let mut paths = Vec::new();
    let mut entries = 0;
    while let Some((dir, depth)) = pending.pop() {
        if depth > 64 {
            return Err("source discovery depth budget exceeded".into());
        }
        for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            entries += 1;
            if entries > MAX_ENTRIES {
                return Err(
                    "source discovery entry budget exceeded; use --file or [effects].files".into(),
                );
            }
            let name = entry.file_name();
            if name.to_string_lossy().starts_with('.')
                || matches!(name.to_str(), Some("target" | "node_modules"))
            {
                continue;
            }
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if kind.is_symlink() {
                return Err(format!(
                    "source discovery symlink refused: {}",
                    entry.path().display()
                ));
            }
            if kind.is_dir() {
                pending.push((entry.path(), depth + 1));
            } else if entry.path().extension().is_some_and(|ext| ext == "ores") {
                paths.push(
                    entry
                        .path()
                        .strip_prefix(root)
                        .map_err(|e| e.to_string())?
                        .to_str()
                        .ok_or("non-UTF-8 source path")?
                        .to_string(),
                );
                if paths.len() > MAX_FILES {
                    return Err(
                        "source discovery exceeds 512 files; use --file or [effects].files".into(),
                    );
                }
            }
        }
    }
    paths.sort();
    return Ok(paths);
}

#[derive(Default)]
struct Options {
    root: PathBuf,
    files: Vec<String>,
    strict: bool,
    effects: bool,
}

fn options(args: &[OsString]) -> Result<Options, String> {
    let mut result = Options {
        root: PathBuf::from("."),
        ..Options::default()
    };
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].to_str().ok_or("non-UTF-8 argument")?;
        match arg {
            "--effects" => result.effects = true,
            "--effects-strict" => result.strict = true,
            "--root" | "--file" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| format!("{arg} requires a value"))?;
                if arg == "--root" {
                    result.root = PathBuf::from(value);
                } else {
                    result
                        .files
                        .push(value.to_str().ok_or("non-UTF-8 source path")?.to_string());
                }
            }
            _ if arg.starts_with("--root=") => result.root = PathBuf::from(&arg[7..]),
            _ if arg.starts_with("--file=") => result.files.push(arg[7..].to_string()),
            "--fuzz" | "--race" | "--logical" | "--model" | "--trace" => {
                return Err(
                    "--effects is a separate static mode, not a runtime race/fuzz certificate"
                        .into(),
                );
            }
            _ => return Err(format!("unsupported option for --effects: {arg}")),
        }
        i += 1;
    }
    if !result.effects {
        return Err("--file and --effects-strict require --effects".into());
    }
    return Ok(result);
}

fn scan(args: &[OsString]) -> Result<(String, i32), String> {
    let mut options = options(args)?;
    let root = options
        .root
        .canonicalize()
        .map_err(|e| format!("project root: {e}"))?;
    if !root.is_dir() {
        return Err("project root must be a directory".into());
    }
    // Parse configuration even with explicit files; malformed configuration
    // must not be laundered into a clean result by an unrelated CLI option.
    let manifest = root.join("oreslang-test.toml");
    let config = match fs::symlink_metadata(&manifest) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err("source configuration symlink refused".into());
            }
            Some(
                read_bounded(&manifest)?
                    .parse::<toml::Table>()
                    .map_err(|e| format!("invalid TOML: {e}"))?,
            )
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.to_string()),
    };
    if options.files.is_empty() {
        if let Some(value) = config.as_ref().and_then(|c| c.get("effects")) {
            let params = value.as_table().ok_or("[effects] must be a TOML table")?;
            if let Some(value) = params.get("files") {
                options.files = value
                    .as_array()
                    .ok_or("[effects].files must be an array of strings")?
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .map(str::to_string)
                            .ok_or("[effects].files must be an array of strings")
                    })
                    .collect::<Result<_, _>>()?;
                if options.files.is_empty() {
                    return Err("[effects].files must not be empty".into());
                }
            }
        }
        if options.files.is_empty() {
            options.files = discover(&root)?;
        }
    }
    if options.files.is_empty() || options.files.len() > MAX_FILES {
        return Err("--effects needs one or more --file paths, [effects].files, or discoverable .ores files (max 512)".into());
    }
    let mut output = String::new();
    let mut warnings = 0;
    let mut checked = 0;
    let mut seen = std::collections::BTreeSet::new();
    let mut source_bytes = 0;
    let mut shown = 0;
    for name in options.files {
        let path = source_path(&root, &name)?;
        if !seen.insert(path.canonicalize().map_err(|e| e.to_string())?) {
            continue;
        }
        let source = read_bounded(&path)?;
        source_bytes += source.len();
        if source_bytes > 4 * 1024 * 1024 {
            return Err("aggregate source budget exceeds 4 MiB; narrow --file selection".into());
        }
        let report =
            effects::analyze(&source).map_err(|e| format!("EFFECTS INCONCLUSIVE {name}: {e}"))?;
        if report.inspected == 0 {
            return Err(format!(
                "EFFECTS INCONCLUSIVE {name}: no braced named fnc/method body inspected"
            ));
        }
        warnings += report.diagnostics.len();
        if warnings > 16_384 {
            return Err("diagnostic budget exceeded; narrow --file selection".into());
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
    output.push_str(&format!("EFFECTS ADVISORY inspected={checked} warnings={warnings}; direct syntax only, no call-graph/catch/actor-runtime proof\n"));
    return Ok((output, i32::from(options.strict && warnings > 0)));
}

fn status(mut command: Command) -> i32 {
    match command.status() {
        Ok(status) => return status.code().unwrap_or(2),
        Err(error) => {
            eprintln!("oreslang test: cannot launch legacy/core runner: {error}");
            return 2;
        }
    }
}

/// Public process boundary. Legacy native/race/fuzz engines remain migration debt.
pub fn run(mut args: Vec<OsString>, core_launcher: bool) -> i32 {
    if core_launcher {
        if args.first().is_some_and(|arg| arg == "test") {
            args.remove(0);
        } else {
            let core = std::env::var_os("ORESLANG_BIN").unwrap_or_else(|| "oreslang-core".into());
            // Resolve bare executable names through PATH before comparing aliases.
            let candidate = if Path::new(&core).components().count() == 1 {
                std::env::var_os("PATH").and_then(|paths| {
                    std::env::split_paths(&paths)
                        .map(|dir| dir.join(&core))
                        .find(|p| p.is_file())
                })
            } else {
                Some(PathBuf::from(&core))
            };
            if candidate.as_ref().and_then(|p| p.canonicalize().ok())
                == std::env::current_exe()
                    .ok()
                    .and_then(|p| p.canonicalize().ok())
                || candidate.as_ref().and_then(|p| p.canonicalize().ok())
                    == Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("bin/oreslang")
                        .canonicalize()
                        .ok()
            {
                eprintln!("ORESLANG_BIN resolves to wrapper; recursion refused");
                return 2;
            }
            let mut command = Command::new(core);
            command.args(args);
            return status(command);
        }
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("usage: oreslang test [--root DIR] [--effects [--effects-strict] [--file SOURCE]...]\n       oreslang test [--fuzz | --race [--logical]] [legacy runner options]\n\n--effects: bounded advisory direct-syntax hints. Effects/call targets remain unknown; no compiler, catch coverage or actor-runtime proof.\nExit 0: advisory scan completed; 1: strict warnings; 2: invalid/inconclusive.\nNative/race/fuzz modes currently delegate to the legacy runner.");
        return 0;
    }
    if args.iter().any(|a| {
        a == "--effects"
            || a == "--effects-strict"
            || a == "--file"
            || a.to_str().is_some_and(|s| s.starts_with("--file="))
    }) {
        match scan(&args) {
            Ok((output, code)) => {
                print!("{output}");
                return code;
            }
            Err(error) => {
                eprintln!("oreslang test: {error}");
                return 2;
            }
        }
    }
    let legacy = std::env::var_os("ORESLANG_TEST_LEGACY")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("bin/legacy-oreslang-test"));
    // Reject direct and symlinked aliases to this executable and its
    // launch wrappers. This keeps a mistaken legacy override from spawning
    // the same launcher indefinitely.
    let target = if legacy.components().count() == 1 {
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|dir| dir.join(&legacy))
                .find(|path| path.is_file())
        })
    } else {
        Some(legacy.clone())
    };
    let resolved = target.and_then(|path| path.canonicalize().ok());
    let current = std::env::current_exe()
        .ok()
        .and_then(|path| path.canonicalize().ok());
    let companion = current.as_ref().map(|path| {
        path.with_file_name(if cfg!(windows) { "oreslang.exe" } else { "oreslang" })
    });
    let bin = Path::new(env!("CARGO_MANIFEST_DIR")).join("bin");
    let known_wrappers = [
        current,
        companion,
        bin.join("oreslang").canonicalize().ok(),
        bin.join("oreslang-test").canonicalize().ok(),
    ];
    if resolved.is_some() && known_wrappers.contains(&resolved) {
        eprintln!("ORESLANG_TEST_LEGACY resolves to wrapper; recursion refused");
        return 2;
    }
    let mut command = Command::new(legacy);
    command.args(args);
    return status(command);
}
