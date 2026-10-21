use serde_json::Value;
use std::path::{Component, Path, PathBuf};
pub type Result<T> = std::result::Result<T, String>;
pub fn safe_path(root: &Path, relative: &str) -> Result<PathBuf> {
    let p = Path::new(relative);
    if p.is_absolute()
        || relative.is_empty()
        || p.components()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(format!("path must be project-relative: {relative}"));
    }
    // Reject link traversal (including intermediate parents) without following links.
    let mut target = root.to_path_buf();
    for part in p.components() {
        if let Component::Normal(name) = part {
            target.push(name);
            if target
                .symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink())
            {
                return Err(format!("source symlink refused: {relative}"));
            }
        }
    }
    Ok(target)
}
#[cfg(unix)]
fn open_no_symlink_components(path: &Path) -> Result<std::fs::File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    // Start at an owned directory FD, not a pathname that can be renamed
    // between component validation and the final read.
    let start = if path.is_absolute() { "/" } else { "." };
    let mut directory: OwnedFd = std::fs::File::open(start)
        .map_err(|e| e.to_string())?
        .into();
    let mut parts = path.components().peekable();
    while let Some(part) = parts.next() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                let name = CString::new(name.as_bytes())
                    .map_err(|_| "NUL byte in input path")?;
                let is_last = parts.peek().is_none();
                let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC
                    | libc::O_NONBLOCK
                    | if is_last { 0 } else { libc::O_DIRECTORY };
                let opened = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
                if opened < 0 {
                    return Err(format!(
                        "cannot open input without symlink traversal: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                // SAFETY: successful openat transfers a fresh owned fd to us.
                directory = unsafe { OwnedFd::from_raw_fd(opened) };
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err("parent traversal in input path is forbidden".into());
            }
        }
    }
    Ok(std::fs::File::from(directory))
}

pub fn bounded_read(path: &Path, max: usize) -> Result<Vec<u8>> {
    if path
        .symlink_metadata()
        .map_err(|e| e.to_string())?
        .file_type()
        .is_symlink()
    {
        return Err("trace/corpus symlink is forbidden".into());
    }
    // Every path component is opened relative to the preceding directory
    // handle. O_NOFOLLOW prevents intermediate-directory substitution, not
    // just a last-component symlink swap.
    #[cfg(unix)]
    let file = open_no_symlink_components(path)?;
    #[cfg(not(unix))]
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > max as u64 {
        return Err("invalid or oversized input".into());
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > max {
        return Err("input exceeds size budget".into());
    }
    Ok(bytes)
}
pub fn trace(path: &Path, expected: Option<&str>) -> Result<Vec<Value>> {
    let raw = bounded_read(path, 10_000_000)?;
    let s = std::str::from_utf8(&raw).map_err(|e| e.to_string())?;
    let lines: Vec<&str> = s.lines().collect();
    if !(2..=100_002).contains(&lines.len()) {
        return Err("trace requires begin/end and <=100000 events".into());
    }
    // serde_json defaults to last duplicate key; reject duplicate properties before parsing.
    let mut records = Vec::with_capacity(lines.len());
    for line in lines {
        let mut de = serde_json::Deserializer::from_str(line);
        // Duplicate-key aware parsing is handled by a dedicated parser below.
        let v = parse_unique_object(&mut de)?;
        records.push(v);
    }
    let start = &records[0];
    let end = records.last().unwrap();
    if start["op"] != "begin"
        || start["version"].as_u64() != Some(1)
        || start["version"].is_boolean()
        || end["op"] != "end"
    {
        return Err("missing ORES_RACE_V1 begin/end".into());
    }
    let run_id = field(start, "run_id")?;
    field(start, "backend")?;
    if end["run_id"] != run_id || end["events"].as_u64() != Some((records.len() - 2) as u64) {
        return Err("invalid trace nonce or event count".into());
    }
    if expected.is_some_and(|v| v != run_id) {
        return Err("trace is stale or foreign to this invocation".into());
    }
    Ok(records)
}
/// Strictly decode a single JSON object, rejecting duplicate keys at any depth.
pub fn strict_json_object(input: &[u8]) -> Result<Value> {
    let mut parser = serde_json::Deserializer::from_slice(input);
    parse_unique_object(&mut parser)
}

fn parse_unique_object<'de, R: serde_json::de::Read<'de>>(
    de: &mut serde_json::Deserializer<R>,
) -> Result<Value> {
    use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
    use std::fmt;
    struct Unique;
    impl<'de> Visitor<'de> for Unique {
        type Value = Value;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a JSON value without duplicate object properties")
        }
        fn visit_bool<E: serde::de::Error>(self, value: bool) -> std::result::Result<Value, E> {
            Ok(Value::Bool(value))
        }
        fn visit_i64<E: serde::de::Error>(self, value: i64) -> std::result::Result<Value, E> {
            Ok(Value::Number(value.into()))
        }
        fn visit_u64<E: serde::de::Error>(self, value: u64) -> std::result::Result<Value, E> {
            Ok(Value::Number(value.into()))
        }
        fn visit_f64<E: serde::de::Error>(self, value: f64) -> std::result::Result<Value, E> {
            serde_json::Number::from_f64(value)
                .map(Value::Number)
                .ok_or_else(|| E::custom("nonfinite JSON number"))
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<Value, E> {
            Ok(Value::String(value.to_owned()))
        }
        fn visit_string<E: serde::de::Error>(self, value: String) -> std::result::Result<Value, E> {
            Ok(Value::String(value))
        }
        fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_some<D: serde::Deserializer<'de>>(
            self,
            d: D,
        ) -> std::result::Result<Value, D::Error> {
            Unique.deserialize(d)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
            let mut out = Vec::new();
            while let Some(value) = seq.next_element_seed(Unique)? {
                out.push(value);
            }
            Ok(Value::Array(out))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
            let mut out = serde_json::Map::new();
            while let Some(key) = map.next_key::<String>()? {
                if out.contains_key(&key) {
                    return Err(serde::de::Error::custom("duplicate JSON property"));
                }
                let value = map.next_value_seed(Unique)?;
                out.insert(key, value);
            }
            Ok(Value::Object(out))
        }
    }
    impl<'de> DeserializeSeed<'de> for Unique {
        type Value = Value;
        fn deserialize<D: serde::Deserializer<'de>>(
            self,
            d: D,
        ) -> std::result::Result<Value, D::Error> {
            d.deserialize_any(self)
        }
    }
    let value = Unique.deserialize(&mut *de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    if !value.is_object() {
        return Err("race trace record must be a JSON object".into());
    }
    Ok(value)
}
pub fn field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    let s = v
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("invalid {key}"))?;
    if s.is_empty() || s.len() > 512 || s.chars().any(|c| c < ' ') {
        return Err(format!("invalid {key}"));
    }
    Ok(s)
}
pub fn table_command(v: &toml::Value, section: &str) -> Result<Vec<String>> {
    let a = v
        .get(section)
        .and_then(|s| s.get("command"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("[{section}].command required"))?;
    let cmd: Option<Vec<_>> = a
        .iter()
        .map(|x| x.as_str().filter(|s| !s.is_empty()).map(str::to_owned))
        .collect();
    cmd.filter(|v| !v.is_empty())
        .ok_or_else(|| format!("[{section}].command requires nonempty argv array"))
}

#[cfg(all(test, unix))]
mod bounded_read_security_tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink};

    #[test]
    fn accepts_regular_file_but_refuses_all_symlink_components() {
        let dir = tempfile::tempdir().unwrap();
        // Canonicalize the ambient system temp root (e.g. macOS /var -> /private/var).
        let root = dir.path().canonicalize().unwrap();
        let normal = root.join("normal");
        let outside = root.join("outside");
        fs::create_dir_all(&normal).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(normal.join("input"), b"safe").unwrap();
        fs::write(outside.join("input"), b"foreign").unwrap();
        assert_eq!(bounded_read(&normal.join("input"), 64).unwrap(), b"safe");
        symlink(&outside, root.join("linked-parent")).unwrap();
        assert!(
            bounded_read(&root.join("linked-parent/input"), 64).is_err(),
            "intermediate symlinks must not select a different source"
        );
        symlink(normal.join("input"), root.join("linked-file")).unwrap();
        assert!(bounded_read(&root.join("linked-file"), 64).is_err());
        assert!(bounded_read(&normal.join("input"), 2).is_err());
    }

    #[test]
    fn special_input_files_cannot_block_the_trace_reader() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap().join("pipe");
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        // O_NONBLOCK means an attacker cannot strand the reader opening a FIFO.
        assert!(bounded_read(&path, 128).is_err());
    }
}

#[cfg(test)]
mod strict_json_regression {
    use super::*;

    fn parse(line: &str) -> Result<Value> {
        let mut decoder = serde_json::Deserializer::from_str(line);
        parse_unique_object(&mut decoder)
    }

    #[test]
    fn nested_and_unicode_equivalent_duplicate_properties_are_rejected() {
        for source in [
            r#"{"op":"begin","meta":{"nested":[{"x":1,"x":2}]}}"#,
            r#"{"op":"begin","meta":[{"a":{"key":0,"key":1}}]}"#,
            r#"{"op":"begin","name":"first","\u006eame":"second"}"#,
            r#"{"op":"begin","meta":{"x":1,"\u0078":2}}"#,
        ] {
            assert!(parse(source).is_err(), "accepted duplicate keys: {source}");
        }
    }

    #[test]
    fn nested_distinct_keys_and_json_scalars_remain_supported() {
        let record = parse(r#"{"op":"begin","meta":[{"a":1,"b":2.5},null,true,false,"ok"]}"#)
            .expect("valid nested JSON");
        assert_eq!(record["meta"][0]["a"], 1);
        assert_eq!(record["meta"][0]["b"], 2.5);
        assert!(
            parse(r#"[{"x":1}]"#).is_err(),
            "trace top-level must be an object"
        );
    }
}
