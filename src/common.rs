use serde_json::Value;
use std::path::{Component, Path, PathBuf};
pub type Result<T> = std::result::Result<T, String>;
pub fn safe_path(root: &Path, relative: &str) -> Result<PathBuf> {
    let p = Path::new(relative);
    if p.is_absolute() || relative.is_empty() || p.components().any(|c| matches!(c, Component::ParentDir | Component::Prefix(_))) {
        return Err(format!("path must be project-relative: {relative}"));
    }
    // Reject link traversal (including intermediate parents) without following links.
    let mut target = root.to_path_buf();
    for part in p.components() {
        if let Component::Normal(name) = part {
            target.push(name);
            if target.symlink_metadata().is_ok_and(|m| m.file_type().is_symlink()) {
                return Err(format!("source symlink refused: {relative}"));
            }
        }
    }
    Ok(target)
}
pub fn bounded_read(path: &Path, max: usize) -> Result<Vec<u8>> {
    if path.symlink_metadata().map_err(|e| e.to_string())?.file_type().is_symlink() {
        return Err("trace/corpus symlink is forbidden".into());
    }
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > max as u64 { return Err("invalid or oversized input".into()); }
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() > max { return Err("input exceeds size budget".into()); }
    Ok(bytes)
}
pub fn trace(path: &Path, expected: Option<&str>) -> Result<Vec<Value>> {
    let raw = bounded_read(path, 10_000_000)?;
    let s = std::str::from_utf8(&raw).map_err(|e| e.to_string())?;
    let lines: Vec<&str> = s.lines().collect();
    if !(2..=100_002).contains(&lines.len()) { return Err("trace requires begin/end and <=100000 events".into()); }
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
    if start["op"] != "begin" || start["version"].as_u64() != Some(1) ||
       start["version"].is_boolean() || end["op"] != "end" {
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
fn parse_unique_object<'de, R: serde_json::de::Read<'de>>(de: &mut serde_json::Deserializer<R>) -> Result<Value> {
    use serde::de::{DeserializeSeed, MapAccess, Visitor};
    use std::fmt;
    struct Unique;
    impl<'de> Visitor<'de> for Unique {
        type Value = Value;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("a JSON object") }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Self::Value, A::Error> {
            let mut out = serde_json::Map::new();
            while let Some(k) = map.next_key::<String>()? {
                if out.contains_key(&k) { return Err(serde::de::Error::custom(format!("duplicate JSON property {k}"))); }
                let v = map.next_value::<Value>()?;
                out.insert(k, v);
            }
            Ok(Value::Object(out))
        }
    }
    impl<'de> DeserializeSeed<'de> for Unique {
        type Value = Value;
        fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> std::result::Result<Self::Value, D::Error> {
            d.deserialize_map(self)
        }
    }
    let v = Unique.deserialize(&mut *de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(v)
}
pub fn field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    let s = v.get(key).and_then(Value::as_str).ok_or_else(|| format!("invalid {key}"))?;
    if s.is_empty() || s.len() > 512 || s.chars().any(|c| c < ' ') { return Err(format!("invalid {key}")); }
    Ok(s)
}
pub fn table_command(v: &toml::Value, section: &str) -> Result<Vec<String>> {
    let a = v.get(section).and_then(|s| s.get("command")).and_then(|v| v.as_array())
        .ok_or_else(|| format!("[{section}].command required"))?;
    let cmd: Option<Vec<_>> = a.iter().map(|x| x.as_str().filter(|s| !s.is_empty()).map(str::to_owned)).collect();
    cmd.filter(|v| !v.is_empty()).ok_or_else(|| format!("[{section}].command requires nonempty argv array"))
}
