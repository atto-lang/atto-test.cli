//! Advisory source-only security and anti-pattern review.
//! A clean heuristic scan is NOT an absence-of-vulnerabilities proof.
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const MAX_FILE: usize = 1_000_000;
const MAX_TOTAL: usize = 16_000_000;
const MAX_FILES: usize = 2_000;
const MAX_FINDINGS: usize = 10_000;

#[derive(Clone, Copy, Debug)]
pub enum Severity { Low, Medium, High, Critical }
impl Severity {
    fn level(self) -> u8 {
        match self { Self::Low => 1, Self::Medium => 2, Self::High => 3, Self::Critical => 4 }
    }
    fn label(self) -> &'static str {
        match self { Self::Low => "low", Self::Medium => "medium", Self::High => "high", Self::Critical => "critical" }
    }
}
#[derive(Debug)]
struct Finding {
    file: String, line: usize, rule: &'static str, severity: Severity, message: &'static str,
}
#[derive(Default)]
struct Flags {
    root: PathBuf, security: bool, anti: bool, explicit: Vec<String>,
    fail_on: u8, json: bool,
}
fn flags(args: &[OsString]) -> Result<Flags, String> {
    let mut f = Flags { root: ".".into(), fail_on: 2, ..Flags::default() };
    let mut i = 0;
    while i < args.len() {
        let word = args[i].to_str().ok_or("non-UTF-8 argument")?;
        let (key, inline) = word.split_once('=').map_or((word,None), |(k,v)|(k,Some(v)));
        match key {
            "--security" if inline.is_none() => f.security = true,
            "--anti-patterns" if inline.is_none() => f.anti = true,
            "--audit" if inline.is_none() => { f.security=true; f.anti=true; }
            "--root" | "--audit-file" | "--fail-on" | "--audit-format" => {
                let value = if let Some(v)=inline { v.to_string() } else {
                    i += 1;
                    args.get(i).and_then(|s|s.to_str()).ok_or_else(||format!("{key} needs a value"))?.to_owned()
                };
                match key {
                    "--root" => f.root = value.into(),
                    "--audit-file" => f.explicit.push(value),
                    "--fail-on" => f.fail_on = match value.as_str() {
                        "none" => 5, "low" => 1, "medium" => 2, "high" => 3,
                        "critical" => 4, _ => return Err("invalid --fail-on".into()),
                    },
                    "--audit-format" => f.json = match value.as_str() {
                        "text" => false, "json" => true,
                        _ => return Err("audit-format must be text or json".into()),
                    },
                    _ => unreachable!(),
                }
            }
            _ => return Err(format!("unsupported source-audit option: {word}")),
        }
        i += 1;
    }
    if !f.security && !f.anti { return Err("audit-file/format requires --security, --anti-patterns or --audit".into()); }
    Ok(f)
}
fn safe_path(root: &Path, name: &str) -> Result<PathBuf,String> {
    let path=Path::new(name);
    if path.as_os_str().is_empty() || path.is_absolute()
        || path.components().any(|c| !matches!(c,Component::Normal(_) | Component::CurDir))
        || path.extension().is_none_or(|x|x!="ores") {
        return Err(format!("invalid project-relative Oreslang audit source {name}"));
    }
    let mut result=root.to_owned();
    for component in path.components() {
        result.push(component);
        if fs::symlink_metadata(&result).map_err(|e| e.to_string())?.file_type().is_symlink() {
            return Err(format!("source symlink refused: {name}"));
        }
    }
    if !result.is_file() { return Err(format!("audit input not regular: {name}")); }
    Ok(result)
}
fn discover(root: &Path, explicit: &[String]) -> Result<Vec<String>,String> {
    if !explicit.is_empty() {
        if explicit.len()>MAX_FILES { return Err("too many --audit-file arguments".into()); }
        let mut selected=BTreeSet::new();
        for p in explicit { safe_path(root,p)?; selected.insert(p.clone()); }
        return Ok(selected.into_iter().collect());
    }
    let skip=[".git",".oreslang-test","target","build","dist","vendor","node_modules","__pycache__",".venv"];
    let mut pending=vec![(root.to_path_buf(),0usize)];
    let mut result=Vec::new();
    let mut entries=0usize;
    while let Some((dir,depth))=pending.pop() {
        if depth>64 { return Err("audit directory nesting limit exceeded".into()); }
        for entry in fs::read_dir(&dir).map_err(|e|e.to_string())? {
            let entry=entry.map_err(|e|e.to_string())?;
            entries+=1;
            if entries>50_000 { return Err("audit directory entry budget exhausted".into()); }
            let name=entry.file_name();
            let name=name.to_str().ok_or("non-UTF-8 audit path")?;
            if skip.contains(&name) || name.starts_with('.') { continue; }
            let ty=entry.file_type().map_err(|e|e.to_string())?;
            if ty.is_symlink() { return Err(format!("symlink in audit tree: {}",entry.path().display())); }
            if ty.is_dir() { pending.push((entry.path(),depth+1)); }
            else if ty.is_file() && name.ends_with(".ores") {
                result.push(entry.path().strip_prefix(root).map_err(|e|e.to_string())?
                    .to_str().ok_or("non-UTF-8 source path")?.to_owned());
                if result.len()>MAX_FILES { return Err("audit file budget exceeded".into()); }
            }
        }
    }
    result.sort();
    if result.is_empty() { return Err("no Oreslang audit sources found (inconclusive)".into()); }
    Ok(result)
}
fn read_source(path: &Path) -> Result<String,String> {
    let m=fs::symlink_metadata(path).map_err(|e|e.to_string())?;
    if !m.is_file() || m.file_type().is_symlink() || m.len()>MAX_FILE as u64 {return Err("unsafe or oversized audit input".into());}
    let mut buf=Vec::new();
    fs::File::open(path).map_err(|e|e.to_string())?.take(MAX_FILE as u64+1)
        .read_to_end(&mut buf).map_err(|e|e.to_string())?;
    if buf.len()>MAX_FILE {return Err("audit file read budget exceeded".into());}
    String::from_utf8(buf).map_err(|_|"invalid UTF-8 audit source".into())
}
#[derive(Debug)]
struct Quoted {start:usize, value:String}
fn mask(source:&str)->Result<(String,Vec<Quoted>),String> {
    let b=source.as_bytes();
    let mut code=b.to_vec();
    let mut quoted=Vec::new();
    let mut i=0usize;
    while i<b.len() {
        let start=i;
        if b[i..].starts_with(b"//") {
            while i<b.len() && b[i]!=b'\n' {i+=1;}
        } else if b[i..].starts_with(b"/*") {
            i+=2;
            let mut depth=1usize;
            while i<b.len() && depth>0 {
                if b[i..].starts_with(b"/*") {depth+=1; if depth>256{return Err("nested comment budget".into());} i+=2;}
                else if b[i..].starts_with(b"*/") {depth-=1;i+=2;}
                else {i+=1;}
            }
            if depth!=0{return Err("unclosed block comment (inconclusive)".into());}
        } else if b[i]==b'"' || b[i]==b'\'' {
            let q=b[i];
            let triple=i+2<b.len() && b[i+1]==q && b[i+2]==q;
            let width=if triple{3}else{1};
            i+=width;
            let value_start=i;
            let mut close=None;
            while i<b.len() {
                if b[i]==b'\\' {i=(i+2).min(b.len());continue;}
                if !triple && b[i]==b'\n' {return Err("unclosed string (inconclusive)".into());}
                if b[i..].len()>=width && b[i..i+width].iter().all(|c|*c==q) {
                    close=Some(i);
                    i+=width;
                    break;
                }
                i+=1;
            }
            let end=close.ok_or("unclosed string (inconclusive)")?;
            quoted.push(Quoted {start, value:source[value_start..end].to_owned()});
        } else { i+=1; continue; }
        for c in &mut code[start..i] {if *c!=b'\n' && *c!=b'\r' {*c=b' ';}}
    }
    let text=String::from_utf8(code).map_err(|_|"invalid UTF-8 masking".to_string())?;
    Ok((text,quoted))
}
fn boundary(code:&str,pos:usize,len:usize)->bool {
    let bytes=code.as_bytes();
    let isword=|c:u8|c.is_ascii_alphanumeric() || c==b'_';
    (pos==0 || !isword(bytes[pos-1])) && (pos+len>=bytes.len() || !isword(bytes[pos+len]))
}
fn case_hits(haystack:&str,term:&str)->Vec<usize> {
    // ASCII-fold search keeps UTF-8 offsets stable.
    let folded=haystack.to_ascii_lowercase();
    folded.match_indices(term).map(|(i,_)|i).collect()
}
fn non_loopback_url(value:&str)->bool {
    for pos in case_hits(value,"http://") {
        let authority=value[pos+7..].split(|c:char| c=='/' || c.is_whitespace() || c=='"' || c=='\'')
            .next().unwrap_or("").to_ascii_lowercase();
        let host=if authority.starts_with('[') {authority.split(']').next().unwrap_or("").trim_start_matches('[').to_string()}
            else {authority.split(':').next().unwrap_or("").to_string()};
        if !["localhost","127.0.0.1","::1"].contains(&host.as_str()) && !host.starts_with("127.") {
            return true;
        }
    }
    false
}
fn line_at(newlines:&[usize], pos:usize)->usize {1+newlines.partition_point(|n| *n<pos)}
fn emit(out:&mut Vec<Finding>,file:&str,newlines:&[usize],pos:usize,
        rule:&'static str,severity:Severity,message:&'static str)->Result<(),String> {
    if out.len()>=MAX_FINDINGS{return Err("audit findings budget exceeded (inconclusive)".into());}
    out.push(Finding {file:file.to_owned(),line:line_at(newlines,pos),rule,severity,message});
    Ok(())
}
fn scan(out:&mut Vec<Finding>,file:&str,source:&str,security:bool,anti:bool)->Result<(),String> {
    let (code,quoted)=mask(source)?;
    let lower=code.to_ascii_lowercase();
    let newline:Vec<usize>=source.match_indices('\n').map(|(pos,_)|pos).collect();
    if security {
        for needle in ["password","passwd","secret","api_key","access_token","private_key","auth_token"] {
            for pos in case_hits(&code,needle) {
                if !boundary(&lower,pos,needle.len()) {continue;}
                let tail=&lower.as_bytes()[pos+needle.len()..];
                let Some(delim)=tail.iter().take(64).position(|ch| *ch==b'=' || *ch==b':') else {continue;};
                let mut at=pos+needle.len()+delim+1;
                while at<lower.len() && lower.as_bytes()[at].is_ascii_whitespace(){at+=1;}
                // Optional type annotation: typed assignments include "Type =".
                if lower.as_bytes().get(at).is_some_and(|x|x.is_ascii_alphabetic()) {
                    if let Some(n)=lower[at..].find('=') {if n<48 {
                        at+=n+1;
                        while at<lower.len() && lower.as_bytes()[at].is_ascii_whitespace(){at+=1;}
                    }}
                }
                if let Some(q)=quoted.iter().find(|q|q.start==at) {
                    let v=q.value.trim().to_ascii_lowercase();
                    if v.len()>=8 && !["example","dummy","test","fake","placeholder","changeme","replace","your_","xxxx","****","...."]
                        .iter().any(|x|v.starts_with(x)) {
                        emit(out,file,&newline,pos,"SEC001",Severity::High,"Possible hard-coded credential")?;
                    }
                }
            }
        }
        for needle in ["md5","sha1","sha_1","md5_hash","sha1_hash","sha_1_hash"] {
            for pos in case_hits(&code,needle) {
                if !boundary(&lower,pos,needle.len()) {continue;}
                if lower[pos+needle.len()..].trim_start().starts_with('(') {
                    emit(out,file,&newline,pos,"SEC002",Severity::Medium,"Weak hash primitive requires review")?;
                }
            }
        }
        for needle in ["shell.exec","shell.execute","shell.run","os.system"] {
            for pos in case_hits(&code,needle) {
                if !boundary(&lower,pos,needle.len()) {continue;}
                if lower[pos+needle.len()..].trim_start().starts_with('(') {
                    emit(out,file,&newline,pos,"SEC004",Severity::Medium,"Shell-based command execution requires review")?;
                }
            }
        }
        for literal in &quoted {
            if non_loopback_url(&literal.value) {
                emit(out,file,&newline,literal.start,"SEC003",Severity::Low,"Non-loopback plaintext HTTP URL")?;
            }
        }
    }
    if anti {
        for keyword in ["catch","recover"] {
            for pos in case_hits(&code,keyword) {
                if !boundary(&lower,pos,keyword.len()){continue;}
                let mut at=pos+keyword.len();
                let bytes=lower.as_bytes();
                while at<bytes.len() && bytes[at].is_ascii_whitespace(){at+=1;}
                if bytes.get(at)==Some(&b'(') {
                    let Some(close)=bytes[at+1..].iter().take(300).position(|b|*b==b')') else {continue;};
                    at+=close+2;
                    while at<bytes.len() && bytes[at].is_ascii_whitespace(){at+=1;}
                }
                if bytes.get(at)!=Some(&b'{'){continue;}
                at+=1;
                while at<bytes.len() && bytes[at].is_ascii_whitespace(){at+=1;}
                if bytes.get(at)==Some(&b'}') {
                    emit(out,file,&newline,pos,"ANTI001",Severity::Medium,"Empty catch/recover discards errors")?;
                }
            }
        }
        for pos in case_hits(&code,"while") {
            if !boundary(&lower,pos,5){continue;}
            let mut at=pos+5;
            let bytes=lower.as_bytes();
            while at<bytes.len() && bytes[at].is_ascii_whitespace(){at+=1;}
            if bytes.get(at)==Some(&b'(') {
                at+=1;
                while at<bytes.len() && bytes[at].is_ascii_whitespace(){at+=1;}
                if !lower[at..].starts_with("true"){continue;}
                at+=4;
                while at<bytes.len() && bytes[at].is_ascii_whitespace(){at+=1;}
                if bytes.get(at)!=Some(&b')'){continue;}
                at+=1;
            } else if lower[at..].starts_with("true") {at+=4;} else {continue;}
            while at<bytes.len() && bytes[at].is_ascii_whitespace(){at+=1;}
            if bytes.get(at)!=Some(&b'{'){continue;}
            let start=at+1;
            let Some(end)=bytes[start..].iter().take(2000).position(|b|*b==b'}') else {continue;};
            let inside=&lower[start..start+end];
            if !["await","select","rt.cooperate","rt cooperate"].iter().any(|needle|inside.contains(needle)) {
                emit(out,file,&newline,pos,"ANTI002",Severity::Low,"Busy loop has no visible suspension/cooperation")?;
            }
        }
    }
    Ok(())
}
fn escape_json(s:&str)->String {
    let mut v=String::from("\"");
    for c in s.chars() {
        match c {
            '"' => v.push_str("\\\""), '\\' => v.push_str("\\\\"),
            '\n' => v.push_str("\\n"), '\r' => v.push_str("\\r"), '\t' => v.push_str("\\t"),
            c if c.is_control() => v.push_str(&format!("\\u{:04x}",c as u32)),
            c => v.push(c),
        }
    }
    v.push('"');
    v
}
pub fn run(args:&[OsString])->i32 {
    let result=(|| -> Result<i32,String>{
        let opts=flags(args)?;
        let root=opts.root.canonicalize().map_err(|e|e.to_string())?;
        if !root.is_dir(){return Err("audit root is not a directory".into());}
        let paths=discover(&root,&opts.explicit)?;
        let mut findings=Vec::new();
        let mut total=0usize;
        for file in &paths {
            let path=safe_path(&root,file)?;
            let source=read_source(&path)?;
            total=total.checked_add(source.len()).ok_or("audit byte count overflow")?;
            if total>MAX_TOTAL{return Err("audit exceeds 16 MB source budget (inconclusive)".into());}
            scan(&mut findings,file,&source,opts.security,opts.anti)?;
        }
        findings.sort_by(|a,b| (&a.file,a.line,a.rule).cmp(&(&b.file,b.line,b.rule)));
        let failing=findings.iter().filter(|f|f.severity.level()>=opts.fail_on).count();
        if opts.json {
            print!("{{\"analysis\":\"advisory-source-heuristics-v1\",\"files_scanned\":{},\"bytes_scanned\":{},\"failing_findings\":{},\"findings\":[",paths.len(),total,failing);
            for (i,f) in findings.iter().enumerate() {
                if i>0{print!(",");}
                print!("{{\"file\":{},\"line\":{},\"rule\":{},\"severity\":{},\"message\":{}}}",
                    escape_json(&f.file),f.line,escape_json(f.rule),
                    escape_json(f.severity.label()),escape_json(f.message));
            }
            println!("],\"warning\":\"advisory heuristics, not a security proof\"}}");
        } else {
            for f in &findings {
                println!("{}:{}: {} {} {}",f.file,f.line,f.severity.label().to_ascii_uppercase(),f.rule,f.message);
            }
            println!("AUDIT: {} files, {} findings, {} at/above severity cutoff; advisory only, not a vulnerability-free certification",
                paths.len(),findings.len(),failing);
        }
        Ok(i32::from(failing>0))
    })();
    match result {Ok(n)=>n,Err(e)=>{eprintln!("oreslang audit: {e}");2}}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn finds_secrets_http_weak_hash_and_shell_without_leaking_literals() {
        let text="// secret = \"hiddenhidden\"\nlet api_key = \"supersecretvalue123\";\nlet url = \"http://example.org\";\nmd5(data); shell.exec(cmd);";
        let mut findings=Vec::new();
        scan(&mut findings,"sample.ores",text,true,false).unwrap();
        let kinds:Vec<_>=findings.iter().map(|x|x.rule).collect();
        assert!(kinds.contains(&"SEC001"));
        assert!(kinds.contains(&"SEC002"));
        assert!(kinds.contains(&"SEC003"));
        assert!(kinds.contains(&"SEC004"));
        assert!(!format!("{findings:?}").contains("supersecretvalue123"));
    }
    #[test] fn masks_comments_and_detects_empty_catch_and_busy_loop() {
        let src="// catch {} while true {}\nlet s=\"while true {}\";\ncatch(error) { /*ignored*/ }\nwhile true { poll(); }\nwhile (true) { await next(); }";
        let mut findings=Vec::new();
        scan(&mut findings,"a.ores",src,false,true).unwrap();
        assert_eq!(findings.iter().filter(|x|x.rule=="ANTI001").count(),1);
        assert_eq!(findings.iter().filter(|x|x.rule=="ANTI002").count(),1);
    }
    #[test] fn truncated_sources_cannot_report_clean() {
        assert!(mask("let s=\"no close").is_err());
        assert!(mask("/* unclosed").is_err());
        assert!(mask("/* nested /* stop */").is_err());
        assert!(flags(&["--audit-file".into(),"foo.ores".into()]).is_err());
    }
}
