//! Strict bounded subprocess execution. No shell; finite output/time budgets.
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct Outcome {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}
fn reader<R: Read>(mut input: R, overflow: Arc<AtomicBool>) -> std::thread::JoinHandle<Result<Vec<u8>, String>>
where R: Send + 'static {
    std::thread::spawn(move || {
        let mut collected = Vec::new();
        let mut chunk = [0u8; 65536];
        loop {
            let count = input.read(&mut chunk).map_err(|e| e.to_string())?;
            if count == 0 { break; }
            if count > 4_000_000usize.saturating_sub(collected.len()) {
                overflow.store(true, Ordering::SeqCst);
                return Err("test process emitted more than 4 MB stdout or stderr".into());
            }
            collected.extend_from_slice(&chunk[..count]);
        }
        Ok(collected)
    })
}
#[cfg(unix)]
fn kill_group(id: u32) {
    unsafe { libc::kill(-(id as libc::pid_t), libc::SIGKILL); }
}
#[cfg(not(unix))]
fn kill_group(_: u32) {}

pub fn run(args: &[String], root: &Path, timeout: f64, input: Option<&[u8]>,
           extra_env: &[(String, String)]) -> Result<Option<Outcome>, String> {
    if args.is_empty() || args[0].is_empty() { return Err("empty test command".into()); }
    let mut cmd = Command::new(&args[0]);
    cmd.args(&args[1..]).current_dir(root).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (key, value) in extra_env { cmd.env(key, value); }
    let mut file = tempfile::tempfile().map_err(|e| e.to_string())?;
    if let Some(data) = input { file.write_all(data).map_err(|e| e.to_string())?; }
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    cmd.stdin(Stdio::from(file));
    #[cfg(unix)]
    unsafe { use std::os::unix::process::CommandExt; cmd.pre_exec(|| {
        if libc::setsid() < 0 { return Err(std::io::Error::last_os_error()); }
        Ok(())
    }); }
    let mut child = cmd.spawn().map_err(|e| format!("cannot start {}: {e}", args[0]))?;
    let output_limit = Arc::new(AtomicBool::new(false));
    let out = reader(child.stdout.take().unwrap(), output_limit.clone());
    let err = reader(child.stderr.take().unwrap(), output_limit.clone());
    let start = Instant::now();
    let mut timed_out = false;
    let code = loop {
        if output_limit.load(Ordering::SeqCst) { break None; }
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => break Some(status.code().unwrap_or(1)),
            None if start.elapsed() >= Duration::from_secs_f64(timeout) => {
                timed_out = true; break None;
            },
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    if code.is_none() {
        kill_group(child.id());
        let _ = child.kill();
    }
    let _ = child.wait();
    // A child may exit while descendants retain its stdout/stderr pipes.
    // Never block indefinitely joining a reader in that situation.
    let cutoff = Instant::now() + Duration::from_secs(1);
    while !(out.is_finished() && err.is_finished()) && Instant::now() < cutoff {
        std::thread::sleep(Duration::from_millis(10));
    }
    if !(out.is_finished() && err.is_finished()) {
        kill_group(child.id());
        let _ = child.kill();
        let cutoff = Instant::now() + Duration::from_secs(1);
        while !(out.is_finished() && err.is_finished()) && Instant::now() < cutoff {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !(out.is_finished() && err.is_finished()) {
            // Dropping join handles detaches them instead of hanging the CLI.
            return Err("test process descendants outlived the runner".into());
        }
        return Err("test process descendants held output pipes open".into());
    }
    let stdout = out.join().map_err(|_| "stdout reader panicked")??;
    let stderr = err.join().map_err(|_| "stderr reader panicked")??;
    if output_limit.load(Ordering::SeqCst) { return Err("test output exceeds 4 MB".into()); }
    if timed_out { return Ok(None); }
    Ok(Some(Outcome {
        code: code.unwrap_or(1),
        stdout: String::from_utf8_lossy(&stdout).to_string(),
        stderr: String::from_utf8_lossy(&stderr).to_string(),
    }))
}
