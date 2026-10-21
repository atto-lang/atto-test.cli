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

#[cfg(target_os="linux")]
fn poll_unreaped_exit(child: &std::process::Child) -> Result<bool, String> {
    // Unlike Child::try_wait(), WNOWAIT observes exit without reaping.
    // Keep the child's PID reserved until its whole process group is cleaned.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if rc != 0 {
        return Err(format!("waitid failed: {}", std::io::Error::last_os_error()));
    }
    Ok(unsafe { info.si_pid() } != 0)
}

pub fn run(args: &[String], root: &Path, timeout: f64, input: Option<&[u8]>,
           extra_env: &[(String, String)]) -> Result<Option<Outcome>, String> {
    if args.is_empty() || args[0].is_empty() { return Err("empty test command".into()); }
    let mut cmd = Command::new(&args[0]);
    cmd.args(&args[1..]).current_dir(root).stdout(Stdio::piped()).stderr(Stdio::piped());
    // Guest tests must not inherit GitHub/CI credentials, SDK tokens, private
    // installation secrets or unrelated host settings. Retain only OS basics.
    cmd.env_clear();
    for key in [
        "PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "LC_CTYPE",
        "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "PATHEXT",
    ] {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
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
        #[cfg(target_os="linux")]
        let observed = if poll_unreaped_exit(&child)? { Some(0) } else { None };
        #[cfg(not(target_os="linux"))]
        let observed = child.try_wait().map_err(|e| e.to_string())?
            .map(|status| status.code().unwrap_or(1));
        if let Some(status) = observed { break Some(status); }
        if start.elapsed() >= Duration::from_secs_f64(timeout) {
            timed_out = true;
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // Linux: the child is deliberately still unreaped, so the process-group
    // identifier cannot have been reused by an unrelated process.
    #[cfg(target_os="linux")]
    let had_inherited_pipes = if code.is_some() {
        let cutoff = Instant::now() + Duration::from_millis(200);
        while !(out.is_finished() && err.is_finished()) && Instant::now() < cutoff {
            std::thread::sleep(Duration::from_millis(10));
        }
        !(out.is_finished() && err.is_finished())
    } else { false };
    #[cfg(target_os="linux")]
    kill_group(child.id());
    #[cfg(not(target_os="linux"))]
    if code.is_none() && child.try_wait().map_err(|e| e.to_string())?.is_none() {
        kill_group(child.id());
    }
    if code.is_none() { let _ = child.kill(); }
    let exit_status = child.wait().map_err(|e| e.to_string())?;
    // A child may exit while descendants retain its stdout/stderr pipes.
    // Never block indefinitely joining a reader in that situation.
    let cutoff = Instant::now() + Duration::from_secs(1);
    while !(out.is_finished() && err.is_finished()) && Instant::now() < cutoff {
        std::thread::sleep(Duration::from_millis(10));
    }
    if !(out.is_finished() && err.is_finished()) {
        // The direct child has already been reaped. Do NOT signal its
        // numeric PID/PGID: it may now identify an unrelated process.
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
    #[cfg(target_os="linux")]
    if had_inherited_pipes {
        return Err("test process descendants kept stdout or stderr open".into());
    }
    Ok(Some(Outcome {
        code: exit_status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&stdout).to_string(),
        stderr: String::from_utf8_lossy(&stderr).to_string(),
    }))
}

#[cfg(all(test, unix))]
mod runner_security_tests {
    use super::*;

    #[test]
    fn guest_environment_only_includes_os_basics_and_explicit_trace_context() {
        let root = std::env::temp_dir();
        let args = vec!["/usr/bin/env".to_string()];
        let extras = vec![("ORESLANG_RACE_RUN_ID".to_string(), "test-nonce".to_string())];
        let output = run(&args, &root, 5.0, None, &extras)
            .expect("guest invocation")
            .expect("guest completed");
        assert_eq!(output.code, 0);
        let allowed = [
            "PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "LC_CTYPE",
            "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "PATHEXT", "ORESLANG_RACE_RUN_ID",
        ];
        let mut saw_explicit = false;
        for entry in output.stdout.lines() {
            let (name, value) = entry.split_once('=').expect("environment line");
            assert!(allowed.contains(&name), "unexpected host environment variable: {name}");
            if name == "ORESLANG_RACE_RUN_ID" {
                assert_eq!(value, "test-nonce");
                saw_explicit = true;
            }
        }
        assert!(saw_explicit, "explicit trace context must reach guest");
    }
}
