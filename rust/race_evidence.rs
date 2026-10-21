//! Pre-admission validation for a FUTURE trusted runtime receipt.
//!
//! A valid *shape* is NOT proof of trust or race freedom. This module does not
//! parse guest output, authenticate a runtime, or enable `--race` PASS.
//! The eventual host-only pipe implementation must validate provenance and
//! sequence every event before this function is useful for admission.

use std::collections::BTreeSet;

pub const VERSION: u32 = 1;
pub const REQUIRED_SURFACES: [&str; 9] = [
    "actor_state",
    "objects",
    "collections",
    "text",
    "task_frames",
    "shared_regions",
    "allocation_lifecycle",
    "scheduler_hb",
    "core_native",
];
const MAX_SCOPES: usize = 65_536;
const MAX_EVENTS: u64 = 10_000_000;
const MAX_RUN_ID: usize = 128;

#[derive(Clone, Copy, Debug)]
pub struct Binding<'a> {
    /// From the host runner, not a guest-reported run identifier.
    pub run_id: &'a str,
    pub backend: &'a str,
    pub source_tree: &'a str,
    pub runtime_build: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub struct Summary<'a> {
    pub version: u32,
    pub run_id: &'a str,
    pub backend: &'a str,
    pub source_tree: &'a str,
    pub runtime_build: &'a str,
    pub emitted: u64,
    pub stored: u64,
    pub final_sequence: u64,
    pub dropped: u64,
    pub complete: bool,
    pub covered_surfaces: &'a [&'a str],
    /// Host-scoped IDs; not globally unique without a verified run identity.
    pub scope_ids: &'a [u64],
}

fn is_hex_digest(value: &str) -> bool {
    return (value.len() == 40 || value.len() == 64)
        && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
        && value.as_bytes().iter().any(|byte| *byte != b'0');
}

fn is_bounded_run_id(value: &str) -> bool {
    return !value.is_empty()
        && value.len() <= MAX_RUN_ID
        && value.as_bytes().iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b':' | b'.')
        });
}

/// Checks bounded receipt invariants only. A caller must *independently*
/// authenticate that the receiver is a trusted host-only runtime channel,
/// verify source/build identities and account for every instrumented path.
/// Never map this function's Ok(()) directly to CLI exit code 0.
pub fn validate_shape(receipt: &Summary<'_>, host: &Binding<'_>) -> Result<(), &'static str> {
    if receipt.version != VERSION {
        return Err("unsupported trusted evidence protocol version");
    }
    if !is_bounded_run_id(host.run_id) || receipt.run_id != host.run_id {
        return Err("missing or mismatched host run identity");
    }
    if !matches!(receipt.backend, "llvm" | "graalvm" | "wasm" | "js" | "dotnet")
        || receipt.backend != host.backend
    {
        return Err("backend identity mismatch");
    }
    if !is_hex_digest(host.source_tree) || receipt.source_tree != host.source_tree {
        return Err("source revision mismatch");
    }
    if !is_hex_digest(host.runtime_build) || receipt.runtime_build != host.runtime_build {
        return Err("runtime build mismatch");
    }
    if !receipt.complete || receipt.dropped != 0 {
        return Err("incomplete runtime event coverage");
    }
    if receipt.emitted == 0 || receipt.emitted > MAX_EVENTS
        || receipt.emitted != receipt.stored
        || receipt.emitted != receipt.final_sequence
    {
        return Err("missing, duplicated or inconsistent events");
    }
    if receipt.scope_ids.is_empty() || receipt.scope_ids.len() > MAX_SCOPES {
        return Err("missing or over-budget memory scopes");
    }
    let mut seen_scopes = BTreeSet::new();
    for scope in receipt.scope_ids {
        if *scope == 0 || !seen_scopes.insert(*scope) {
            return Err("zero or duplicate host-local memory scope identity");
        }
    }
    if receipt.covered_surfaces.len() != REQUIRED_SURFACES.len() {
        return Err("unsupported or incomplete instrumentation surface count");
    }
    let mut seen_coverage = BTreeSet::new();
    for surface in receipt.covered_surfaces {
        if !REQUIRED_SURFACES.contains(surface) || !seen_coverage.insert(*surface) {
            return Err("unknown or duplicate covered memory/synchronization surface");
        }
    }
    if seen_coverage.len() != REQUIRED_SURFACES.len() {
        return Err("missing instrumented access or happens-before surface");
    }
    return Ok(());
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BUILD: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    fn binding() -> Binding<'static> {
        return Binding {
            run_id: "host-generated-run-7",
            backend: "llvm",
            source_tree: SOURCE,
            runtime_build: BUILD,
        };
    }
    fn receipt() -> Summary<'static> {
        return Summary {
            version: VERSION,
            run_id: "host-generated-run-7",
            backend: "llvm",
            source_tree: SOURCE,
            runtime_build: BUILD,
            emitted: 42,
            stored: 42,
            final_sequence: 42,
            dropped: 0,
            complete: true,
            covered_surfaces: &REQUIRED_SURFACES,
            scope_ids: &[7, 8],
        };
    }
    #[test]
    fn complete_shape_does_not_by_itself_attest_trust() {
        assert_eq!(validate_shape(&receipt(), &binding()), Ok(()));
    }
    #[test]
    fn overflow_and_incomplete_coverage_are_rejected() {
        let mut r = receipt();
        r.dropped = 1;
        assert!(validate_shape(&r, &binding()).is_err());
        r.dropped = 0;
        r.complete = false;
        assert!(validate_shape(&r, &binding()).is_err());
        r.complete = true;
        r.covered_surfaces = &REQUIRED_SURFACES[..8];
        assert!(validate_shape(&r, &binding()).is_err());
    }
    #[test]
    fn missing_invalid_and_duplicate_events_fail() {
        let mut r = receipt();
        r.emitted = 0;
        assert!(validate_shape(&r, &binding()).is_err());
        r.emitted = 42;
        r.stored = 41;
        assert!(validate_shape(&r, &binding()).is_err());
        r.stored = 42;
        r.final_sequence = 43;
        assert!(validate_shape(&r, &binding()).is_err());
    }
    #[test]
    fn mismatched_provenance_and_scope_reuse_fail() {
        let mut r = receipt();
        r.run_id = "guest-chosen-run";
        assert!(validate_shape(&r, &binding()).is_err());
        r.run_id = binding().run_id;
        r.backend = "unknown";
        assert!(validate_shape(&r, &binding()).is_err());
        r.backend = "llvm";
        r.source_tree = "invalid";
        assert!(validate_shape(&r, &binding()).is_err());
        r.source_tree = SOURCE;
        r.scope_ids = &[7, 7];
        assert!(validate_shape(&r, &binding()).is_err());
        r.scope_ids = &[0];
        assert!(validate_shape(&r, &binding()).is_err());
    }
    #[test]
    fn input_budgets_and_unsafe_host_identity_fail() {
        let mut r = receipt();
        r.emitted = MAX_EVENTS + 1;
        r.stored = r.emitted;
        r.final_sequence = r.emitted;
        assert!(validate_shape(&r, &binding()).is_err());
        let mut unsafe_host = binding();
        unsafe_host.run_id = "run-id\nforged";
        r = receipt();
        r.run_id = unsafe_host.run_id;
        assert!(validate_shape(&r, &unsafe_host).is_err());
        unsafe_host.run_id = binding().run_id;
        unsafe_host.runtime_build = "0000000000000000000000000000000000000000";
        assert!(validate_shape(&r, &unsafe_host).is_err());
    }
    #[test]
    fn unsupported_version_and_duplicate_surface_fail() {
        let mut r = receipt();
        r.version = VERSION + 1;
        assert!(validate_shape(&r, &binding()).is_err());
        r.version = VERSION;
        r.covered_surfaces = &["actor_state", "actor_state"];
        assert!(validate_shape(&r, &binding()).is_err());
    }
}
