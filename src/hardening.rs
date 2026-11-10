//! Process hardening and the instance passport.
//!
//! "RAM-only" is a promise about what never reaches a disk. This module turns the parts of
//! that promise the process itself controls into enforced settings, and reports what it could
//! and could not enforce so clients can see it in the Ed25519-signed `/info` response:
//!
//! - core dumps are disabled (`RLIMIT_CORE = 0`) and the process is marked non-dumpable
//!   (`PR_SET_DUMPABLE = 0`), which also blocks `ptrace` and `/proc/<pid>/mem` from
//!   unprivileged peers;
//! - all current and future pages are locked in RAM with `mlockall(MCL_ONFAULT)` when the
//!   memlock limit allows it, so note ciphertext cannot be paged to swap;
//! - host swap is detected and reported, because locking is only needed when swap exists;
//! - the running binary is hashed so operators and auditors can match it to a build.
//!
//! The passport is self-reported: the signature proves it came from the process that holds the
//! pinned key, not that the operator runs an unmodified binary. None of this reaches into the
//! kernel, the hypervisor or the hardware: a VM snapshot or a root user still sees process
//! memory. See docs/ram-only.md for the exact guarantees.

use std::{
    fs,
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use sha2::{Digest, Sha256};

/// What the process enforced for itself at startup. `None` means "not applicable here".
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct RamOnlyReport {
    /// `false` once `PR_SET_DUMPABLE = 0` succeeded (Linux).
    pub dumpable: Option<bool>,
    /// `true` once `RLIMIT_CORE` is zero (Unix).
    pub core_dump_limit_zero: Option<bool>,
    /// `true` once `mlockall` pinned current and future pages (Linux).
    pub memory_locked: Option<bool>,
    /// Why memory could not be locked, when it could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_lock_detail: Option<&'static str>,
    /// Whether the host exposes any swap device to this process (Linux, from `/proc/swaps`).
    pub swap_present: Option<bool>,
    /// Stored note ciphertext and read-token hashes are overwritten with zeros when dropped.
    pub zeroize_on_drop: bool,
}

/// Facts about the running instance, published (signed) through `/info`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct InstancePassport {
    /// Crate version the binary was built from.
    pub version: &'static str,
    /// Unix time the process collected its passport, i.e. when it started.
    pub started_at: u64,
    /// SHA-256 of the executable file, lowercase hex; `None` if it could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_sha256: Option<String>,
    pub ram_only: RamOnlyReport,
}

impl InstancePassport {
    /// Passport for a process that did not run `harden_process` (tests, embedding).
    pub fn unknown() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION"),
            started_at: now_ts(),
            binary_sha256: None,
            ram_only: RamOnlyReport {
                zeroize_on_drop: true,
                ..RamOnlyReport::default()
            },
        }
    }

    /// Collects the passport after hardening; hashes the running executable.
    pub fn collect(ram_only: RamOnlyReport) -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION"),
            started_at: now_ts(),
            binary_sha256: hash_current_exe(),
            ram_only,
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        now_ts().saturating_sub(self.started_at)
    }
}

/// Applies every hardening step this platform supports and reports the outcome.
/// Safe to call more than once; later calls only re-read the state.
pub fn harden_process() -> RamOnlyReport {
    let mut report = RamOnlyReport {
        zeroize_on_drop: true,
        ..RamOnlyReport::default()
    };
    #[cfg(unix)]
    {
        report.core_dump_limit_zero = Some(disable_core_dumps());
    }
    #[cfg(target_os = "linux")]
    {
        report.dumpable = Some(!set_non_dumpable());
        let (locked, detail) = lock_memory();
        report.memory_locked = Some(locked);
        report.memory_lock_detail = detail;
        report.swap_present = swap_present();
    }
    report
}

/// SHA-256 of the executable backing this process.
pub fn hash_current_exe() -> Option<String> {
    let path = std::env::current_exe().ok()?;
    let mut file = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Some(
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(unix)]
fn disable_core_dumps() -> bool {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit only reads the struct we pass; lowering a limit needs no privilege.
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0 }
}

#[cfg(target_os = "linux")]
fn set_non_dumpable() -> bool {
    let zero: libc::c_ulong = 0;
    // SAFETY: PR_SET_DUMPABLE takes integer arguments only and touches no memory.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, zero, zero, zero, zero) == 0 }
}

#[cfg(target_os = "linux")]
fn lock_memory() -> (bool, Option<&'static str>) {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into the struct we pass.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } != 0 {
        return (false, Some("RLIMIT_MEMLOCK could not be read"));
    }
    // With MCL_FUTURE and a finite limit, a later allocation past the limit would fail and
    // abort the server instead of merely staying unlocked, so only lock when unlimited.
    if limit.rlim_cur != libc::RLIM_INFINITY {
        return (
            false,
            Some("RLIMIT_MEMLOCK is finite; start with an unlimited memlock limit to pin memory"),
        );
    }
    // SAFETY: mlockall takes flags only. MCL_ONFAULT locks pages as they are touched instead
    // of pre-faulting every mapping (thread stacks included).
    let flags = libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT;
    if unsafe { libc::mlockall(flags) } == 0 {
        (true, None)
    } else {
        (
            false,
            Some("mlockall failed; the process lacks CAP_IPC_LOCK or the kernel refused"),
        )
    }
}

#[cfg(target_os = "linux")]
fn swap_present() -> Option<bool> {
    fs::read_to_string("/proc/swaps")
        .ok()
        .map(|table| table.lines().skip(1).any(|line| !line.trim().is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardening_reports_what_it_enforced() {
        let report = harden_process();
        assert!(report.zeroize_on_drop);
        #[cfg(unix)]
        assert_eq!(report.core_dump_limit_zero, Some(true));
        #[cfg(target_os = "linux")]
        {
            assert_eq!(report.dumpable, Some(false));
            assert!(report.memory_locked.is_some());
            if report.memory_locked == Some(false) {
                assert!(report.memory_lock_detail.is_some());
            }
            assert!(report.swap_present.is_some());
        }
        // Hardening is idempotent.
        assert_eq!(harden_process(), report);
    }

    #[test]
    fn passport_hashes_the_running_binary() {
        let passport = InstancePassport::collect(RamOnlyReport::default());
        let digest = passport
            .binary_sha256
            .clone()
            .expect("test binary is readable");
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(passport.version, env!("CARGO_PKG_VERSION"));
        assert!(passport.started_at > 1_700_000_000);
        assert!(passport.uptime_secs() < 60);
        assert_eq!(InstancePassport::unknown().binary_sha256, None);
    }
}
