use std::path::Path;

use crate::agent::ToolsCheckResult;
use crate::install::remote::RemoteInstallSession;
use crate::install::state::{validate_mountpoint, InstallScope, InstallState};

#[derive(Debug, Clone)]
pub struct PreflightReport {
    pub checks: Vec<PreflightCheck>,
}

#[derive(Debug, Clone)]
pub struct PreflightCheck {
    pub name: &'static str,
    pub status: PreflightStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightStatus {
    Pass,
    Fail,
}

impl PreflightReport {
    pub fn pass(&self) -> bool {
        self.checks
            .iter()
            .all(|check| check.status == PreflightStatus::Pass)
    }

    #[allow(dead_code)]
    pub fn failed_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == PreflightStatus::Fail)
            .count()
    }
}

/// `progress` receives transient bootstrap messages. The CLI prints them; the
/// TUI passes a no-op — raw `println!` while the terminal is in raw mode
/// shreds the frame.
pub fn run(repo: &Path, state: &InstallState, progress: &dyn Fn(&str)) -> PreflightReport {
    run_with_checkers(
        repo,
        state,
        |repo| crate::install::secrets::check_with_mode(repo, &state.secrets_mode),
        |repo, state| remote_tools_check(repo, state, progress),
        target_facts_check,
    )
}

fn run_with_checkers(
    repo: &Path,
    state: &InstallState,
    secret_checker: impl Fn(&Path) -> crate::install::secrets::SecretCheck,
    remote_tools_checker: impl Fn(&Path, &InstallState) -> PreflightCheck,
    facts_checker: impl Fn(&InstallState) -> PreflightCheck,
) -> PreflightReport {
    let mut checks = Vec::new();
    checks.push(capacity_check(state));
    checks.push(target_check(state));
    if state.scope == InstallScope::Remote {
        checks.push(ssh_check(state));
        checks.push(remote_tools_checker(repo, state));
    }
    checks.push(facts_checker(state));
    checks.push(generated_config_check(repo, state));
    checks.push(secrets_check(repo, secret_checker));
    PreflightReport { checks }
}

/// Introspect the target and assess it against the planned install: firmware
/// mode, disks in use, existing VG collisions, capacity. Critical findings fail
/// preflight; the rest surface as detail so the operator sees what's going on.
fn target_facts_check(state: &InstallState) -> PreflightCheck {
    let facts = match state.scope {
        InstallScope::Local => crate::facts::collect(),
        InstallScope::Remote => match crate::facts::collect_over_ssh(&state.remote) {
            Ok(facts) => facts,
            Err(err) => return fail("target facts", err),
        },
    };
    facts_check_from_report(&facts, state)
}

fn facts_check_from_report(
    facts: &crate::facts::TargetFacts,
    state: &InstallState,
) -> PreflightCheck {
    let plan = crate::facts::InstallAssessment {
        selected_disks: state.disks.iter().map(|disk| disk.path.clone()).collect(),
        planned_vgs: state
            .volume_groups
            .iter()
            .map(|group| group.name.clone())
            .collect(),
        planned_gib: state.used_gib(),
        overwrite: state.overwrite_existing_storage,
    };
    let insights = crate::facts::assess(facts, &plan);

    let critical: Vec<&crate::facts::Insight> = insights
        .iter()
        .filter(|insight| insight.severity == crate::facts::Severity::Critical)
        .collect();
    if !critical.is_empty() {
        return fail(
            "target facts",
            critical
                .iter()
                .map(|insight| insight.message.clone())
                .collect::<Vec<_>>()
                .join("; "),
        );
    }

    let mut detail = format!(
        "{} {} ({}, {})",
        facts.hostname.as_deref().unwrap_or("unknown host"),
        facts
            .nixos_version
            .as_deref()
            .or(facts.os_name.as_deref())
            .unwrap_or("unknown os"),
        if facts.efi { "UEFI" } else { "BIOS" },
        if facts.live_iso {
            "installer ISO"
        } else {
            "running system"
        },
    );
    let notes: Vec<String> = insights
        .into_iter()
        .filter(|insight| insight.severity != crate::facts::Severity::Info)
        .map(|insight| insight.message)
        .collect();
    if !notes.is_empty() {
        detail.push_str(&format!("; {}", notes.join("; ")));
    }
    pass("target facts", detail)
}

fn ssh_check(state: &InstallState) -> PreflightCheck {
    let check = crate::install::ssh::check_key_auth(&state.remote);
    if check.ok {
        pass("ssh", check.detail)
    } else {
        fail("ssh", check.detail)
    }
}

fn remote_tools_check(
    repo: &Path,
    state: &InstallState,
    progress: &dyn Fn(&str),
) -> PreflightCheck {
    let mut session = match RemoteInstallSession::connect(repo, &state.remote, |message| {
        progress(&format!("agent bootstrap: {message}"));
    }) {
        Ok(session) => session,
        Err(err) => return fail("remote tools", err),
    };

    let required = required_remote_tools();
    match session.tools_check(&required, true) {
        Ok(result) => {
            let check = remote_tools_check_from_result(result);
            let _ = session.close();
            check
        }
        Err(err) => fail("remote tools", err),
    }
}

fn required_remote_tools() -> Vec<String> {
    ["bash", "lsblk", "sudo"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn remote_tools_check_from_result(result: ToolsCheckResult) -> PreflightCheck {
    if !result.missing.is_empty() {
        return fail(
            "remote tools",
            format!("missing command: {}", result.missing.join(", ")),
        );
    }

    if result.sudo_ok == Some(false) {
        return fail(
            "remote tools",
            if result.sudo_stderr.is_empty() {
                "passwordless sudo failed".to_string()
            } else {
                format!("passwordless sudo failed: {}", result.sudo_stderr)
            },
        );
    }

    let tools = result
        .found
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let user = result
        .user
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown");
    pass(
        "remote tools",
        format!("{tools}, and sudo -n are available (remote user: {user})"),
    )
}

fn capacity_check(state: &InstallState) -> PreflightCheck {
    let total = state.total_disk_gib();
    let used = state.used_gib();
    if total == 0 {
        return fail("capacity", "no install disk selected");
    }
    if used > total {
        return fail(
            "capacity",
            format!("{used}G selected volumes exceed {total}G selected disk capacity"),
        );
    }
    pass(
        "capacity",
        format!("{used}G used / {total}G total / {}G free", total - used),
    )
}

fn target_check(state: &InstallState) -> PreflightCheck {
    if let Err(err) = validate_hostname(&state.hostname) {
        return fail("target", err);
    }
    if let Err(err) = validate_username(&state.install_user) {
        return fail("target", err);
    }
    match state.scope {
        InstallScope::Remote => {
            if state.remote.trim().is_empty() {
                return fail("target", "remote target is required");
            }
            if !state.remote.contains('@') {
                return fail(
                    "target",
                    format!("remote should look like user@host: {}", state.remote),
                );
            }
            pass(
                "target",
                format!("remote {} host {}", state.remote, state.hostname),
            )
        }
        InstallScope::Local => match validate_mountpoint(&state.mountpoint) {
            Ok(()) => pass(
                "target",
                format!(
                    "local mountpoint {} host {}",
                    state.mountpoint, state.hostname
                ),
            ),
            Err(err) => fail("target", err),
        },
    }
}

fn generated_config_check(repo: &Path, state: &InstallState) -> PreflightCheck {
    match crate::install::exec::prepare_generated(repo, state) {
        Ok(()) => pass("generated config", "disko.nix, host.nix, user.nix parse"),
        Err(err) => fail("generated config", err),
    }
}

fn secrets_check(
    repo: &Path,
    secret_checker: impl Fn(&Path) -> crate::install::secrets::SecretCheck,
) -> PreflightCheck {
    let check = secret_checker(repo);
    if check.ok {
        pass("secrets", check.detail)
    } else {
        fail("secrets", check.detail)
    }
}

fn pass(name: &'static str, detail: impl Into<String>) -> PreflightCheck {
    PreflightCheck {
        name,
        status: PreflightStatus::Pass,
        detail: detail.into(),
    }
}

fn fail(name: &'static str, detail: impl Into<String>) -> PreflightCheck {
    PreflightCheck {
        name,
        status: PreflightStatus::Fail,
        detail: detail.into(),
    }
}

fn validate_hostname(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 63 {
        return Err(format!("invalid hostname: {value}"));
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return Err(format!("invalid hostname: {value}"));
    }
    if bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    {
        Ok(())
    } else {
        Err(format!("invalid hostname: {value}"))
    }
}

fn validate_username(value: &str) -> Result<(), String> {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err("username is required".to_string());
    };
    if !(first.is_ascii_lowercase() || first == '_') {
        return Err(format!("invalid username: {value}"));
    }
    if chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-') {
        Ok(())
    } else {
        Err(format!("invalid username: {value}"))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        remote_tools_check_from_result, run_with_checkers, PreflightCheck, PreflightStatus,
    };
    use crate::agent::{ToolPath, ToolsCheckResult};
    use crate::install::secrets::SecretCheck;
    use crate::install::state::InstallState;

    #[test]
    fn preflight_passes_for_sample_state() {
        let dir = temp_dir("pass");
        fs::create_dir_all(&dir).unwrap();
        let mut state = InstallState::sample();
        state.scope = crate::install::state::InstallScope::Local;
        let report = run_with_checkers(&dir, &state, fake_secret_ok, fake_remote_tools_ok, fake_facts_ok);

        assert!(report.pass());
        assert_eq!(report.failed_count(), 0);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn preflight_fails_over_capacity() {
        let dir = temp_dir("capacity");
        fs::create_dir_all(&dir).unwrap();
        let mut state = InstallState::sample();
        state.scope = crate::install::state::InstallScope::Local;
        state.disks[0].size_gib = 100;
        let report = run_with_checkers(&dir, &state, fake_secret_ok, fake_remote_tools_ok, fake_facts_ok);

        assert!(!report.pass());
        assert!(report
            .checks
            .iter()
            .any(|check| check.name == "capacity" && check.status == PreflightStatus::Fail));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn preflight_fails_bad_remote() {
        let dir = temp_dir("target");
        fs::create_dir_all(&dir).unwrap();
        let mut state = InstallState::sample();
        state.remote = "10.10.10.7".to_string();
        let report = run_with_checkers(&dir, &state, fake_secret_ok, fake_remote_tools_ok, fake_facts_ok);

        assert!(!report.pass());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn local_preflight_does_not_add_ssh_check() {
        let dir = temp_dir("local");
        fs::create_dir_all(&dir).unwrap();
        let mut state = InstallState::sample();
        state.scope = crate::install::state::InstallScope::Local;
        let report = run_with_checkers(&dir, &state, fake_secret_ok, fake_remote_tools_ok, fake_facts_ok);

        assert!(!report.checks.iter().any(|check| check.name == "ssh"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn preflight_fails_when_secret_check_fails() {
        let dir = temp_dir("secrets");
        fs::create_dir_all(&dir).unwrap();
        let mut state = InstallState::sample();
        state.scope = crate::install::state::InstallScope::Local;
        let report = run_with_checkers(
            &dir,
            &state,
            |_| SecretCheck {
                ok: false,
                detail: "no yubikey".to_string(),
            },
            fake_remote_tools_ok,
            fake_facts_ok,
        );

        assert!(!report.pass());
        assert!(report
            .checks
            .iter()
            .any(|check| check.name == "secrets" && check.status == PreflightStatus::Fail));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn remote_tools_check_passes_with_required_tools() {
        let check = remote_tools_check_from_result(fake_tools_ok());

        assert_eq!(check.status, PreflightStatus::Pass);
        assert_eq!(check.name, "remote tools");
    }

    #[test]
    fn remote_tools_check_fails_when_tool_is_missing() {
        let mut result = fake_tools_ok();
        result.missing.push("sudo".to_string());
        result.found.retain(|tool| tool.name != "sudo");
        let check = remote_tools_check_from_result(result);

        assert_eq!(check.status, PreflightStatus::Fail);
        assert!(check.detail.contains("missing command: sudo"));
    }

    #[test]
    fn remote_tools_check_fails_when_passwordless_sudo_fails() {
        let mut result = fake_tools_ok();
        result.sudo_ok = Some(false);
        result.sudo_stderr = "a password is required".to_string();
        let check = remote_tools_check_from_result(result);

        assert_eq!(check.status, PreflightStatus::Fail);
        assert!(check.detail.contains("passwordless sudo failed"));
    }

    fn fake_secret_ok(_: &Path) -> SecretCheck {
        SecretCheck {
            ok: true,
            detail: "ok".to_string(),
        }
    }

    fn fake_remote_tools_ok(_: &Path, _: &InstallState) -> PreflightCheck {
        remote_tools_check_from_result(fake_tools_ok())
    }

    fn fake_facts_ok(_: &InstallState) -> PreflightCheck {
        PreflightCheck {
            name: "target facts",
            status: PreflightStatus::Pass,
            detail: "nixos (UEFI, installer ISO)".to_string(),
        }
    }

    #[test]
    fn facts_check_fails_on_critical_insights_and_passes_otherwise() {
        let mut state = InstallState::sample();
        state.scope = crate::install::state::InstallScope::Remote;

        // A clean live-ISO target with the selected disk present and empty.
        let facts = crate::facts::TargetFacts {
            hostname: Some("nixos".to_string()),
            efi: true,
            live_iso: true,
            mem_mib: Some(8192),
            disks: vec![crate::facts::DiskFacts {
                path: "/dev/nvme0n1".to_string(),
                size_bytes: 500 * 1024 * 1024 * 1024,
                ..crate::facts::DiskFacts::default()
            }],
            ..crate::facts::TargetFacts::default()
        };
        let check = super::facts_check_from_report(&facts, &state);
        assert_eq!(check.status, PreflightStatus::Pass);
        assert!(check.detail.contains("UEFI"));

        // BIOS firmware must fail preflight.
        let bios = crate::facts::TargetFacts { efi: false, ..facts.clone() };
        let check = super::facts_check_from_report(&bios, &state);
        assert_eq!(check.status, PreflightStatus::Fail);
        assert!(check.detail.contains("BIOS mode"));

        // Existing VG named like the plan without overwrite must fail.
        let vg_collision = crate::facts::TargetFacts {
            volume_groups: vec![crate::facts::VgFacts {
                name: "pool".to_string(),
                ..crate::facts::VgFacts::default()
            }],
            ..facts
        };
        state.overwrite_existing_storage = false;
        let check = super::facts_check_from_report(&vg_collision, &state);
        assert_eq!(check.status, PreflightStatus::Fail);
        assert!(check.detail.contains("already exists"));
    }

    fn fake_tools_ok() -> ToolsCheckResult {
        ToolsCheckResult {
            user: Some("nixos".to_string()),
            found: ["bash", "lsblk", "sudo"]
                .into_iter()
                .map(|name| ToolPath {
                    name: name.to_string(),
                    path: format!("/run/current-system/sw/bin/{name}"),
                })
                .collect(),
            missing: Vec::new(),
            sudo_ok: Some(true),
            sudo_stderr: String::new(),
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nox-preflight-{name}-{}-{now}",
            std::process::id()
        ))
    }
}
