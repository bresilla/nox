use crate::install::state::InstallState;
use crate::Result;

#[derive(Debug, Clone, Copy, Default)]
pub struct RemoteInstallSecrets<'a> {
    pub shared_system_key: Option<&'a [u8]>,
    pub github_token: Option<&'a [u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteInstallStep {
    pub name: &'static str,
    pub program: String,
    pub args: Vec<String>,
    pub stdin: Vec<u8>,
    pub destructive: bool,
}

impl RemoteInstallStep {
    fn new(
        name: &'static str,
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
        destructive: bool,
    ) -> Self {
        Self {
            name,
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            stdin: Vec::new(),
            destructive,
        }
    }

    fn new_with_stdin(
        name: &'static str,
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
        stdin: Vec<u8>,
        destructive: bool,
    ) -> Self {
        Self {
            name,
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            stdin,
            destructive,
        }
    }

    pub fn command_line(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .map(shell_display)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Parse this step into its typed operation, validating the arguments.
    /// Both the remote executor and the local in-process backend dispatch on
    /// this, so validation happens once and identically for either side.
    pub fn op(&self) -> Result<StepOp<'_>> {
        if self.program == "nixos-install" {
            return Ok(StepOp::NixosInstall { args: &self.args });
        }
        if self.program != "nox-agent" {
            return Ok(StepOp::Program {
                program: &self.program,
                args: &self.args,
            });
        }

        let subcommand = self
            .args
            .first()
            .map(String::as_str)
            .ok_or_else(|| format!("step '{}' has no agent subcommand", self.name))?;
        match subcommand {
            "network-route-cleanup" => Ok(StepOp::RouteCleanup),
            "storage-overwrite" => {
                let vg_name = self.arg(1, "VG name")?;
                validate_vg_name(vg_name)?;
                Ok(StepOp::StorageOverwrite { vg_name })
            }
            "disk-prepare" => {
                let disk = self.arg(1, "disk path")?;
                Ok(StepOp::DiskPrepare { disk })
            }
            "disko-apply" => {
                let disko_file = self.arg(1, "Disko file path")?;
                validate_absolute_path(disko_file, "disko file")?;
                Ok(StepOp::DiskoApply { disko_file })
            }
            "secret-file-write" => {
                let path = self.arg(1, "path")?;
                let mode = self.arg(2, "mode")?;
                validate_secret_write(path, mode, &self.stdin)?;
                let mode = u32::from_str_radix(mode, 8)
                    .map_err(|err| format!("invalid secret write mode {mode}: {err}"))?;
                Ok(StepOp::SecretWrite { path, mode })
            }
            "config-copy" => {
                let source_dir = self.arg(1, "source dir")?;
                let role = self.arg(2, "role")?;
                let install_user = self.arg(3, "install user")?;
                validate_config_copy(source_dir, role, install_user)?;
                Ok(StepOp::ConfigCopy {
                    source_dir,
                    role,
                    install_user,
                })
            }
            "system-bin-ensure" => Ok(StepOp::BinEnsure),
            "dotfiles-run" => {
                let dotfiles_repo = self.arg(1, "repo")?;
                let install_user = self.arg(2, "install user")?;
                validate_dotfiles_run(dotfiles_repo, install_user)?;
                Ok(StepOp::DotfilesRun {
                    dotfiles_repo,
                    install_user,
                })
            }
            "reboot-target" => Ok(StepOp::Reboot),
            other => Err(format!("unknown agent step operation: {other}")),
        }
    }

    fn arg(&self, index: usize, label: &str) -> Result<&str> {
        self.args
            .get(index)
            .map(String::as_str)
            .ok_or_else(|| format!("step '{}' is missing {label}", self.name))
    }
}

/// The typed operations an install plan can contain. Backends (remote agent,
/// local in-process) map each op to their own implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepOp<'a> {
    /// Plain program executed on the target (id, test, findmnt…).
    Program {
        program: &'a str,
        args: &'a [String],
    },
    /// nixos-install, wrapped by the backend with sudo/TMPDIR handling.
    NixosInstall { args: &'a [String] },
    RouteCleanup,
    StorageOverwrite { vg_name: &'a str },
    DiskPrepare { disk: &'a str },
    DiskoApply { disko_file: &'a str },
    SecretWrite { path: &'a str, mode: u32 },
    ConfigCopy {
        source_dir: &'a str,
        role: &'a str,
        install_user: &'a str,
    },
    BinEnsure,
    DotfilesRun {
        dotfiles_repo: &'a str,
        install_user: &'a str,
    },
    Reboot,
}

fn validate_vg_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err("VG name is empty".to_string());
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
    {
        return Err(format!("invalid VG name: {name}"));
    }
    Ok(())
}

fn validate_absolute_path(path: &str, label: &str) -> Result<()> {
    if path.is_empty() || !path.starts_with('/') || path.contains('\0') {
        return Err(format!("{label} must be an absolute path: {path}"));
    }
    Ok(())
}

fn validate_secret_write(path: &str, mode: &str, stdin: &[u8]) -> Result<()> {
    // Allowed: the sops key, and per-user password hash files under the
    // dedicated nixos-install dir.
    let allowed = path == "/mnt/var/lib/sops-nix/key.txt"
        || path == "/mnt/var/lib/nixos-install/user-password.hash"
        || (path.starts_with("/mnt/var/lib/nixos-install/passwd-")
            && path.ends_with(".hash")
            && !path.contains("..")
            && !path.contains('\0'));
    if !allowed {
        return Err(format!("unsupported secret write path: {path}"));
    }
    if mode != "0600" {
        return Err(format!("unsupported secret write mode: {mode}"));
    }
    if stdin.is_empty() {
        return Err("secret-file-write stdin is empty".to_string());
    }
    Ok(())
}

fn validate_config_copy(source_dir: &str, role: &str, install_user: &str) -> Result<()> {
    if source_dir.is_empty() || !source_dir.starts_with('/') {
        return Err(format!(
            "config-copy source dir must be absolute: {source_dir}"
        ));
    }
    if source_dir == "/" {
        return Err("config-copy source dir cannot be filesystem root".to_string());
    }
    if !matches!(role, "laptop" | "server") {
        return Err(format!("invalid config-copy role: {role}"));
    }
    validate_install_user(install_user)
}

fn validate_dotfiles_run(dotfiles_repo: &str, install_user: &str) -> Result<()> {
    if dotfiles_repo.trim().is_empty() {
        return Err("dotfiles repo is empty".to_string());
    }
    if dotfiles_repo.contains('\0')
        || dotfiles_repo.contains(char::is_whitespace)
        || dotfiles_repo.starts_with('-')
    {
        return Err(format!("invalid dotfiles repo: {dotfiles_repo}"));
    }
    validate_install_user(install_user)
}

fn validate_install_user(value: &str) -> Result<()> {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err("install user is empty".to_string());
    };
    if !(first.is_ascii_lowercase() || first == '_') {
        return Err(format!("invalid install user: {value}"));
    }
    if chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-') {
        Ok(())
    } else {
        Err(format!("invalid install user: {value}"))
    }
}

struct RemotePaths {
    source_dir: String,
    role: &'static str,
    flake_file: String,
    disko_file: String,
    flake_ref: String,
}

fn remote_paths(state: &InstallState, source_dir: &str) -> Result<RemotePaths> {
    if source_dir.is_empty() || !source_dir.starts_with('/') {
        return Err(format!(
            "remote source directory must be absolute: {source_dir}"
        ));
    }

    let role = state.role.title();
    let flake_host = format!("install-{role}-generated");
    let source_dir = source_dir.trim_end_matches('/');
    if source_dir.is_empty() {
        return Err("remote source directory cannot be filesystem root".to_string());
    }

    Ok(RemotePaths {
        source_dir: source_dir.to_string(),
        role,
        flake_file: format!("{source_dir}/host/flake.nix"),
        disko_file: format!("{source_dir}/host/generated/disko.nix"),
        flake_ref: format!("{source_dir}/host#{flake_host}"),
    })
}

pub fn plan_remote_install_steps(
    state: &InstallState,
    source_dir: &str,
) -> Result<Vec<RemoteInstallStep>> {
    plan_remote_install_steps_with_secrets(state, source_dir, RemoteInstallSecrets::default())
}

/// Plan the storage-only prefix of a remote install: verify the target, clean up
/// competing routes, verify the transferred flake and disko files, remove any
/// existing volume groups in overwrite mode, wipe the selected disks, apply the
/// Disko layout, and confirm the resulting mount. This is the reusable core that
/// both the full installer and the standalone `storage apply` path build on.
pub fn plan_remote_storage_steps(
    state: &InstallState,
    source_dir: &str,
) -> Result<Vec<RemoteInstallStep>> {
    let paths = remote_paths(state, source_dir)?;

    let mut steps = vec![RemoteInstallStep::new(
        "verify remote user",
        "id",
        ["-un"],
        false,
    )];

    if state.network_route_cleanup {
        steps.push(RemoteInstallStep::new(
            "clean up competing default routes",
            "nox-agent",
            ["network-route-cleanup"],
            false,
        ));
    }

    steps.extend([
        RemoteInstallStep::new(
            "verify flake source",
            "test",
            ["-f", paths.flake_file.as_str()],
            false,
        ),
        RemoteInstallStep::new(
            "verify generated disko",
            "test",
            ["-f", paths.disko_file.as_str()],
            false,
        ),
    ]);

    if state.overwrite_existing_storage {
        let vg_names = crate::install::disko::lvm_vg_names(state)?;
        for vg_name in vg_names {
            steps.push(RemoteInstallStep::new(
                "remove existing volume group",
                "nox-agent",
                ["storage-overwrite", vg_name.as_str()],
                true,
            ));
        }
    }

    for disk in &state.disks {
        steps.push(RemoteInstallStep::new(
            "prepare target disk",
            "nox-agent",
            ["disk-prepare", disk.path.as_str()],
            true,
        ));
    }

    steps.extend([
        RemoteInstallStep::new(
            "apply disko layout",
            "nox-agent",
            ["disko-apply", paths.disko_file.as_str()],
            true,
        ),
        RemoteInstallStep::new("verify mounted system", "findmnt", ["/mnt"], false),
    ]);

    Ok(steps)
}

pub fn plan_remote_install_steps_with_secrets(
    state: &InstallState,
    source_dir: &str,
    secrets: RemoteInstallSecrets<'_>,
) -> Result<Vec<RemoteInstallStep>> {
    let paths = remote_paths(state, source_dir)?;
    let source_dir = paths.source_dir.as_str();
    let role = paths.role;
    let flake_ref = paths.flake_ref.as_str();

    let mut steps = plan_remote_storage_steps(state, source_dir)?;

    if let Some(shared_system_key) = secrets.shared_system_key {
        steps.push(RemoteInstallStep::new_with_stdin(
            "copy shared system key",
            "nox-agent",
            ["secret-file-write", "/mnt/var/lib/sops-nix/key.txt", "0600"],
            shared_system_key.to_vec(),
            true,
        ));
    }

    // Per-user password hashes, placed before nixos-install so account
    // activation can read them. Falls back to the legacy single-user field.
    let password_writes: Vec<(String, String)> = if state.users.is_empty() {
        state
            .user_password_hash
            .as_ref()
            .map(|hash| {
                (
                    "/mnt/var/lib/nixos-install/user-password.hash".to_string(),
                    hash.clone(),
                )
            })
            .into_iter()
            .collect()
    } else {
        state
            .users
            .iter()
            .filter_map(|user| {
                user.password_hash.as_ref().map(|hash| {
                    (
                        format!("/mnt/var/lib/nixos-install/passwd-{}.hash", user.name),
                        hash.clone(),
                    )
                })
            })
            .collect()
    };
    for (target, hash) in password_writes {
        steps.push(RemoteInstallStep::new_with_stdin(
            "write user password hash",
            "nox-agent",
            ["secret-file-write", &target, "0600"],
            hash.as_bytes().to_vec(),
            true,
        ));
    }

    steps.extend([
        RemoteInstallStep::new(
            "install nixos",
            "nixos-install",
            ["--flake", flake_ref, "--no-root-passwd"],
            true,
        ),
        RemoteInstallStep::new(
            "copy system config",
            "nox-agent",
            ["config-copy", source_dir, role, state.install_user.as_str()],
            true,
        ),
    ]);

    if !state.skip_bin_ensure {
        steps.push(RemoteInstallStep::new_with_stdin(
            "run system bin ensure",
            "nox-agent",
            ["system-bin-ensure"],
            secrets.github_token.unwrap_or_default().to_vec(),
            true,
        ));
    }

    // Per-user dotfiles: clone each user's repo into their home. Falls back to
    // the legacy single-user field when no multi-user list is present.
    let dotfiles_jobs: Vec<(String, String)> = if state.users.is_empty() {
        normalized_dotfiles_repo(state.dotfiles_repo.as_deref())
            .map(|repo| (state.install_user.clone(), repo.to_string()))
            .into_iter()
            .collect()
    } else {
        state
            .users
            .iter()
            .filter_map(|user| {
                normalized_dotfiles_repo(user.dotfiles.as_deref())
                    .map(|repo| (user.name.clone(), repo.to_string()))
            })
            .collect()
    };
    for (username, repo) in dotfiles_jobs {
        steps.push(RemoteInstallStep::new_with_stdin(
            "run dotfiles",
            "nox-agent",
            ["dotfiles-run", &repo, &username],
            secrets.github_token.unwrap_or_default().to_vec(),
            true,
        ));
    }

    steps.push(RemoteInstallStep::new(
        "reboot target",
        "nox-agent",
        ["reboot-target"],
        true,
    ));

    Ok(steps)
}

#[allow(dead_code)]
pub fn assert_destructive_allowed(step: &RemoteInstallStep, allowed: bool) -> Result<()> {
    if step.destructive && !allowed {
        Err(format!(
            "refusing destructive remote step without confirmation: {}",
            step.name
        ))
    } else {
        Ok(())
    }
}

fn shell_display(value: &str) -> String {
    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_' | b'#' | b':')
    }) {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn normalized_dotfiles_repo(value: Option<&str>) -> Option<&str> {
    match value.map(str::trim) {
        None | Some("") | Some("skip") | Some("none") | Some("no") => None,
        Some(value) => Some(value),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        assert_destructive_allowed, plan_remote_install_steps,
        plan_remote_install_steps_with_secrets, RemoteInstallSecrets,
    };
    use crate::install::state::InstallState;

    #[test]
    fn remote_plan_contains_expected_order() {
        let state = InstallState::sample();
        let steps = plan_remote_install_steps(&state, "/tmp/nx-source").unwrap();
        let names = steps.iter().map(|step| step.name).collect::<Vec<_>>();

        assert_eq!(
            names,
            vec![
                "verify remote user",
                "clean up competing default routes",
                "verify flake source",
                "verify generated disko",
                "prepare target disk",
                "apply disko layout",
                "verify mounted system",
                "install nixos",
                "copy system config",
                "run system bin ensure",
                "run dotfiles",
                "reboot target",
            ]
        );
    }

    #[test]
    fn storage_steps_are_the_install_prefix_through_mount() {
        let state = InstallState::sample();
        let storage = super::plan_remote_storage_steps(&state, "/tmp/nx-source").unwrap();
        let names = storage.iter().map(|step| step.name).collect::<Vec<_>>();

        assert_eq!(
            names,
            vec![
                "verify remote user",
                "clean up competing default routes",
                "verify flake source",
                "verify generated disko",
                "prepare target disk",
                "apply disko layout",
                "verify mounted system",
            ]
        );

        // The storage steps must be a byte-for-byte prefix of the full install plan
        // so the standalone `storage apply` path executes exactly what the installer
        // would for the same state.
        let full = plan_remote_install_steps(&state, "/tmp/nx-source").unwrap();
        assert_eq!(&full[..storage.len()], storage.as_slice());
    }

    #[test]
    fn storage_steps_include_overwrite_removal() {
        let mut state = InstallState::sample();
        state.overwrite_existing_storage = true;
        let storage = super::plan_remote_storage_steps(&state, "/tmp/nx-source").unwrap();
        let overwrite = storage
            .iter()
            .find(|step| step.name == "remove existing volume group")
            .unwrap();

        assert!(overwrite.destructive);
        assert_eq!(overwrite.command_line(), "nox-agent storage-overwrite pool");
        assert!(!storage.iter().any(|step| step.name == "install nixos"));
    }

    #[test]
    fn route_cleanup_can_be_disabled() {
        let mut state = InstallState::sample();
        state.network_route_cleanup = false;
        let steps = plan_remote_install_steps(&state, "/tmp/nx-source").unwrap();
        let names = steps.iter().map(|step| step.name).collect::<Vec<_>>();

        assert_eq!(
            names[..3],
            [
                "verify remote user",
                "verify flake source",
                "verify generated disko",
            ]
        );
        assert!(!names.contains(&"clean up competing default routes"));
    }

    #[test]
    fn overwrite_mode_removes_existing_vg_before_disk_prepare() {
        let mut state = InstallState::sample();
        state.overwrite_existing_storage = true;
        let steps = plan_remote_install_steps(&state, "/tmp/nx-source").unwrap();
        let names = steps.iter().map(|step| step.name).collect::<Vec<_>>();

        assert_eq!(
            names[..6],
            [
                "verify remote user",
                "clean up competing default routes",
                "verify flake source",
                "verify generated disko",
                "remove existing volume group",
                "prepare target disk",
            ]
        );

        let overwrite = steps
            .iter()
            .find(|step| step.name == "remove existing volume group")
            .unwrap();
        assert!(overwrite.destructive);
        assert_eq!(
            overwrite.command_line(),
            "nox-agent storage-overwrite pool"
        );
    }

    #[test]
    fn destructive_steps_are_marked() {
        let state = InstallState::sample();
        let steps = plan_remote_install_steps(&state, "/tmp/nx-source").unwrap();

        assert!(!steps[0].destructive);
        assert!(!steps[1].destructive);
        assert!(!steps[2].destructive);
        assert!(
            steps
                .iter()
                .find(|step| step.name == "prepare target disk")
                .unwrap()
                .destructive
        );
        assert!(
            steps
                .iter()
                .find(|step| step.name == "apply disko layout")
                .unwrap()
                .destructive
        );
        assert!(
            steps
                .iter()
                .find(|step| step.name == "install nixos")
                .unwrap()
                .destructive
        );
        assert!(
            steps
                .iter()
                .find(|step| step.name == "reboot target")
                .unwrap()
                .destructive
        );
    }

    #[test]
    fn destructive_steps_require_confirmation() {
        let state = InstallState::sample();
        let steps = plan_remote_install_steps(&state, "/tmp/nx-source").unwrap();
        let disko = steps
            .iter()
            .find(|step| step.name == "prepare target disk")
            .unwrap();

        assert!(assert_destructive_allowed(disko, false).is_err());
        assert!(assert_destructive_allowed(disko, true).is_ok());
    }

    #[test]
    fn disk_prepare_steps_include_selected_disk_paths() {
        let state = InstallState::sample();
        let steps = plan_remote_install_steps(&state, "/tmp/nx-source").unwrap();
        let disk_step = steps
            .iter()
            .find(|step| step.name == "prepare target disk")
            .unwrap();

        assert_eq!(disk_step.args, vec!["disk-prepare", "/dev/nvme0n1"]);
    }

    #[test]
    fn shared_key_step_sits_after_mount_before_nixos_install() {
        let state = InstallState::sample();
        let steps = plan_remote_install_steps_with_secrets(
            &state,
            "/tmp/nx-source",
            RemoteInstallSecrets {
                shared_system_key: Some(b"AGE-SECRET-KEY"),
                github_token: None,
            },
        )
        .unwrap();
        let names = steps.iter().map(|step| step.name).collect::<Vec<_>>();

        let mount_index = names
            .iter()
            .position(|name| *name == "verify mounted system")
            .unwrap();
        let key_index = names
            .iter()
            .position(|name| *name == "copy shared system key")
            .unwrap();
        let install_index = names
            .iter()
            .position(|name| *name == "install nixos")
            .unwrap();

        assert!(mount_index < key_index);
        assert!(key_index < install_index);
        let key_step = &steps[key_index];
        assert!(key_step.destructive);
        assert_eq!(
            key_step.args,
            vec!["secret-file-write", "/mnt/var/lib/sops-nix/key.txt", "0600"]
        );
        assert_eq!(key_step.stdin, b"AGE-SECRET-KEY");
    }

    #[test]
    fn finish_steps_are_typed_and_keep_github_token_on_stdin() {
        let state = InstallState::sample();
        let steps = plan_remote_install_steps_with_secrets(
            &state,
            "/tmp/nx-source",
            RemoteInstallSecrets {
                shared_system_key: Some(b"AGE-SECRET-KEY"),
                github_token: Some(b"ghp_test"),
            },
        )
        .unwrap();

        let config = steps
            .iter()
            .find(|step| step.name == "copy system config")
            .unwrap();
        assert_eq!(
            config.args,
            vec!["config-copy", "/tmp/nx-source", "laptop", "bresilla"]
        );

        let bin = steps
            .iter()
            .find(|step| step.name == "run system bin ensure")
            .unwrap();
        assert_eq!(bin.args, vec!["system-bin-ensure"]);
        assert_eq!(bin.stdin, b"ghp_test");

        let reboot = steps
            .iter()
            .find(|step| step.name == "reboot target")
            .unwrap();
        assert_eq!(reboot.args, vec!["reboot-target"]);
    }

    #[test]
    fn writes_user_password_hash_before_nixos_install() {
        let mut state = InstallState::sample();
        state.users[0].password_hash = Some("$y$j9T$hashvalue".to_string());
        let steps = plan_remote_install_steps_with_secrets(
            &state,
            "/tmp/nx-source",
            RemoteInstallSecrets {
                shared_system_key: Some(b"AGE-SECRET-KEY"),
                github_token: Some(b"ghp_test"),
            },
        )
        .unwrap();
        let names = steps.iter().map(|step| step.name).collect::<Vec<_>>();

        let password_index = names
            .iter()
            .position(|name| *name == "write user password hash")
            .unwrap();
        let install_index = names.iter().position(|name| *name == "install nixos").unwrap();
        assert!(password_index < install_index);

        let step = &steps[password_index];
        assert!(step.destructive);
        assert_eq!(
            step.args,
            vec![
                "secret-file-write",
                "/mnt/var/lib/nixos-install/passwd-bresilla.hash",
                "0600"
            ]
        );
        assert_eq!(step.stdin, b"$y$j9T$hashvalue");
    }

    #[test]
    fn omits_password_step_when_no_password_set() {
        let state = InstallState::sample();
        let steps = plan_remote_install_steps(&state, "/tmp/nx-source").unwrap();
        assert!(!steps.iter().any(|step| step.name == "write user password hash"));
    }

    #[test]
    fn bin_ensure_step_can_be_skipped() {
        let mut state = InstallState::sample();
        state.skip_bin_ensure = true;
        let steps = plan_remote_install_steps_with_secrets(
            &state,
            "/tmp/nx-source",
            RemoteInstallSecrets {
                shared_system_key: Some(b"AGE-SECRET-KEY"),
                github_token: Some(b"ghp_test"),
            },
        )
        .unwrap();

        assert!(!steps.iter().any(|step| step.name == "run system bin ensure"));
        // config-copy still runs; reboot is still the final step.
        assert!(steps.iter().any(|step| step.name == "copy system config"));
        assert_eq!(steps.last().unwrap().name, "reboot target");
    }

    #[test]
    fn dotfiles_step_is_optional_and_uses_github_token_stdin() {
        let mut state = InstallState::sample();
        state.users[0].dotfiles = Some("skip".to_string());
        let steps = plan_remote_install_steps_with_secrets(
            &state,
            "/tmp/nx-source",
            RemoteInstallSecrets {
                shared_system_key: Some(b"AGE-SECRET-KEY"),
                github_token: Some(b"ghp_test"),
            },
        )
        .unwrap();
        assert!(!steps.iter().any(|step| step.name == "run dotfiles"));

        state.users[0].dotfiles = Some("https://github.com/bresilla/dot.git".to_string());
        let steps = plan_remote_install_steps_with_secrets(
            &state,
            "/tmp/nx-source",
            RemoteInstallSecrets {
                shared_system_key: Some(b"AGE-SECRET-KEY"),
                github_token: Some(b"ghp_test"),
            },
        )
        .unwrap();
        let dotfiles = steps
            .iter()
            .find(|step| step.name == "run dotfiles")
            .unwrap();
        assert_eq!(
            dotfiles.args,
            vec![
                "dotfiles-run",
                "https://github.com/bresilla/dot.git",
                "bresilla"
            ]
        );
        assert_eq!(dotfiles.stdin, b"ghp_test");
    }

    #[test]
    fn rejects_relative_source_dir() {
        let state = InstallState::sample();
        let err = plan_remote_install_steps(&state, "tmp/nx-source").unwrap_err();

        assert!(err.contains("must be absolute"));
    }

    #[test]
    fn every_planned_step_parses_into_a_typed_op() {
        let mut state = InstallState::sample();
        state.overwrite_existing_storage = true;
        state.users[0].password_hash = Some("$y$j9T$hash".to_string());
        let steps = plan_remote_install_steps_with_secrets(
            &state,
            "/tmp/nx-source",
            RemoteInstallSecrets {
                shared_system_key: Some(b"AGE-SECRET-KEY"),
                github_token: Some(b"ghp_test"),
            },
        )
        .unwrap();

        use super::StepOp;
        let ops = steps
            .iter()
            .map(|step| step.op().unwrap())
            .collect::<Vec<_>>();
        assert!(ops.iter().any(|op| matches!(op, StepOp::RouteCleanup)));
        assert!(ops
            .iter()
            .any(|op| matches!(op, StepOp::StorageOverwrite { vg_name: "pool" })));
        assert!(ops
            .iter()
            .any(|op| matches!(op, StepOp::DiskPrepare { disk: "/dev/nvme0n1" })));
        assert!(ops.iter().any(|op| matches!(op, StepOp::DiskoApply { .. })));
        assert_eq!(
            ops.iter()
                .filter(|op| matches!(op, StepOp::SecretWrite { .. }))
                .count(),
            2 // sops key + password hash
        );
        assert!(ops.iter().any(|op| matches!(op, StepOp::NixosInstall { .. })));
        assert!(ops.iter().any(|op| matches!(op, StepOp::ConfigCopy { .. })));
        assert!(ops.iter().any(|op| matches!(op, StepOp::BinEnsure)));
        assert!(ops.iter().any(|op| matches!(op, StepOp::DotfilesRun { .. })));
        assert!(ops.iter().any(|op| matches!(op, StepOp::Reboot)));
        assert!(ops.iter().any(|op| matches!(op, StepOp::Program { .. })));
    }

    #[test]
    fn op_parsing_validates_arguments() {
        use super::RemoteInstallStep;

        let bad_secret_path = RemoteInstallStep {
            name: "copy shared system key",
            program: "nox-agent".to_string(),
            args: vec![
                "secret-file-write".to_string(),
                "/mnt/tmp/evil.txt".to_string(),
                "0600".to_string(),
            ],
            stdin: b"key".to_vec(),
            destructive: true,
        };
        assert!(bad_secret_path.op().unwrap_err().contains("unsupported secret write path"));

        let bad_vg = RemoteInstallStep {
            name: "remove existing volume group",
            program: "nox-agent".to_string(),
            args: vec!["storage-overwrite".to_string(), "bad vg".to_string()],
            stdin: Vec::new(),
            destructive: true,
        };
        assert!(bad_vg.op().unwrap_err().contains("invalid VG name"));

        let bad_role = RemoteInstallStep {
            name: "copy system config",
            program: "nox-agent".to_string(),
            args: vec![
                "config-copy".to_string(),
                "/tmp/nx-source".to_string(),
                "desktop".to_string(),
                "bresilla".to_string(),
            ],
            stdin: Vec::new(),
            destructive: true,
        };
        assert!(bad_role.op().unwrap_err().contains("invalid config-copy role"));

        let bad_repo = RemoteInstallStep {
            name: "run dotfiles",
            program: "nox-agent".to_string(),
            args: vec![
                "dotfiles-run".to_string(),
                "-bad".to_string(),
                "bresilla".to_string(),
            ],
            stdin: Vec::new(),
            destructive: true,
        };
        assert!(bad_repo.op().unwrap_err().contains("invalid dotfiles repo"));

        let unknown = RemoteInstallStep {
            name: "mystery",
            program: "nox-agent".to_string(),
            args: vec!["mystery-op".to_string()],
            stdin: Vec::new(),
            destructive: false,
        };
        assert!(unknown.op().unwrap_err().contains("unknown agent step operation"));
    }
}
