use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(test)]
use crate::install::artifacts::TransferredArtifact;
#[cfg(test)]
use crate::install::disk::DiskPrepareResult;
use crate::install::executor::{RemoteExecutionPolicy, RemoteInstallExecution};
use crate::install::remote::RemoteInstallSession;
use crate::install::state::{validate_mountpoint, InstallScope, InstallState};
use crate::nix_ast;
use crate::Result;

const REMOTE_SOURCE_DIR: &str = "/tmp/nx-source";

pub fn prepare_generated(repo: &Path, state: &InstallState) -> Result<()> {
    validate_state(state)?;
    // nox produces LIS; the nix files are translations OF the document. The
    // implicit whole-disk default layout is made explicit first so the
    // document fully describes the machine.
    let mut source = state.clone();
    source.materialize_default_slices();
    let doc = crate::install::lis::from_state(&source);
    crate::install::lis::write_document(repo, &doc)?;
    // The opinionated translator (this flake's modules) consumes the document.
    let gen_state = crate::install::lis::state_from(&doc);
    crate::install::disko::write(repo, &gen_state)?;
    crate::install::storage_plan::write(repo, &gen_state)?;
    write_host(repo, &gen_state)?;
    write_user(repo, &gen_state)?;

    for file in generated_nix_files(repo) {
        let report = nix_ast::parse_file(&file)?;
        if !report.is_ok() {
            return Err(format!(
                "generated file {} has Nix parse errors: {}",
                file.display(),
                report.errors.join("; ")
            ));
        }
    }
    Ok(())
}

/// Run the confirmed install, reporting every event through `reporter`. The CLI
/// passes a text reporter; the TUI passes an mpsc-backed one so a live progress
/// screen can render the same events.
pub fn run_confirmed_with_reporter(
    repo: &Path,
    state: &InstallState,
    reporter: &crate::report::Reporter,
) -> Result<u8> {
    prepare_generated(repo, state)?;
    let execution = match state.scope {
        InstallScope::Remote => run_confirmed_remote_with_agent(repo, state, reporter)?,
        InstallScope::Local => run_confirmed_local(repo, state, reporter)?,
    };
    Ok(if execution.refused.is_empty() { 0 } else { 1 })
}

/// Run the confirmed install in-process on this machine (already Disko-mounted).
fn run_confirmed_local(
    repo: &Path,
    state: &InstallState,
    reporter: &crate::report::Reporter,
) -> Result<RemoteInstallExecution> {
    reporter.phase("prepare");
    let secrets = prepare_remote_install_secrets(repo, state, None)?;
    let source_dir = repo.to_string_lossy().to_string();
    let steps = crate::install::plan::plan_remote_install_steps_with_secrets(
        state,
        &source_dir,
        plan_secrets(&secrets),
    )?;
    let policy = confirmed_remote_policy(&steps);
    let mut ops = crate::install::local::LiveLocalOps {
        reporter: reporter.clone(),
    };
    reporter.phase("execute");
    crate::install::local::execute_local_plan(&mut ops, &steps, policy, reporter)
}

fn run_confirmed_remote_with_agent(
    repo: &Path,
    state: &InstallState,
    reporter: &crate::report::Reporter,
) -> Result<RemoteInstallExecution> {
    let reporter = reporter.clone();
    // The interactive confirmed path honors NX_AGE_KEY_FILE and otherwise uses the YubiKey.
    let secrets = prepare_remote_install_secrets(repo, state, None)?;
    reporter.phase("bootstrap");
    let bootstrap_reporter = reporter.clone();
    let mut session = RemoteInstallSession::connect(repo, &state.remote, move |message| {
        bootstrap_reporter.note(format!("agent bootstrap: {message}"));
    })?;
    session.set_reporter(reporter.clone());

    let execution = (|| {
        reporter.phase("transfer");
        let transferred = session.transfer_flake_source(repo, REMOTE_SOURCE_DIR)?;
        for artifact in transferred {
            reporter.note(format!(
                "transferred source: {} -> {} ({} bytes)",
                artifact.local_path.display(),
                artifact.remote_path,
                artifact.bytes_written
            ));
        }

        let steps = crate::install::plan::plan_remote_install_steps_with_secrets(
            state,
            REMOTE_SOURCE_DIR,
            plan_secrets(&secrets),
        )?;
        let policy = confirmed_remote_policy(&steps);
        reporter.phase("execute");
        crate::install::executor::execute_remote_plan(&mut session, &steps, policy, &reporter)
    })();

    let close = session.close();
    let execution = execution?;
    close?;
    Ok(execution)
}

pub(crate) struct RemoteInstallSecretBytes {
    pub(crate) shared_system_key: Vec<u8>,
    pub(crate) github_token: Vec<u8>,
}

/// Where the shared system age key comes from: a plaintext age identity file on
/// this machine, the YubiKey (via `install.sh key-check`, which decrypts the
/// YubiKey-only `secrets/key.txt`), or nowhere — the user chose to install
/// without secrets.
pub(crate) enum SecretSource {
    AgeFile(PathBuf),
    YubiKey,
    Skip,
}

/// Resolve the secret backend: an explicit age key file wins, then the state's
/// chosen mode (TUI decision), then `NX_AGE_KEY_FILE`, otherwise the YubiKey.
pub(crate) fn resolve_secret_source(
    age_key_file: Option<&Path>,
    mode: &crate::install::state::SecretsMode,
) -> SecretSource {
    if let Some(path) = age_key_file {
        return SecretSource::AgeFile(path.to_path_buf());
    }
    match mode {
        crate::install::state::SecretsMode::Skip => return SecretSource::Skip,
        crate::install::state::SecretsMode::KeyFile(path) => {
            return SecretSource::AgeFile(PathBuf::from(path));
        }
        crate::install::state::SecretsMode::YubiKey => {}
    }
    if let Some(path) = std::env::var_os("NX_AGE_KEY_FILE") {
        let path = PathBuf::from(path);
        if !path.as_os_str().is_empty() {
            return SecretSource::AgeFile(path);
        }
    }
    SecretSource::YubiKey
}

/// `Ok(None)` means the user chose to install without secrets: no key is
/// copied to the target and token-consuming steps run without a token.
pub(crate) fn prepare_remote_install_secrets(
    repo: &Path,
    state: &InstallState,
    age_key_file: Option<&Path>,
) -> Result<Option<RemoteInstallSecretBytes>> {
    match resolve_secret_source(age_key_file, &state.secrets_mode) {
        SecretSource::AgeFile(path) => prepare_secrets_from_age_file(repo, &path).map(Some),
        SecretSource::YubiKey => prepare_secrets_from_yubikey(repo).map(Some),
        SecretSource::Skip => Ok(None),
    }
}

/// Plan-level view of optional secrets, shared by every confirmed-install path.
pub(crate) fn plan_secrets(
    secrets: &Option<RemoteInstallSecretBytes>,
) -> crate::install::plan::RemoteInstallSecrets<'_> {
    match secrets {
        Some(secrets) => crate::install::plan::RemoteInstallSecrets {
            shared_system_key: Some(&secrets.shared_system_key),
            github_token: Some(&secrets.github_token),
        },
        None => crate::install::plan::RemoteInstallSecrets::default(),
    }
}

/// Prepare install secrets using a connected YubiKey. Decrypts `secrets/key.txt`
/// natively (no external `age`/`age-plugin-yubikey`) and writes the plaintext key
/// to a RAM cache so `sops` can decrypt the GitHub token with it.
fn prepare_secrets_from_yubikey(repo: &Path) -> Result<RemoteInstallSecretBytes> {
    let encrypted = repo.join("host/secrets/key.txt");
    let ciphertext = fs::read(&encrypted)
        .map_err(|err| format!("failed to read {}: {err}", encrypted.display()))?;
    let report = crate::yubikey_probe::recipients()?;
    if report.recipients.is_empty() {
        return Err("no age-compatible YubiKey recipients found in retired PIV slots".to_string());
    }
    let key = crate::sops::data_key::decrypt_age_file(&ciphertext, &report)?;
    if key.is_empty() {
        return Err("decrypted shared system key is empty".to_string());
    }

    let key_file = shared_system_key_cache_path();
    let result = (|| {
        fs::write(&key_file, &key).map_err(|err| {
            format!("failed to write decrypted key {}: {err}", key_file.display())
        })?;
        #[cfg(unix)]
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("failed to chmod {}: {err}", key_file.display()))?;
        let github_token = decrypt_github_token(repo, &key_file)?;
        Ok(RemoteInstallSecretBytes {
            shared_system_key: key,
            github_token,
        })
    })();
    let _ = fs::remove_file(&key_file);
    result
}

/// Prepare the install secrets from a local age identity file. The file is used
/// directly as the shared system key placed on the target and as the sops age
/// key that decrypts the GitHub token, so no YubiKey is required.
fn prepare_secrets_from_age_file(repo: &Path, age_key_file: &Path) -> Result<RemoteInstallSecretBytes> {
    let key = fs::read(age_key_file).map_err(|err| {
        format!(
            "failed to read age key file {}: {err}",
            age_key_file.display()
        )
    })?;
    if key.is_empty() {
        return Err(format!(
            "age key file is empty: {}",
            age_key_file.display()
        ));
    }
    let github_token = decrypt_github_token(repo, age_key_file)?;
    Ok(RemoteInstallSecretBytes {
        shared_system_key: key,
        github_token,
    })
}


/// The secrets directory in effect: the self-contained `secrets-test/` fixture
/// when present, otherwise the real `secrets/`.
pub(crate) fn secrets_dir(repo: &Path) -> PathBuf {
    let test_dir = repo.join("host/secrets-test");
    if test_dir.is_dir() {
        test_dir
    } else {
        repo.join("host/secrets")
    }
}

fn decrypt_github_token(repo: &Path, key_file: &Path) -> Result<Vec<u8>> {
    let secret_file = secrets_dir(repo).join("common/github.yaml");
    let output = Command::new("sops")
        .arg("--decrypt")
        .arg(&secret_file)
        .env("SOPS_AGE_KEY_FILE", key_file)
        .output()
        .map_err(|err| format!("failed to run sops for {}: {err}", secret_file.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return if stderr.is_empty() {
            Err(format!(
                "sops decrypt {} failed with {}",
                secret_file.display(),
                output.status.code().unwrap_or(1)
            ))
        } else {
            Err(format!(
                "sops decrypt {} failed with {}: {}",
                secret_file.display(),
                output.status.code().unwrap_or(1),
                stderr
            ))
        };
    }
    github_token_from_yaml(&output.stdout).map(|token| token.into_bytes())
}

fn github_token_from_yaml(bytes: &[u8]) -> Result<String> {
    let value: serde_yaml::Value = serde_yaml::from_slice(bytes)
        .map_err(|err| format!("failed to parse decrypted GitHub secret YAML: {err}"))?;
    let github = mapping_get(&value, "github")
        .ok_or_else(|| "decrypted GitHub secret has no github section".to_string())?;
    let token = mapping_get(github, "token")
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| "decrypted GitHub secret has no github.token".to_string())?;
    Ok(token.to_string())
}

fn mapping_get<'a>(value: &'a serde_yaml::Value, key: &str) -> Option<&'a serde_yaml::Value> {
    let serde_yaml::Value::Mapping(mapping) = value else {
        return None;
    };
    mapping.get(serde_yaml::Value::String(key.to_string()))
}

fn shared_system_key_cache_path() -> PathBuf {
    let dir = Path::new("/dev/shm");
    let base = if dir.is_dir() {
        dir.to_path_buf()
    } else {
        std::env::temp_dir()
    };
    base.join(format!(
        "nixos-install-system-key.nox.{}",
        std::process::id()
    ))
}

fn confirmed_remote_policy(steps: &[crate::install::plan::RemoteInstallStep]) -> RemoteExecutionPolicy {
    RemoteExecutionPolicy::allow_destructive_steps(
        steps.iter().filter(|step| step.destructive).count(),
    )
}

#[cfg(test)]
fn prepare_confirmed_remote_with_runner(
    state: &InstallState,
    mut transfer_generated: impl FnMut() -> Result<Vec<TransferredArtifact>>,
    disk_preparer: impl FnMut(&str, &str) -> Result<DiskPrepareResult>,
) -> Result<Vec<DiskPrepareResult>> {
    if state.scope != InstallScope::Remote {
        return Ok(Vec::new());
    }
    transfer_generated()?;
    prepare_confirmed_remote_disks_with_runner(state, disk_preparer)
}

#[cfg(test)]
fn prepare_confirmed_remote_disks_with_runner(
    state: &InstallState,
    mut disk_preparer: impl FnMut(&str, &str) -> Result<DiskPrepareResult>,
) -> Result<Vec<DiskPrepareResult>> {
    if state.scope != InstallScope::Remote {
        return Ok(Vec::new());
    }
    if state.disks.is_empty() {
        return Err("no remote install disks selected".to_string());
    }

    let mut results = Vec::new();
    for disk in &state.disks {
        println!("preparing remote disk through nx agent: {}", disk.path);
        let result = disk_preparer(&state.remote, &disk.path)?;
        if result.status != 0 {
            let detail = if result.stderr.is_empty() {
                format!("remote disk prep exited with {}", result.status)
            } else {
                format!(
                    "remote disk prep exited with {}: {}",
                    result.status, result.stderr
                )
            };
            return Err(format!("failed to prepare {}: {detail}", disk.path));
        }
        if !result.stdout.is_empty() {
            println!("{}", result.stdout);
        }
        results.push(result);
    }
    Ok(results)
}

fn validate_state(state: &InstallState) -> Result<()> {
    validate_hostname(&state.hostname)?;
    validate_username(&state.install_user)?;
    match state.scope {
        InstallScope::Remote => {
            if state.remote.trim().is_empty() {
                return Err("remote target is required".to_string());
            }
            if !state.remote.contains('@') {
                return Err(format!(
                    "remote target should look like user@host: {}",
                    state.remote
                ));
            }
        }
        InstallScope::Local => validate_mountpoint(&state.mountpoint)?,
    }
    Ok(())
}

fn write_host(repo: &Path, state: &InstallState) -> Result<()> {
    validate_hostname(&state.hostname)?;
    let file = repo.join("host/generated/host.nix");
    // The secrets decision is always written out explicitly. `false` turns the
    // whole sops layer off on the target (host/modules/secrets.nix is mkIf'd
    // on this) so it activates cleanly with no age key; place
    // /var/lib/sops-nix/key.txt and flip it back to re-enable everything.
    let secrets_line = if state.secrets_mode == crate::install::state::SecretsMode::Skip {
        "\n  bresilla.secrets.enable = false;\n"
    } else {
        "\n  bresilla.secrets.enable = true;\n"
    };
    write_file(
        &file,
        &format!(
            r#"{{
  lib,
  modulesPath,
  ...
}}:

{{
  imports = [
    (modulesPath + "/installer/scan/not-detected.nix")
  ];

  networking.hostName = lib.mkDefault "{}";
  time.timeZone = lib.mkDefault "{}";
{}
  bresilla.features.system.architecture = lib.mkDefault "unknown";
  bresilla.features.system.cpuVendor = lib.mkDefault "unknown";

  boot.loader.systemd-boot.enable = lib.mkDefault true;
  boot.loader.efi = {{
    canTouchEfiVariables = lib.mkDefault true;
    efiSysMountPoint = lib.mkDefault "/boot/efi";
  }};
}}
"#,
            state.hostname, state.timezone, secrets_line
        ),
    )
}

/// Runtime path for a given account's hashed password file.
pub(crate) fn user_password_hash_target(username: &str) -> String {
    format!("/var/lib/nixos-install/passwd-{username}.hash")
}

fn write_user(repo: &Path, state: &InstallState) -> Result<()> {
    let users = if state.users.is_empty() {
        // Fall back to the legacy single-user fields for non-TUI callers.
        vec![crate::install::state::UserAccount {
            name: state.install_user.clone(),
            password_hash: state.user_password_hash.clone(),
            dotfiles: state.dotfiles_repo.clone(),
            groups: crate::install::state::default_user_groups(),
        }]
    } else {
        state.users.clone()
    };
    for user in &users {
        validate_username(&user.name)?;
    }
    let primary = &users[0];

    let hashed_password_file = if primary.password_hash.is_some() {
        format!(
            "lib.mkDefault \"{}\"",
            user_password_hash_target(&primary.name)
        )
    } else {
        "lib.mkDefault null".to_string()
    };
    let groups_nix = |groups: &[String]| -> String {
        groups
            .iter()
            .map(|g| format!("\"{g}\""))
            .collect::<Vec<_>>()
            .join(" ")
    };

    let mut body = format!(
        r#"{{
  lib,
  pkgs,
  ...
}}:

{{
  bresilla.user.name = lib.mkDefault "{name}";
  bresilla.user.hashedPasswordFile = {hash};
  bresilla.features.system.ssh.enable = lib.mkDefault {ssh};

  # Primary account group membership chosen in the installer.
  users.users."{name}".extraGroups = lib.mkForce [ {primary_groups} ];
"#,
        name = primary.name,
        hash = hashed_password_file,
        ssh = if state.allow_ssh { "true" } else { "false" },
        primary_groups = groups_nix(&primary.groups),
    );

    // Additional accounts beyond the primary.
    for user in users.iter().skip(1) {
        let hashed = match &user.password_hash {
            Some(_) => format!(
                "\n    hashedPasswordFile = \"{}\";",
                user_password_hash_target(&user.name)
            ),
            None => String::new(),
        };
        body.push_str(&format!(
            r#"
  users.users."{name}" = {{
    isNormalUser = true;
    shell = pkgs.zsh;
    extraGroups = [ {groups} ];{hashed}
  }};
"#,
            name = user.name,
            groups = groups_nix(&user.groups),
            hashed = hashed,
        ));
    }
    body.push_str("}\n");

    write_file(&repo.join("host/generated/user.nix"), &body)
}

fn write_file(file: &Path, content: &str) -> Result<()> {
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    fs::write(file, content).map_err(|err| format!("failed to write {}: {err}", file.display()))
}

fn generated_nix_files(repo: &Path) -> [PathBuf; 3] {
    [
        repo.join("host/generated/disko.nix"),
        repo.join("host/generated/host.nix"),
        repo.join("host/generated/user.nix"),
    ]
}

fn validate_hostname(value: &str) -> Result<()> {
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

fn validate_username(value: &str) -> Result<()> {
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
    use std::cell::RefCell;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        confirmed_remote_policy, github_token_from_yaml,
        prepare_confirmed_remote_disks_with_runner, prepare_confirmed_remote_with_runner,
        prepare_generated, resolve_secret_source, validate_hostname, validate_username,
        SecretSource,
    };
    use std::path::Path;
    use crate::install::artifacts::TransferredArtifact;
    use crate::install::disk::DiskPrepareResult;
    
    use crate::install::state::{InstallScope, InstallState};

    #[test]
    fn age_file_backend_reads_key_and_decrypts_github_token() {
        // End-to-end check of the local-age secret path using real age/sops crypto.
        // Skips when the tools are not on PATH so it stays green in minimal envs.
        if !tool_available("age-keygen") || !tool_available("sops") {
            eprintln!("skipping: age-keygen/sops not available");
            return;
        }

        let dir = temp_dir("age-secrets");
        fs::create_dir_all(dir.join("host/secrets/common")).unwrap();
        let key_file = dir.join("age-key.txt");

        // Generate a test age identity and derive its recipient.
        let status = std::process::Command::new("age-keygen")
            .arg("-o")
            .arg(&key_file)
            .status()
            .unwrap();
        assert!(status.success());
        let recipient = std::process::Command::new("age-keygen")
            .arg("-y")
            .arg(&key_file)
            .output()
            .unwrap();
        let recipient = String::from_utf8(recipient.stdout).unwrap().trim().to_string();

        // Encrypt a fixture github.yaml to that recipient with sops.
        let plaintext = dir.join("github.plain.yaml");
        fs::write(&plaintext, "github:\n  token: ghp_local_age_test\n").unwrap();
        let encrypted = std::process::Command::new("sops")
            .arg("--encrypt")
            .arg(&plaintext)
            .current_dir(&dir)
            .env("SOPS_AGE_RECIPIENTS", &recipient)
            .output()
            .unwrap();
        assert!(encrypted.status.success(), "sops encrypt failed: {}", String::from_utf8_lossy(&encrypted.stderr));
        fs::write(dir.join("host/secrets/common/github.yaml"), &encrypted.stdout).unwrap();

        let secrets = super::prepare_secrets_from_age_file(&dir, &key_file).unwrap();
        assert_eq!(secrets.shared_system_key, fs::read(&key_file).unwrap());
        assert_eq!(secrets.github_token, b"ghp_local_age_test");

        fs::remove_dir_all(dir).unwrap();
    }

    fn tool_available(name: &str) -> bool {
        std::process::Command::new(name)
            .arg("--version")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn explicit_age_key_file_selects_age_backend() {
        use crate::install::state::SecretsMode;
        let source =
            resolve_secret_source(Some(Path::new("/tmp/age-key.txt")), &SecretsMode::YubiKey);
        assert!(matches!(source, SecretSource::AgeFile(path) if path == Path::new("/tmp/age-key.txt")));
    }

    #[test]
    fn defaults_to_yubikey_without_age_key_or_env() {
        use crate::install::state::SecretsMode;
        // Only meaningful when NX_AGE_KEY_FILE is unset in this process.
        if std::env::var_os("NX_AGE_KEY_FILE").is_none() {
            assert!(matches!(
                resolve_secret_source(None, &SecretsMode::YubiKey),
                SecretSource::YubiKey
            ));
        }
    }

    #[test]
    fn skip_mode_and_key_file_mode_pick_their_sources() {
        use crate::install::state::SecretsMode;
        assert!(matches!(
            resolve_secret_source(None, &SecretsMode::Skip),
            SecretSource::Skip
        ));
        let source =
            resolve_secret_source(None, &SecretsMode::KeyFile("/tmp/id.txt".to_string()));
        assert!(matches!(source, SecretSource::AgeFile(path) if path == Path::new("/tmp/id.txt")));
        // An explicit CLI key file outranks even a Skip decision.
        let source = resolve_secret_source(Some(Path::new("/cli/key")), &SecretsMode::Skip);
        assert!(matches!(source, SecretSource::AgeFile(_)));
    }

    #[test]
    fn validates_hostname_like_shell_installer() {
        assert!(validate_hostname("novo").is_ok());
        assert!(validate_hostname("nixos-box").is_ok());
        assert!(validate_hostname("-bad").is_err());
        assert!(validate_hostname("bad_underscore").is_err());
    }

    #[test]
    fn validates_username_like_shell_installer() {
        assert!(validate_username("bresilla").is_ok());
        assert!(validate_username("_svc").is_ok());
        assert!(validate_username("Bad").is_err());
        assert!(validate_username("bad.name").is_err());
    }

    #[test]
    fn prepares_generated_files_that_parse_as_nix() {
        let dir = temp_dir("generated");
        fs::create_dir_all(&dir).unwrap();
        prepare_generated(&dir, &InstallState::sample()).unwrap();

        assert!(dir.join("host/generated/disko.nix").is_file());
        assert!(dir.join("host/generated/host.nix").is_file());
        assert!(dir.join("host/generated/user.nix").is_file());
        assert!(dir.join("host/generated/storage-plan.json").is_file());
        let user = fs::read_to_string(dir.join("host/generated/user.nix")).unwrap();
        assert!(user.contains("bresilla.features.system.ssh.enable = lib.mkDefault true;"));
        let storage_plan = fs::read_to_string(dir.join("host/generated/storage-plan.json")).unwrap();
        let storage_plan = serde_json::from_str::<serde_json::Value>(&storage_plan).unwrap();
        assert_eq!(storage_plan["storage_mode"], "joined-lvm");
        assert_eq!(storage_plan["volume_groups"][0]["name"], "pool");
        // The secrets decision is always explicit in the generated host.nix.
        let host = fs::read_to_string(dir.join("host/generated/host.nix")).unwrap();
        assert!(host.contains("bresilla.secrets.enable = true;"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn skipping_secrets_disables_them_in_generated_host_nix() {
        let dir = temp_dir("generated-no-secrets");
        fs::create_dir_all(&dir).unwrap();
        let mut state = InstallState::sample();
        state.secrets_mode = crate::install::state::SecretsMode::Skip;
        prepare_generated(&dir, &state).unwrap();
        let host = fs::read_to_string(dir.join("host/generated/host.nix")).unwrap();
        assert!(host.contains("bresilla.secrets.enable = false;"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn generated_user_file_sets_password_hash_file_when_password_present() {
        let dir = temp_dir("generated-password");
        fs::create_dir_all(&dir).unwrap();
        let mut state = InstallState::sample();
        state.users[0].password_hash = Some("$y$j9T$abc".to_string());
        prepare_generated(&dir, &state).unwrap();

        let user = fs::read_to_string(dir.join("host/generated/user.nix")).unwrap();
        assert!(user.contains(
            "bresilla.user.hashedPasswordFile = lib.mkDefault \"/var/lib/nixos-install/passwd-bresilla.hash\";"
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn generated_user_file_renders_multiple_users_with_groups() {
        let dir = temp_dir("generated-multiuser");
        fs::create_dir_all(&dir).unwrap();
        let mut state = InstallState::sample();
        state.users = vec![
            crate::install::state::UserAccount {
                name: "bresilla".into(),
                password_hash: Some("$y$hash1".into()),
                dotfiles: None,
                groups: vec!["wheel".into(), "corner".into()],
            },
            crate::install::state::UserAccount {
                name: "guest".into(),
                password_hash: None,
                dotfiles: None,
                groups: vec!["networkmanager".into()],
            },
        ];
        prepare_generated(&dir, &state).unwrap();

        let user = fs::read_to_string(dir.join("host/generated/user.nix")).unwrap();
        // primary group override + password path
        assert!(user.contains("users.users.\"bresilla\".extraGroups = lib.mkForce [ \"wheel\" \"corner\" ]"));
        assert!(user.contains("passwd-bresilla.hash"));
        // additional user with its own groups
        assert!(user.contains("users.users.\"guest\" = {"));
        assert!(user.contains("extraGroups = [ \"networkmanager\" ]"));
        // guest has no password → no hashedPasswordFile line for guest
        assert!(!user.contains("passwd-guest.hash"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn generated_user_file_leaves_password_null_by_default() {
        let dir = temp_dir("generated-nopass");
        fs::create_dir_all(&dir).unwrap();
        prepare_generated(&dir, &InstallState::sample()).unwrap();

        let user = fs::read_to_string(dir.join("host/generated/user.nix")).unwrap();
        assert!(user.contains("bresilla.user.hashedPasswordFile = lib.mkDefault null;"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn generated_user_file_can_leave_ssh_disabled() {
        let dir = temp_dir("generated-no-ssh");
        fs::create_dir_all(&dir).unwrap();
        let mut state = InstallState::sample();
        state.allow_ssh = false;
        prepare_generated(&dir, &state).unwrap();

        let user = fs::read_to_string(dir.join("host/generated/user.nix")).unwrap();
        assert!(user.contains("bresilla.features.system.ssh.enable = lib.mkDefault false;"));
        fs::remove_dir_all(dir).unwrap();
    }


    #[test]
    fn extracts_github_token_from_decrypted_yaml() {
        let token = github_token_from_yaml(
            br#"
github:
  token: "ghp_example"
"#,
        )
        .unwrap();

        assert_eq!(token, "ghp_example");
    }

    #[test]
    fn confirmed_remote_install_prepares_selected_disks() {
        let state = InstallState::sample();

        let results =
            prepare_confirmed_remote_disks_with_runner(&state, fake_disk_prepare).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, 0);
    }

    #[test]
    fn confirmed_remote_install_transfers_generated_before_disk_prepare() {
        let state = InstallState::sample();
        let events = RefCell::new(Vec::new());

        let results = prepare_confirmed_remote_with_runner(
            &state,
            || {
                events.borrow_mut().push("transfer".to_string());
                Ok(vec![TransferredArtifact {
                    local_path: PathBuf::from("/repo/generated/disko.nix"),
                    remote_path: "/tmp/nx-generated/disko.nix".to_string(),
                    bytes_written: 5,
                }])
            },
            |remote, disk| {
                events.borrow_mut().push(format!("prepare {disk}"));
                fake_disk_prepare(remote, disk)
            },
        )
        .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(
            events.into_inner(),
            vec!["transfer".to_string(), "prepare /dev/nvme0n1".to_string()]
        );
    }

    #[test]
    fn confirmed_local_install_does_not_prepare_remote_disks() {
        let mut state = InstallState::sample();
        state.scope = InstallScope::Local;

        let results =
            prepare_confirmed_remote_disks_with_runner(&state, panic_disk_prepare).unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn confirmed_local_install_skips_remote_transfer_and_disk_prepare() {
        let mut state = InstallState::sample();
        state.scope = InstallScope::Local;

        let results = prepare_confirmed_remote_with_runner(
            &state,
            || panic!("local install should not transfer generated files"),
            panic_disk_prepare,
        )
        .unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn confirmed_remote_install_fails_when_disk_prepare_fails() {
        let state = InstallState::sample();

        let err =
            prepare_confirmed_remote_disks_with_runner(&state, failing_disk_prepare).unwrap_err();

        assert!(err.contains("failed to prepare /dev/nvme0n1"));
        assert!(err.contains("wipe failed"));
    }

    #[test]
    fn confirmed_remote_policy_allows_every_planned_destructive_step() {
        let state = InstallState::sample();
        let steps = crate::install::plan::plan_remote_install_steps(&state, "/tmp/nx-source").unwrap();
        let destructive_steps = steps.iter().filter(|step| step.destructive).count();
        let policy = confirmed_remote_policy(&steps);

        assert_eq!(policy.destructive_steps_allowed, destructive_steps);
        assert!(policy.destructive_steps_allowed > 0);
    }

    fn temp_dir(name: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("nox-install-{name}-{}-{now}", std::process::id()))
    }

    fn fake_disk_prepare(remote: &str, disk: &str) -> Result<DiskPrepareResult, String> {
        assert_eq!(remote, "nixos@10.10.10.7");
        assert_eq!(disk, "/dev/nvme0n1");
        Ok(DiskPrepareResult {
            status: 0,
            stdout: "prepared".to_string(),
            stderr: String::new(),
        })
    }

    fn failing_disk_prepare(_: &str, _: &str) -> Result<DiskPrepareResult, String> {
        Ok(DiskPrepareResult {
            status: 1,
            stdout: String::new(),
            stderr: "wipe failed".to_string(),
        })
    }

    fn panic_disk_prepare(_: &str, _: &str) -> Result<DiskPrepareResult, String> {
        panic!("local install should not prepare remote disks")
    }
}
