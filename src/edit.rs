use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{exec_status, sops::config::SopsConfig, sops::metadata::SopsMetadata, ui, Result};
use crate::yubikey_probe;

pub fn dispatch(repo: &Path) -> Result<u8> {
    let target = ui::select(
        "edit target",
        &[
            "package", "service", "profile", "specific", "user", "accounts", "features", "common",
            "secrets", "flake",
        ],
    )?;

    match target.as_str() {
        "package" => edit_nix_file_from_dir(repo, "package group", &repo.join("host/modules/programms")),
        "service" => edit_nix_file_from_dir(repo, "service module", &repo.join("host/modules/services")),
        "profile" => edit_nix_file_from_dir(repo, "profile", &repo.join("host/modules/profiles")),
        "specific" => {
            ensure_specific(repo)?;
            edit_file(Some(repo), &repo.join("host/specific/configuration.nix"))
        }
        "user" => edit_user_config(),
        "accounts" => edit_file(Some(repo), &repo.join("host/modules/accounts.nix")),
        "features" => edit_file(Some(repo), &repo.join("host/modules/features.nix")),
        "common" => edit_file(Some(repo), &repo.join("host/modules/common.nix")),
        "secrets" => edit_secret(repo),
        "flake" => edit_file(Some(repo), &repo.join("host/flake.nix")),
        other => Err(format!("unknown edit target: {other}")),
    }
}

fn edit_nix_file_from_dir(repo: &Path, title: &str, dir: &Path) -> Result<u8> {
    let files = nix_files_in_dir(dir)?;
    let choices = files
        .iter()
        .map(|file| {
            file.file_stem()
                .and_then(|stem| stem.to_str())
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("invalid Nix filename: {}", file.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    let refs = choices.iter().map(String::as_str).collect::<Vec<_>>();
    let selected = ui::select(title, &refs)?;
    let selected_index = choices
        .iter()
        .position(|choice| choice == &selected)
        .ok_or_else(|| format!("unknown selection: {selected}"))?;
    edit_file(Some(repo), &files[selected_index])
}

fn nix_files_in_dir(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_nix_files(dir, &mut files)?;
    files.sort_by(|left, right| {
        left.strip_prefix(dir)
            .unwrap_or(left)
            .cmp(right.strip_prefix(dir).unwrap_or(right))
    });
    if files.is_empty() {
        return Err(format!("no .nix files found in {}", dir.display()));
    }
    Ok(files)
}

fn collect_nix_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Err(format!("missing directory: {}", dir.display()));
    }
    for entry in
        fs::read_dir(dir).map_err(|err| format!("failed to read {}: {err}", dir.display()))?
    {
        let entry = entry.map_err(|err| format!("failed to read directory entry: {err}"))?;
        let path = entry.path();
        if path.is_dir() {
            collect_nix_files(&path, files)?;
        } else if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("nix") {
            files.push(path);
        }
    }
    Ok(())
}

fn edit_file(repo: Option<&Path>, file: &Path) -> Result<u8> {
    if !file.is_file() {
        return Err(format!("missing file: {}", file.display()));
    }
    if is_sops_file(file)? {
        let repo = repo.ok_or_else(|| {
            format!(
                "SOPS file {} needs a repo context for .sops.yaml",
                file.display()
            )
        })?;
        return edit_sops_file(repo, file);
    }
    exec_status(Command::new(editor()).arg(file))
}

fn edit_secret(repo: &Path) -> Result<u8> {
    let mut choices = vec!["module".to_string()];
    choices.extend(secret_files(repo)?.into_iter().map(|path| {
        path.strip_prefix(repo)
            .unwrap_or(&path)
            .display()
            .to_string()
    }));

    let refs: Vec<&str> = choices.iter().map(String::as_str).collect();
    let selected = ui::select("secret file", &refs)?;
    if selected == "module" {
        return edit_file(Some(repo), &repo.join("host/modules/secrets.nix"));
    }
    edit_file(Some(repo), &repo.join(selected))
}

fn secret_files(repo: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_secret_files(&repo.join("host/secrets"), &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_secret_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in
        fs::read_dir(dir).map_err(|err| format!("failed to read {}: {err}", dir.display()))?
    {
        let entry = entry.map_err(|err| format!("failed to read directory entry: {err}"))?;
        let path = entry.path();
        if path.is_dir() {
            collect_secret_files(&path, files)?;
        } else if path.is_file() && is_sops_file(&path)? {
            files.push(path);
        }
    }
    Ok(())
}

fn is_sops_file(file: &Path) -> Result<bool> {
    let content = fs::read_to_string(file)
        .map_err(|err| format!("failed to read {}: {err}", file.display()))?;
    Ok(is_sops_content(&content))
}

fn is_sops_content(content: &str) -> bool {
    content.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed == "sops:" || trimmed.starts_with("sops =") || trimmed.starts_with("\"sops\":")
    })
}

fn edit_sops_file(repo: &Path, file: &Path) -> Result<u8> {
    if env::var_os("EDITOR").is_none() {
        return Err(
            "EDITOR is not set. Install an editor and export EDITOR, for example: export EDITOR=nvim"
                .to_string(),
        );
    }

    verify_sops_config(repo, file)?;

    // With the YubiKey feature, decrypt/edit/re-encrypt YAML SOPS files natively.
    // Without it (the portable installer build), fall through to external `sops`.
    if is_yaml_file(file) {
        let metadata = SopsMetadata::load(file)?;
        let report = verify_yubikey_recipient(&metadata, file)?;
        let data_key = crate::sops::data_key::decrypt_first(&metadata, &report)?;
        return crate::sops::edit::edit_yaml_file(file, &data_key, editor());
    }

    need_command("sops", "sops")?;
    need_command("age-plugin-yubikey", "age-plugin-yubikey")?;

    let mut command = Command::new("sops");
    command.env(
        "SOPS_AGE_KEY_CMD",
        env::var("SOPS_AGE_KEY_CMD")
            .unwrap_or_else(|_| "age-plugin-yubikey --identity".to_string()),
    );
    command.arg(file);
    exec_status(&mut command)
}

fn verify_yubikey_recipient(
    metadata: &SopsMetadata,
    file: &Path,
) -> Result<yubikey_probe::RecipientReport> {
    let encrypted_recipients = metadata.recipients();
    let report = yubikey_probe::recipients()?;
    if report.recipients.is_empty() {
        return Err("no age-compatible YubiKey recipients found in retired PIV slots".to_string());
    }

    let mut connected = BTreeSet::new();
    for recipient in &report.recipients {
        for value in recipient.all_recipients() {
            connected.insert(value.to_string());
        }
    }

    if connected
        .iter()
        .any(|recipient| encrypted_recipients.contains(recipient))
    {
        for recipient in &report.recipients {
            eprintln!(
                "YubiKey: serial {} slot {}",
                recipient.serial, recipient.slot
            );
        }
        return Ok(report);
    }

    Err(format!(
        "inserted YubiKey does not match any recipient in {}\nconnected: {}\nfile: {}",
        file.display(),
        connected.into_iter().collect::<Vec<_>>().join(", "),
        encrypted_recipients
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

fn is_yaml_file(file: &Path) -> bool {
    matches!(
        file.extension().and_then(|extension| extension.to_str()),
        Some("yaml" | "yml")
    )
}

fn verify_sops_config(repo: &Path, file: &Path) -> Result<()> {
    let config = SopsConfig::load(repo)?;
    let rule = config.match_file(repo, file)?;
    let metadata = SopsMetadata::load(file)?;
    let file_recipients = metadata.recipients();
    let missing = rule
        .recipients
        .difference(file_recipients)
        .cloned()
        .collect::<Vec<_>>();

    if missing.is_empty() {
        eprintln!(".sops.yaml: matched {}", rule.path_regex);
        return Ok(());
    }

    Err(format!(
        "{} is missing recipient(s) from .sops.yaml rule '{}': {}",
        file.display(),
        rule.path_regex,
        missing.join(", ")
    ))
}

fn need_command(command: &str, package: &str) -> Result<()> {
    if command_exists(command) {
        Ok(())
    } else {
        Err(format!(
            "missing command '{command}'. Install package: {package}"
        ))
    }
}

fn command_exists(command: &str) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path).any(|dir| dir.join(command).is_file())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{is_sops_content, nix_files_in_dir};

    #[test]
    fn detects_yaml_sops_metadata() {
        assert!(is_sops_content(
            "hello: ENC[AES256_GCM,data]\nsops:\n  age: []\n"
        ));
    }

    #[test]
    fn ignores_plain_files() {
        assert!(!is_sops_content("{ ... }:\n\n{}\n"));
    }

    #[test]
    fn discovers_nix_files_recursively_and_sorted() {
        let dir = temp_dir("discover");
        fs::create_dir_all(dir.join("nested")).unwrap();
        fs::write(dir.join("zeta.nix"), "{}\n").unwrap();
        fs::write(dir.join("alpha.txt"), "ignore\n").unwrap();
        fs::write(dir.join("nested").join("beta.nix"), "{}\n").unwrap();

        let files = nix_files_in_dir(&dir).unwrap();
        let relative = files
            .iter()
            .map(|file| {
                file.strip_prefix(&dir)
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect::<Vec<_>>();

        assert_eq!(relative, vec!["nested/beta.nix", "zeta.nix"]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_empty_nix_file_directory() {
        let dir = temp_dir("empty");
        fs::create_dir_all(&dir).unwrap();
        let err = nix_files_in_dir(&dir).unwrap_err();
        assert!(err.contains("no .nix files found"));
        fs::remove_dir_all(dir).unwrap();
    }

    fn temp_dir(name: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("nox-edit-{name}-{}-{now}", std::process::id()))
    }
}

fn edit_user_config() -> Result<u8> {
    let dir = env::var_os("NX_USER_CONFIG_DIR")
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|home| home.join(".nix")))
        .ok_or_else(|| "could not determine user config directory".to_string())?;
    let file = dir.join("configuration.nix");
    fs::create_dir_all(&dir).map_err(|err| format!("failed to create {}: {err}", dir.display()))?;
    if !file.exists() {
        fs::write(
            &file,
            "{ ... }:\n\n{\n  # User-specific local config goes here.\n}\n",
        )
        .map_err(|err| format!("failed to write {}: {err}", file.display()))?;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644))
            .map_err(|err| format!("failed to chmod {}: {err}", file.display()))?;
    }
    edit_file(None, &file)
}

fn ensure_specific(repo: &Path) -> Result<()> {
    let dir = repo.join("host/specific");
    let file = dir.join("configuration.nix");
    fs::create_dir_all(&dir).map_err(|err| format!("failed to create {}: {err}", dir.display()))?;
    if !file.exists() {
        fs::write(
            &file,
            "{ ... }:\n\n{\n  # Host-specific local overrides go here.\n}\n",
        )
        .map_err(|err| format!("failed to write {}: {err}", file.display()))?;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o664))
            .map_err(|err| format!("failed to chmod {}: {err}", file.display()))?;
    }
    Ok(())
}

fn editor() -> OsString {
    env::var_os("EDITOR")
        .or_else(|| env::var_os("VISUAL"))
        .unwrap_or_else(|| OsString::from("vi"))
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}
