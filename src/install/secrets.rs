use std::path::Path;

use crate::Result;
use crate::{sops::metadata::SopsMetadata, yubikey_probe};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretCheck {
    pub ok: bool,
    pub detail: String,
}

/// Hash a plaintext login password to sha512-crypt (`$6$…`), the standard
/// crypt(3) format NixOS accepts in `hashedPasswordFile`. Pure Rust — no
/// external `mkpasswd` needed, so it works on any machine the TUI runs on.
pub fn hash_password(password: &str) -> Result<String> {
    if password.is_empty() {
        return Err("password is empty".to_string());
    }
    let params = sha_crypt::Sha512Params::new(sha_crypt::ROUNDS_DEFAULT)
        .map_err(|err| format!("bad sha512-crypt parameters: {err:?}"))?;
    sha_crypt::sha512_simple(password, &params)
        .map_err(|err| format!("failed to hash password: {err:?}"))
}

pub fn check(repo: &Path) -> SecretCheck {
    match check_inner(repo) {
        Ok(detail) => SecretCheck { ok: true, detail },
        Err(detail) => SecretCheck { ok: false, detail },
    }
}

/// The mode-aware check the installer uses: YubiKey (default), a plaintext
/// age identity file, or the deliberate choice to install without secrets.
pub fn check_with_mode(
    repo: &Path,
    mode: &crate::install::state::SecretsMode,
) -> SecretCheck {
    use crate::install::state::SecretsMode;
    match mode {
        SecretsMode::YubiKey => check(repo),
        SecretsMode::KeyFile(path) => match check_age_key_file(repo, Path::new(path)) {
            Ok(detail) => SecretCheck { ok: true, detail },
            Err(detail) => SecretCheck { ok: false, detail },
        },
        SecretsMode::Skip => SecretCheck {
            ok: true,
            detail: "skipped by choice — installing without secrets (target gets \
                     bresilla.secrets.enable = false)"
                .to_string(),
        },
    }
}

/// Validate a plaintext age identity file: it must parse, and one of its
/// derived recipients must be among `secrets/system.yaml`'s recipients.
fn check_age_key_file(repo: &Path, key_file: &Path) -> Result<String> {
    require_file(key_file)?;
    require_file(repo.join("host/.sops.yaml").as_path())?;
    let system = repo.join("host/secrets/system.yaml");
    require_file(&system)?;
    let metadata = SopsMetadata::load(&system)?;

    let content = std::fs::read_to_string(key_file)
        .map_err(|err| format!("failed to read {}: {err}", key_file.display()))?;
    let mut derived = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let identity: age::x25519::Identity = line
            .parse()
            .map_err(|err| format!("{} is not an age identity file: {err}", key_file.display()))?;
        derived.push(identity.to_public().to_string());
    }
    if derived.is_empty() {
        return Err(format!(
            "{} holds no AGE-SECRET-KEY entries",
            key_file.display()
        ));
    }
    if !derived
        .iter()
        .any(|recipient| metadata.recipients().contains(recipient))
    {
        return Err(format!(
            "{} does not match any secrets/system.yaml recipient",
            key_file.display()
        ));
    }
    Ok(format!("age key file {} matches system.yaml", key_file.display()))
}

fn check_inner(repo: &Path) -> Result<String> {
    require_file(repo.join("host/.sops.yaml").as_path())?;
    require_file(repo.join("host/secrets/key.txt").as_path())?;
    let system = repo.join("host/secrets/system.yaml");
    require_file(&system)?;

    let metadata = SopsMetadata::load(&system)?;
    let recipients = yubikey_probe::recipients()?;
    let connected = recipients
        .recipients
        .iter()
        .flat_map(|recipient| recipient.all_recipients())
        .any(|recipient| metadata.recipients().contains(recipient));
    if !connected {
        return Err("connected YubiKey does not match secrets/system.yaml recipients".to_string());
    }

    let data_key = crate::sops::data_key::decrypt_first(&metadata, &recipients)?;
    let report = crate::sops::values::check_file(&system, &data_key)?;
    Ok(format!(
        "system.yaml decrypted={}/{} mac_decrypted={} mac_matches={}",
        report.decrypted_values, report.encrypted_values, report.mac_decrypted, report.mac_matches
    ))
}

fn require_file(path: &Path) -> Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("missing required secret file: {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{check, hash_password};

    #[test]
    fn missing_repo_secret_files_fail_cleanly() {
        let result = check(Path::new("/definitely/missing/nox-secrets"));
        assert!(!result.ok);
        assert!(result.detail.contains("missing required secret file"));
    }

    #[test]
    fn hashes_passwords_in_process_to_sha512_crypt() {
        let hash = hash_password("hunter2").unwrap();
        // crypt(3) sha512 format: $6$<salt>$<hash>, no external tools involved.
        assert!(hash.starts_with("$6$"), "got: {hash}");
        assert!(sha_crypt::sha512_check("hunter2", &hash).is_ok());
        assert!(sha_crypt::sha512_check("wrong", &hash).is_err());
        assert!(hash_password("").is_err());
    }
}
