use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::{exec_status, Result};

#[derive(Debug, Clone)]
pub struct Options {
    pub role: Option<String>,
    pub check_only: bool,
}

pub fn dispatch(repo: &Path, options: Options) -> Result<u8> {
    let options = options.resolve(repo)?;
    ensure_specific(repo)?;

    if options.check_only {
        check(repo, &options.role)
    } else {
        switch(repo, &options.role)
    }
}

struct ResolvedOptions {
    role: String,
    check_only: bool,
}

impl Options {
    fn resolve(self, repo: &Path) -> Result<ResolvedOptions> {
        let role = self
            .role
            .or_else(|| std::env::var("NIXOS_ROLE").ok())
            .or_else(|| read_role_file(repo))
            .unwrap_or_else(|| "laptop".to_string());
        validate_role(&role)?;

        Ok(ResolvedOptions {
            role,
            check_only: self.check_only,
        })
    }
}

fn read_role_file(repo: &Path) -> Option<String> {
    fs::read_to_string(repo.join("host/.nixos-role"))
        .ok()
        .map(|role| role.trim().to_string())
        .filter(|role| !role.is_empty())
}

fn validate_role(role: &str) -> Result<()> {
    match role {
        "laptop" | "server" => Ok(()),
        _ => Err("role must be laptop or server".to_string()),
    }
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

fn check(repo: &Path, role: &str) -> Result<u8> {
    let attr = format!(
        "path:{}/host#nixosConfigurations.install-{role}-generated.config.system.stateVersion",
        repo.display()
    );
    let mut command = Command::new("nix");
    command
        .current_dir(repo)
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "eval",
            "--impure",
            "--no-warn-dirty",
        ])
        .arg(attr)
        .stdout(Stdio::null());
    let status = exec_status(&mut command)?;
    if status == 0 {
        println!("check: ok");
    }
    Ok(status)
}

fn switch(repo: &Path, role: &str) -> Result<u8> {
    let flake_ref = format!("path:{}/host#install-{role}-generated", repo.display());
    let mut command = Command::new("sudo");
    command
        .current_dir(repo)
        .arg("nixos-rebuild")
        .arg("switch")
        .arg("--flake")
        .arg(flake_ref);
    exec_status(&mut command)
}

#[cfg(test)]
mod tests {
    use super::{ensure_specific, read_role_file, validate_role};
    use std::fs;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nx-generate-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn accepts_only_known_roles() {
        assert!(validate_role("laptop").is_ok());
        assert!(validate_role("server").is_ok());
        assert!(validate_role("desktop").is_err());
    }

    #[test]
    fn reads_and_trims_role_file() {
        let dir = temp_dir("role");
        fs::create_dir_all(dir.join("host")).unwrap();
        fs::write(dir.join("host/.nixos-role"), "  server\n").unwrap();
        assert_eq!(read_role_file(&dir).as_deref(), Some("server"));
        fs::write(dir.join("host/.nixos-role"), "  \n").unwrap();
        assert_eq!(read_role_file(&dir), None);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ensure_specific_creates_placeholder_once() {
        let dir = temp_dir("specific");
        ensure_specific(&dir).unwrap();
        let file = dir.join("host/specific/configuration.nix");
        assert!(file.is_file());
        // Re-running must not clobber existing user content.
        fs::write(&file, "{ ... }: { custom = true; }\n").unwrap();
        ensure_specific(&dir).unwrap();
        assert!(fs::read_to_string(&file).unwrap().contains("custom = true"));
        fs::remove_dir_all(dir).unwrap();
    }
}
