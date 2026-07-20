use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrappedAgent {
    pub store_path: PathBuf,
    pub binary: PathBuf,
}

pub fn bootstrap_with_progress(
    repo: &Path,
    remote: &str,
    mut progress: impl FnMut(&str),
) -> Result<BootstrappedAgent> {
    progress("building local nox agent with Nix");
    let store_path = build(repo)?;
    progress("copying nox Nix closure to target");
    copy(remote, &store_path)?;
    progress("remote nox agent is ready");
    Ok(BootstrappedAgent {
        binary: store_path.join("bin/nox"),
        store_path,
    })
}

pub fn build(repo: &Path) -> Result<PathBuf> {
    let _ = repo;
    let output = Command::new("nix")
        .arg("--extra-experimental-features")
        .arg("nix-command flakes")
        .arg("build")
        .arg(format!("{}#nox", nox_flake_ref()))
        .arg("--no-link")
        .arg("--print-out-paths")
        .output()
        .map_err(|err| format!("failed to run nix build: {err}"))?;

    if !output.status.success() {
        return Err(command_error("nix build", &output));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let path = stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| "nix build did not print a store path".to_string())?;

    Ok(PathBuf::from(path))
}

pub fn copy(remote: &str, store_path: &Path) -> Result<()> {
    if remote.trim().is_empty() {
        return Err("remote target is empty".to_string());
    }
    let output = Command::new("nix")
        .arg("--extra-experimental-features")
        .arg("nix-command flakes")
        .arg("copy")
        .arg("--to")
        .arg(format!("ssh://{}", remote.trim()))
        .arg(store_path)
        .output()
        .map_err(|err| format!("failed to run nix copy: {err}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(command_error("nix copy", &output))
    }
}

/// Where the agent binary is built from: the published nox flake by default,
/// or `NOX_FLAKE` (e.g. `path:/home/me/nox`) for local development so the
/// agent matches the checkout being worked on.
fn nox_flake_ref() -> String {
    std::env::var("NOX_FLAKE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "github:bresilla/nox".to_string())
}

fn command_error(name: &str, output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    if detail.is_empty() {
        format!("{name} exited with {}", output.status)
    } else {
        format!("{name} exited with {}: {detail}", output.status)
    }
}

#[cfg(test)]
mod tests {
    use super::nox_flake_ref;

    #[test]
    fn agent_builds_from_the_nox_flake_with_env_override() {
        // Serialized by env-var scoping: read default, then override.
        std::env::remove_var("NOX_FLAKE");
        assert_eq!(nox_flake_ref(), "github:bresilla/nox");
        std::env::set_var("NOX_FLAKE", "path:/home/me/nox");
        assert_eq!(nox_flake_ref(), "path:/home/me/nox");
        std::env::remove_var("NOX_FLAKE");
    }
}
