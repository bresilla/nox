use std::fs;
use std::path::{Path, PathBuf};

use crate::agent::FileWriteResult;
use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedArtifact {
    pub local_path: PathBuf,
    pub remote_path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferredArtifact {
    pub local_path: PathBuf,
    pub remote_path: String,
    pub bytes_written: u64,
}

#[allow(dead_code)]
pub fn transfer_generated(
    remote: &str,
    agent_binary: &str,
    repo: &Path,
    remote_dir: &str,
) -> Result<Vec<TransferredArtifact>> {
    let artifacts = load_generated(repo, remote_dir)?;
    transfer_artifacts_with_writer(&artifacts, |path, bytes| {
        crate::agent::client::write_file(remote, agent_binary, path, bytes, Some(0o644), true)
    })
}

pub fn transfer_generated_with_writer(
    repo: &Path,
    remote_dir: &str,
    writer: impl FnMut(&str, &[u8]) -> Result<FileWriteResult>,
) -> Result<Vec<TransferredArtifact>> {
    let artifacts = load_generated(repo, remote_dir)?;
    transfer_artifacts_with_writer(&artifacts, writer)
}

pub fn transfer_flake_source_with_writer(
    repo: &Path,
    remote_dir: &str,
    writer: impl FnMut(&str, &[u8]) -> Result<FileWriteResult>,
) -> Result<Vec<TransferredArtifact>> {
    let artifacts = load_flake_source(repo, remote_dir)?;
    transfer_artifacts_with_writer(&artifacts, writer)
}

fn load_generated(repo: &Path, remote_dir: &str) -> Result<Vec<GeneratedArtifact>> {
    validate_remote_dir(remote_dir)?;
    generated_files()
        .into_iter()
        .map(|name| {
            let local_path = repo.join("host/generated").join(name);
            let bytes = fs::read(&local_path)
                .map_err(|err| format!("failed to read {}: {err}", local_path.display()))?;
            Ok(GeneratedArtifact {
                local_path,
                remote_path: remote_join(remote_dir, name),
                bytes,
            })
        })
        .collect()
}

fn load_flake_source(repo: &Path, remote_dir: &str) -> Result<Vec<GeneratedArtifact>> {
    validate_remote_dir(remote_dir)?;
    let mut artifacts = Vec::new();
    // When a self-contained `secrets-test/` fixture exists, overlay it onto
    // `secrets/` in the transferred source so the target (and its sops-nix config)
    // uses the test key and test secrets instead of the YubiKey-locked real ones.
    let use_test_secrets = repo.join("host/secrets-test").is_dir();
    for root in flake_source_roots() {
        if root == "host/secrets" && use_test_secrets {
            collect_test_secrets_overlay(repo, remote_dir, &mut artifacts)?;
            continue;
        }
        let path = repo.join(root);
        if !path.exists() {
            continue;
        }
        collect_source_files(repo, &path, remote_dir, &mut artifacts)?;
    }
    artifacts.sort_by(|left, right| left.remote_path.cmp(&right.remote_path));
    Ok(artifacts)
}

fn collect_test_secrets_overlay(
    repo: &Path,
    remote_dir: &str,
    artifacts: &mut Vec<GeneratedArtifact>,
) -> Result<()> {
    let mut overlay = Vec::new();
    collect_source_files(repo, &repo.join("host/secrets-test"), remote_dir, &mut overlay)?;

    let from_prefix = remote_join(remote_dir, "host/secrets-test");
    let to_prefix = remote_join(remote_dir, "host/secrets");
    for mut artifact in overlay {
        if let Some(rest) = artifact.remote_path.strip_prefix(&from_prefix) {
            artifact.remote_path = format!("{to_prefix}{rest}");
        }
        // Never ship the plaintext age key inside the source; the shared system
        // key is placed separately via the secret-file-write step.
        if artifact.remote_path.ends_with("/host/secrets/key.txt") {
            continue;
        }
        artifacts.push(artifact);
    }
    Ok(())
}

fn collect_source_files(
    repo: &Path,
    path: &Path,
    remote_dir: &str,
    artifacts: &mut Vec<GeneratedArtifact>,
) -> Result<()> {
    let relative = path
        .strip_prefix(repo)
        .map_err(|err| format!("failed to relativize {}: {err}", path.display()))?;
    if should_skip_source_path(relative) {
        return Ok(());
    }

    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing to transfer symlink in flake source: {}",
            path.display()
        ));
    }
    if metadata.is_dir() {
        let mut entries = fs::read_dir(path)
            .map_err(|err| format!("failed to read directory {}: {err}", path.display()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|err| {
                format!(
                    "failed to read directory entry in {}: {err}",
                    path.display()
                )
            })?;
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            collect_source_files(repo, &entry.path(), remote_dir, artifacts)?;
        }
        return Ok(());
    }
    if !metadata.is_file() {
        return Ok(());
    }

    let bytes =
        fs::read(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let relative_path = relative
        .to_str()
        .ok_or_else(|| format!("source path is not valid UTF-8: {}", relative.display()))?;
    artifacts.push(GeneratedArtifact {
        local_path: path.to_path_buf(),
        remote_path: remote_join(remote_dir, relative_path),
        bytes,
    });
    Ok(())
}

fn transfer_artifacts_with_writer(
    artifacts: &[GeneratedArtifact],
    mut writer: impl FnMut(&str, &[u8]) -> Result<FileWriteResult>,
) -> Result<Vec<TransferredArtifact>> {
    artifacts
        .iter()
        .map(|artifact| {
            let result = writer(&artifact.remote_path, &artifact.bytes)?;
            Ok(TransferredArtifact {
                local_path: artifact.local_path.clone(),
                remote_path: result.path,
                bytes_written: result.bytes_written,
            })
        })
        .collect()
}

fn generated_files() -> [&'static str; 4] {
    ["disko.nix", "host.nix", "user.nix", "storage-plan.json"]
}

fn flake_source_roots() -> [&'static str; 7] {
    [
        "host/flake.nix",
        "host/flake.lock",
        "host/modules",
        "host/generated",
        "host/secrets",
        "host/specific",
        "host/.sops.yaml",
    ]
}

fn should_skip_source_path(relative: &Path) -> bool {
    if relative == Path::new("host/secrets/key.txt") {
        return true;
    }

    relative.components().any(|component| {
        let text = component.as_os_str().to_string_lossy();
        matches!(
            text.as_ref(),
            ".git"
                | ".agents"
                | ".codex"
                | ".cloudflare"
                | "target"
                | "result"
                | "result-bin"
                | ".direnv"
        )
    })
}

fn validate_remote_dir(remote_dir: &str) -> Result<()> {
    if remote_dir.is_empty() {
        return Err("remote generated directory is empty".to_string());
    }
    if !remote_dir.starts_with('/') {
        return Err(format!(
            "remote generated directory must be absolute: {remote_dir}"
        ));
    }
    if remote_dir.contains('\0') {
        return Err("remote generated directory contains invalid NUL byte".to_string());
    }
    Ok(())
}

fn remote_join(remote_dir: &str, file: &str) -> String {
    let file = file.trim_start_matches('/');
    format!("{}/{}", remote_dir.trim_end_matches('/'), file)
}

#[cfg(test)]
mod tests {
    use super::{load_flake_source, load_generated, transfer_artifacts_with_writer};
    use crate::agent::FileWriteResult;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn loads_generated_files_for_remote_directory() {
        let dir = temp_dir("load");
        let generated = dir.join("host/generated");
        fs::create_dir_all(&generated).unwrap();
        fs::write(generated.join("disko.nix"), "disko").unwrap();
        fs::write(generated.join("host.nix"), "host").unwrap();
        fs::write(generated.join("user.nix"), "user").unwrap();
        fs::write(generated.join("storage-plan.json"), "{}").unwrap();

        let artifacts = load_generated(&dir, "/tmp/nx-generated").unwrap();

        assert_eq!(artifacts.len(), 4);
        assert_eq!(artifacts[0].remote_path, "/tmp/nx-generated/disko.nix");
        assert_eq!(artifacts[1].bytes, b"host");
        assert_eq!(
            artifacts[3].remote_path,
            "/tmp/nx-generated/storage-plan.json"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_relative_remote_directory() {
        let err = load_generated(&PathBuf::from("/tmp/repo"), "tmp/generated").unwrap_err();

        assert!(err.contains("must be absolute"));
    }

    #[test]
    fn transfers_loaded_artifacts_with_writer() {
        let artifacts = vec![super::GeneratedArtifact {
            local_path: PathBuf::from("/repo/generated/host.nix"),
            remote_path: "/tmp/generated/host.nix".to_string(),
            bytes: b"host".to_vec(),
        }];

        let transferred = transfer_artifacts_with_writer(&artifacts, |path, bytes| {
            assert_eq!(path, "/tmp/generated/host.nix");
            assert_eq!(bytes, b"host");
            Ok(FileWriteResult {
                path: path.to_string(),
                bytes_written: bytes.len() as u64,
            })
        })
        .unwrap();

        assert_eq!(transferred[0].remote_path, "/tmp/generated/host.nix");
        assert_eq!(transferred[0].bytes_written, 4);
    }

    #[test]
    fn loads_minimal_flake_source_without_build_outputs() {
        let dir = temp_dir("source");
        fs::create_dir_all(dir.join("host")).unwrap();
        fs::write(dir.join("host/flake.nix"), "flake").unwrap();
        fs::write(dir.join("host/flake.lock"), "lock").unwrap();
        fs::create_dir_all(dir.join("host/modules/programms")).unwrap();
        fs::write(dir.join("host/modules/programms/system.nix"), "system").unwrap();
        fs::create_dir_all(dir.join("host/generated")).unwrap();
        fs::write(dir.join("host/generated/disko.nix"), "disko").unwrap();
        fs::write(dir.join("host/generated/storage-plan.json"), "{}").unwrap();
        fs::create_dir_all(dir.join("host/secrets")).unwrap();
        fs::write(dir.join("host/secrets/key.txt"), "secret").unwrap();
        fs::write(dir.join("host/secrets/system.yaml"), "encrypted").unwrap();
        fs::create_dir_all(dir.join("target/debug")).unwrap();
        fs::write(dir.join("target/debug/huge"), "no").unwrap();

        let artifacts = load_flake_source(&dir, "/tmp/nx-source").unwrap();
        let remote_paths = artifacts
            .iter()
            .map(|artifact| artifact.remote_path.as_str())
            .collect::<Vec<_>>();

        assert!(remote_paths.contains(&"/tmp/nx-source/host/flake.nix"));
        assert!(remote_paths.contains(&"/tmp/nx-source/host/generated/disko.nix"));
        assert!(remote_paths.contains(&"/tmp/nx-source/host/generated/storage-plan.json"));
        assert!(remote_paths.contains(&"/tmp/nx-source/host/modules/programms/system.nix"));
        assert!(remote_paths.contains(&"/tmp/nx-source/host/secrets/system.yaml"));
        assert!(!remote_paths.contains(&"/tmp/nx-source/host/secrets/key.txt"));
        assert!(!remote_paths.iter().any(|path| path.contains("target")));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn overlays_test_secrets_onto_real_secrets_paths() {
        let dir = temp_dir("overlay");
        fs::create_dir_all(dir.join("host/secrets/common")).unwrap();
        fs::write(dir.join("host/flake.nix"), "flake").unwrap();
        fs::write(dir.join("host/secrets/key.txt"), "real-key").unwrap();
        fs::write(dir.join("host/secrets/system.yaml"), "REAL-SYSTEM").unwrap();
        fs::write(dir.join("host/secrets/common/github.yaml"), "REAL-GITHUB").unwrap();

        fs::create_dir_all(dir.join("host/secrets-test/common")).unwrap();
        fs::write(dir.join("host/secrets-test/key.txt"), "test-key").unwrap();
        fs::write(dir.join("host/secrets-test/system.yaml"), "TEST-SYSTEM").unwrap();
        fs::write(dir.join("host/secrets-test/common/github.yaml"), "TEST-GITHUB").unwrap();
        fs::write(dir.join("host/secrets-test/common/hosts"), "TEST-HOSTS").unwrap();

        let artifacts = load_flake_source(&dir, "/tmp/nx-source").unwrap();
        let by_path = |p: &str| artifacts.iter().find(|a| a.remote_path == p);

        // Test secrets are mapped onto secrets/ paths...
        assert_eq!(
            by_path("/tmp/nx-source/host/secrets/system.yaml").unwrap().bytes,
            b"TEST-SYSTEM"
        );
        assert_eq!(
            by_path("/tmp/nx-source/host/secrets/common/github.yaml")
                .unwrap()
                .bytes,
            b"TEST-GITHUB"
        );
        assert!(by_path("/tmp/nx-source/host/secrets/common/hosts").is_some());
        // ...the real secrets are not transferred...
        assert!(artifacts
            .iter()
            .all(|a| !a.remote_path.contains("secrets-test")));
        assert!(artifacts.iter().all(|a| a.bytes != b"REAL-SYSTEM"));
        // ...and no plaintext key ships in the source.
        assert!(by_path("/tmp/nx-source/host/secrets/key.txt").is_none());
        fs::remove_dir_all(dir).unwrap();
    }

    fn temp_dir(name: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nox-artifacts-{name}-{}-{now}",
            std::process::id()
        ))
    }
}
