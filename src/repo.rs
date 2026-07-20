use std::env;
use std::path::{Path, PathBuf};

use crate::Result;

pub fn find() -> Result<PathBuf> {
    if let Some(dir) = env::var_os("NX_REPO_DIR").map(PathBuf::from) {
        return validate(dir);
    }

    if let Ok(exe) = env::current_exe() {
        if let Some(found) = exe.parent().and_then(find_upwards) {
            return Ok(found);
        }
    }

    if let Ok(cwd) = env::current_dir() {
        if let Some(found) = find_upwards(&cwd) {
            return Ok(found);
        }
    }

    let etc = PathBuf::from("/etc/nixos");
    if is_repo(&etc) {
        return Ok(etc);
    }

    Err("could not find repo root containing flake.nix and Cargo.toml".to_string())
}

fn validate(dir: PathBuf) -> Result<PathBuf> {
    if is_repo(&dir) {
        Ok(dir)
    } else {
        Err(format!(
            "NX_REPO_DIR does not look like this repo: {}",
            dir.display()
        ))
    }
}

fn find_upwards(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        if is_repo(&dir) {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn is_repo(path: &Path) -> bool {
    // The config repo is identified by its host flake; the nox crate lives in
    // its own repository and merely operates ON a config repo.
    path.join("host/flake.nix").is_file()
}

#[cfg(test)]
mod tests {
    use super::{find_upwards, is_repo, validate};
    use std::fs;
    use std::path::PathBuf;

    fn temp_repo(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nx-repo-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("nested/deep")).unwrap();
        fs::create_dir_all(dir.join("host")).unwrap();
        fs::write(dir.join("host/flake.nix"), "{}").unwrap();
        dir
    }

    #[test]
    fn detects_repo_root_by_marker_files() {
        let dir = temp_repo("marker");
        assert!(is_repo(&dir));
        assert!(!is_repo(&dir.join("nested")));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn finds_repo_root_from_nested_directory() {
        let dir = temp_repo("upwards");
        let found = find_upwards(&dir.join("nested/deep")).unwrap();
        assert_eq!(found, dir);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn validate_rejects_non_repo_directory() {
        let dir = std::env::temp_dir().join(format!("nx-repo-empty-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let err = validate(dir.clone()).unwrap_err();
        assert!(err.contains("does not look like this repo"));
        fs::remove_dir_all(dir).unwrap();
    }
}
