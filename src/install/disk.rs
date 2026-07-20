use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::install::state::InstallScope;
use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskInfo {
    pub path: String,
    pub size_gib: u64,
    pub model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskPrepareResult {
    pub status: u32,
    pub stdout: String,
    pub stderr: String,
}

pub fn discover(scope: InstallScope, remote: &str) -> Result<Vec<DiskInfo>> {
    let output = match scope {
        InstallScope::Local => Command::new("lsblk")
            .args([
                "--json",
                "--bytes",
                "--nodeps",
                "--output",
                "NAME,PATH,SIZE,TYPE,MODEL",
            ])
            .output()
            .map_err(|err| format!("failed to run lsblk: {err}"))?,
        InstallScope::Remote => {
            if remote.trim().is_empty() {
                return Err("remote target is required for disk discovery".to_string());
            }
            let output = crate::install::ssh::run_command(
                remote,
                "lsblk --json --bytes --nodeps --output NAME,PATH,SIZE,TYPE,MODEL",
            )?;
            if output.status != 0 {
                return Err(format!(
                    "disk discovery failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            return parse_lsblk_json(&output.stdout);
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("disk discovery failed: {}", stderr.trim()));
    }

    parse_lsblk_json(&output.stdout)
}

pub fn remote_prepare_preview(disk: &str) -> Result<String> {
    validate_disk_path(disk)?;
    Ok(format!(
        r#"if command -v sudo >/dev/null 2>&1; then sudo --non-interactive bash -s -- {}; else bash -s -- {}; fi <<'REMOTE_DISK_PREP'
set -euo pipefail

disk="$1"
case "$disk" in
  /dev/*) ;;
  *) echo "refusing non-/dev disk path: $disk" >&2; exit 2 ;;
esac

umount -R /mnt 2>/dev/null || true
swapoff --all 2>/dev/null || true

if command -v vgchange >/dev/null 2>&1; then
  vgchange -an 2>/dev/null || true
fi

if command -v lsblk >/dev/null 2>&1; then
  while IFS= read -r dev; do
    wipefs --all --force "$dev" 2>/dev/null || true
  done < <(lsblk -lnpo NAME "$disk" 2>/dev/null | tac)
fi

wipefs --all --force "$disk" 2>/dev/null || true

if command -v blkdiscard >/dev/null 2>&1 && blkdiscard -f "$disk" 2>/dev/null; then
  echo "target disk prepared with blkdiscard: $disk"
else
  echo "blkdiscard unavailable; zeroing first 4 GiB of $disk"
  dd if=/dev/zero of="$disk" bs=16M count=256 conv=fsync status=none 2>/dev/null || true
fi

blockdev --rereadpt "$disk" 2>/dev/null || true
udevadm settle 2>/dev/null || true
REMOTE_DISK_PREP"#,
        shell_single_quote(disk),
        shell_single_quote(disk)
    ))
}

pub fn local_prepare(disk: &str) -> Result<DiskPrepareResult> {
    let command = remote_prepare_preview(disk)?;
    let output = Command::new("bash")
        .arg("-c")
        .arg(command)
        .output()
        .map_err(|err| format!("failed to run disk preparation: {err}"))?;
    Ok(DiskPrepareResult {
        status: output.status.code().unwrap_or(1) as u32,
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

#[cfg(test)]
fn remote_prepare_with_runner(
    remote: &str,
    disk: &str,
    runner: fn(&str, &str) -> Result<crate::install::ssh::RemoteCommandOutput>,
) -> Result<DiskPrepareResult> {
    if remote.trim().is_empty() {
        return Err("remote target is required for disk preparation".to_string());
    }
    let command = remote_prepare_preview(disk)?;
    let output = runner(remote, &command)?;
    Ok(DiskPrepareResult {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

fn validate_disk_path(disk: &str) -> Result<()> {
    if !disk.starts_with("/dev/") {
        return Err(format!("refusing to prepare non-/dev disk path: {disk}"));
    }
    if disk.contains('\0') || disk.contains('\n') || disk.contains('\r') {
        return Err("disk path contains invalid control characters".to_string());
    }
    Ok(())
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn parse_lsblk_json(bytes: &[u8]) -> Result<Vec<DiskInfo>> {
    let raw: LsblkOutput = serde_json::from_slice(bytes)
        .map_err(|err| format!("failed to parse lsblk JSON: {err}"))?;
    let mut disks = raw
        .blockdevices
        .into_iter()
        .filter(|device| device.device_type.as_deref() == Some("disk"))
        .filter_map(|device| {
            let path = device.path.or(device.name)?;
            let size_gib = size_value_to_gib(device.size?)?;
            Some(DiskInfo {
                path,
                size_gib,
                model: device.model.and_then(non_empty),
            })
        })
        .collect::<Vec<_>>();
    disks.sort_by(|left, right| left.path.cmp(&right.path));
    if disks.is_empty() {
        return Err("no disks found in lsblk output".to_string());
    }
    Ok(disks)
}

fn size_value_to_gib(value: serde_json::Value) -> Option<u64> {
    let bytes = match value {
        serde_json::Value::Number(number) => number.as_u64()?,
        serde_json::Value::String(text) => text.parse::<u64>().ok()?,
        _ => return None,
    };
    Some(bytes.div_ceil(1024 * 1024 * 1024))
}

fn non_empty(value: String) -> Option<String> {
    let value = value.trim().to_string();
    (!value.is_empty()).then_some(value)
}

#[derive(Debug, Deserialize)]
struct LsblkOutput {
    blockdevices: Vec<LsblkDevice>,
}

#[derive(Debug, Deserialize)]
struct LsblkDevice {
    name: Option<String>,
    path: Option<String>,
    size: Option<serde_json::Value>,
    #[serde(rename = "type")]
    device_type: Option<String>,
    model: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{
        parse_lsblk_json, remote_prepare_preview, remote_prepare_with_runner,
    };
    use crate::install::ssh::RemoteCommandOutput;

    #[test]
    fn parses_lsblk_json_disks() {
        let json = br#"{
          "blockdevices": [
            {"name": "loop0", "path": "/dev/loop0", "size": 1000, "type": "loop", "model": null},
            {"name": "nvme0n1", "path": "/dev/nvme0n1", "size": 500107862016, "type": "disk", "model": "Samsung SSD"},
            {"name": "sda", "path": "/dev/sda", "size": "64000000000", "type": "disk", "model": ""}
          ]
        }"#;

        let disks = parse_lsblk_json(json).unwrap();
        assert_eq!(disks.len(), 2);
        assert_eq!(disks[0].path, "/dev/nvme0n1");
        assert_eq!(disks[0].size_gib, 466);
        assert_eq!(disks[0].model.as_deref(), Some("Samsung SSD"));
        assert_eq!(disks[1].path, "/dev/sda");
        assert_eq!(disks[1].size_gib, 60);
        assert_eq!(disks[1].model, None);
    }

    #[test]
    fn renders_remote_prepare_preview() {
        let command = remote_prepare_preview("/dev/nvme0n1").unwrap();

        assert!(command.contains("sudo --non-interactive bash -s -- '/dev/nvme0n1'"));
        assert!(command.contains("umount -R /mnt"));
        assert!(command.contains("wipefs --all --force \"$disk\""));
        assert!(command.contains("blkdiscard -f \"$disk\""));
    }

    #[test]
    fn rejects_non_dev_disk_prepare_path() {
        let err = remote_prepare_preview("/tmp/nvme0n1").unwrap_err();

        assert!(err.contains("refusing to prepare non-/dev disk path"));
    }

    #[test]
    fn quotes_remote_prepare_disk_path() {
        let command = remote_prepare_preview("/dev/disk/by-id/test'quote").unwrap();

        assert!(command.contains("'/dev/disk/by-id/test'\\''quote'"));
    }

    #[test]
    fn remote_prepare_runs_rendered_command() {
        let result =
            remote_prepare_with_runner("nixos@10.10.10.7", "/dev/nvme0n1", fake_prepare_runner)
                .unwrap();

        assert_eq!(result.status, 0);
        assert_eq!(
            result.stdout,
            "target disk prepared with blkdiscard: /dev/nvme0n1"
        );
        assert_eq!(result.stderr, "");
    }

    #[test]
    fn remote_prepare_requires_remote_target() {
        let err = remote_prepare_with_runner("", "/dev/nvme0n1", fake_prepare_runner).unwrap_err();

        assert_eq!(err, "remote target is required for disk preparation");
    }

    fn fake_prepare_runner(remote: &str, command: &str) -> Result<RemoteCommandOutput, String> {
        assert_eq!(remote, "nixos@10.10.10.7");
        assert!(command.contains("sudo --non-interactive bash -s -- '/dev/nvme0n1'"));
        assert!(command.contains("REMOTE_DISK_PREP"));
        Ok(RemoteCommandOutput {
            status: 0,
            stdout: b"target disk prepared with blkdiscard: /dev/nvme0n1\n".to_vec(),
            stderr: Vec::new(),
        })
    }
}
