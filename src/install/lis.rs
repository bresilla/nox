//! LIS producer/consumer for nox, built on the reference `lis` crate
//! (https://github.com/onix-os/lis).
//!
//! `from_state` maps the wizard's `InstallState` onto a typed LIS document —
//! the distro-neutral core sections plus an `x-nixos` extension carrying what
//! only this applier understands. `apply_to_state` is the inverse: it powers
//! both resume-previous-answers and the `lis-apply` CLI (LIS → generated nix).

use std::collections::BTreeMap;
use std::path::Path;

use lis::{Document, Size};
use serde::{Deserialize, Serialize};

use crate::install::state::{
    DiskSlice, InstallRole, InstallState, Mountpoint, SecretsMode, Subvolume, UserAccount,
    Volume, VolumeFs, VolumeGroupDraft,
};
use crate::Result;

/// The `x-nixos` extension: what only this repo's applier understands.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct XNixos {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets_key_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_cleanup: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bin_ensure: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data_mounts: BTreeMap<String, String>,
}

// ── InstallState → LIS ───────────────────────────────────────────

fn disk_handle(path: &str) -> String {
    path.trim_start_matches("/dev/").replace('/', "-")
}

fn fs_to_lis(fs: VolumeFs) -> lis::Fs {
    match fs {
        VolumeFs::Btrfs => lis::Fs::Btrfs,
        VolumeFs::Ext4 => lis::Fs::Ext4,
        VolumeFs::Xfs => lis::Fs::Xfs,
        VolumeFs::Swap => lis::Fs::Swap,
    }
}

fn fs_from_lis(fs: lis::Fs) -> VolumeFs {
    match fs {
        lis::Fs::Ext4 => VolumeFs::Ext4,
        lis::Fs::Xfs => VolumeFs::Xfs,
        lis::Fs::Swap => VolumeFs::Swap,
        _ => VolumeFs::Btrfs,
    }
}

pub fn from_state(state: &InstallState) -> Document {
    let mut doc = Document::new();

    // Disk handles + partitions: the ESP on the first managed disk, then one
    // raw partition per pool slice (the LVM PVs).
    let managed: Vec<&String> = state
        .disk_slices
        .iter()
        .filter(|(_, slices)| !slices.is_empty())
        .map(|(path, _)| path)
        .collect();
    let mut disks = Vec::new();
    let mut partitions = Vec::new();
    let mut slice_ids: BTreeMap<(String, usize), String> = BTreeMap::new();
    for (di, path) in managed.iter().enumerate() {
        let handle = disk_handle(path);
        disks.push(lis::TargetDisk {
            id: handle.clone(),
            matcher: lis::DiskMatch {
                path: Some((*path).clone()),
                ..Default::default()
            },
        });
        if di == 0 {
            partitions.push(lis::Partition {
                disk: handle.clone(),
                role: Some(lis::Role::Esp),
                size: Some(Size::MiB(state.esp_size_mib)),
                ..Default::default()
            });
        }
        for (i, slice) in state.slices_for_disk(path).iter().enumerate() {
            let id = format!("p-{handle}-{i}");
            slice_ids.insert(((*path).clone(), i), id.clone());
            partitions.push(lis::Partition {
                disk: handle.clone(),
                id: Some(id),
                role: Some(lis::Role::Raw),
                size: Some(Size::GiB(slice.size_gib)),
                fs: Some(lis::Fs::None),
                ..Default::default()
            });
        }
    }

    // Pools → LVM groups; volumes keep their pool assignment.
    let mut lvm = Vec::new();
    for group in &state.volume_groups {
        let mut devices = Vec::new();
        for path in &managed {
            for (i, slice) in state.slices_for_disk(path).iter().enumerate() {
                if slice.pool == group.name {
                    devices.push(slice_ids[&((*path).clone(), i)].clone());
                }
            }
        }
        if devices.is_empty() {
            continue;
        }
        let volumes = state
            .volumes
            .iter()
            .filter(|v| state.volume_group_for_volume(&v.name) == group.name)
            .map(|v| lis::LvmVolume {
                name: v.name.clone(),
                size: Some(if v.fill { Size::Rest } else { Size::GiB(v.size_gib) }),
                fs: Some(fs_to_lis(v.fs)),
                mountpoint: match &v.mountpoint {
                    Mountpoint::Path(p) => Some(p.clone()),
                    Mountpoint::Swap => None,
                },
                subvolumes: v
                    .subvolumes
                    .iter()
                    .map(|s| lis::Subvolume {
                        name: s.name.clone(),
                        mountpoint: s.mountpoint.clone(),
                        mount_options: Vec::new(),
                    })
                    .collect(),
                ..Default::default()
            })
            .collect();
        lvm.push(lis::LvmGroup {
            name: group.name.clone(),
            devices,
            volumes,
        });
    }

    doc.meta = Some(lis::Meta {
        name: Some(state.hostname.clone()),
        generator: Some(format!("nox {}", env!("CARGO_PKG_VERSION"))),
        ..Default::default()
    });
    doc.target = Some(lis::Target {
        arch: Some(lis::Arch::X86_64),
        firmware: Some(lis::Firmware::Uefi),
        disks,
    });
    // The wizard's single encrypt toggle = one LUKS container per pool PV.
    let encryption = if state.encrypt {
        slice_ids
            .values()
            .map(|part| lis::Encryption {
                id: format!("crypt-{part}"),
                over: part.clone(),
                kind: Some(lis::LuksKind::Luks2),
                key: Some(lis::KeySource { passphrase: true, keyfile: None }),
                unlock: vec![lis::Unlock::Passphrase],
            })
            .collect()
    } else {
        Vec::new()
    };
    doc.storage = Some(lis::Storage {
        wipe: Some(state.overwrite_existing_storage),
        partitions,
        encryption,
        lvm,
        ..Default::default()
    });
    doc.boot = Some(lis::Boot {
        loader: Some(lis::Loader::SystemdBoot),
        ..Default::default()
    });
    doc.system = Some(lis::System {
        hostname: Some(state.hostname.clone()),
        timezone: Some(state.timezone.clone()),
        ..Default::default()
    });
    doc.users = state
        .users
        .iter()
        .map(|u| lis::User {
            name: u.name.clone(),
            admin: Some(u.groups.iter().any(|g| g == "wheel")),
            groups: u.groups.clone(),
            password: u.password_hash.as_ref().map(|h| lis::Password {
                hash: Some(h.clone()),
                locked: None,
            }),
            dotfiles: u.dotfiles.as_ref().map(|r| lis::Dotfiles {
                repo: r.clone(),
                method: None,
            }),
            ..Default::default()
        })
        .collect();
    doc.network = Some(lis::Network {
        ssh: Some(lis::Ssh {
            enabled: Some(state.allow_ssh),
            ..Default::default()
        }),
        ..Default::default()
    });
    doc.software = Some(lis::Software {
        role: Some(match state.role {
            InstallRole::Server => "server".to_string(),
            InstallRole::Laptop => "minimal".to_string(),
        }),
        ..Default::default()
    });

    let x_nixos = XNixos {
        role: Some(match state.role {
            InstallRole::Server => "server".to_string(),
            InstallRole::Laptop => "laptop".to_string(),
        }),
        secrets: Some(state.secrets_mode != SecretsMode::Skip),
        secrets_key_file: match &state.secrets_mode {
            SecretsMode::KeyFile(path) => Some(path.clone()),
            _ => None,
        },
        remote: Some(state.remote.clone()),
        network_cleanup: Some(state.network_route_cleanup),
        bin_ensure: Some(!state.skip_bin_ensure),
        data_mounts: state.data_mounts.clone(),
    };
    doc.extensions.insert(
        "x-nixos".to_string(),
        serde_json::to_value(&x_nixos).expect("x-nixos serializes"),
    );
    doc
}

// ── LIS → InstallState ───────────────────────────────────────────

fn size_gib(size: &Size) -> Option<u64> {
    size.as_gib()
}

/// Fold a LIS document back into an `InstallState` (over `draft()` defaults).
/// Foreign sections are ignored — this consumes the nox subset.
pub fn apply_to_state(doc: &Document, state: &mut InstallState) {
    if let Some(system) = &doc.system {
        if let Some(h) = &system.hostname {
            state.hostname = h.clone();
        }
        if let Some(tz) = &system.timezone {
            state.timezone = tz.clone();
        }
    }
    if let Some(on) = doc
        .network
        .as_ref()
        .and_then(|n| n.ssh.as_ref())
        .and_then(|s| s.enabled)
    {
        state.allow_ssh = on;
    }
    if !doc.users.is_empty() {
        state.users = doc
            .users
            .iter()
            .map(|u| {
                let mut groups = u.groups.clone();
                if u.admin == Some(true) && !groups.iter().any(|g| g == "wheel") {
                    groups.insert(0, "wheel".to_string());
                }
                UserAccount {
                    name: u.name.clone(),
                    password_hash: u.password.as_ref().and_then(|p| p.hash.clone()),
                    dotfiles: u.dotfiles.as_ref().map(|d| d.repo.clone()),
                    groups,
                }
            })
            .collect();
        state.sync_primary_user();
    }
    let x: XNixos = doc
        .extensions
        .get("x-nixos")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    if let Some(role) = &x.role {
        state.role = if role == "server" {
            InstallRole::Server
        } else {
            InstallRole::Laptop
        };
    }
    if let Some(remote) = &x.remote {
        state.remote = remote.clone();
    }
    if let Some(on) = x.network_cleanup {
        state.network_route_cleanup = on;
    }
    if let Some(on) = x.bin_ensure {
        state.skip_bin_ensure = !on;
    }
    state.secrets_mode = match (&x.secrets, &x.secrets_key_file) {
        (Some(false), _) => SecretsMode::Skip,
        (_, Some(path)) => SecretsMode::KeyFile(path.clone()),
        _ => SecretsMode::YubiKey,
    };
    state.data_mounts = x.data_mounts.clone();

    let Some(storage) = &doc.storage else { return };
    if let Some(wipe) = storage.wipe {
        state.overwrite_existing_storage = wipe;
    }
    state.encrypt = !storage.encryption.is_empty();
    // LVM devices may reference LUKS containers; resolve to the partition under.
    let crypt_over: BTreeMap<&str, &str> = storage
        .encryption
        .iter()
        .map(|c| (c.id.as_str(), c.over.as_str()))
        .collect();

    // Disk handle → device path from the target section.
    let mut handle_paths: BTreeMap<&str, &str> = BTreeMap::new();
    if let Some(target) = &doc.target {
        for disk in &target.disks {
            if let Some(path) = &disk.matcher.path {
                handle_paths.insert(disk.id.as_str(), path.as_str());
            }
        }
    }
    // Partition id → (device path, size); the ESP restores its size.
    let mut part_info: BTreeMap<&str, (&str, u64)> = BTreeMap::new();
    for part in &storage.partitions {
        if part.role == Some(lis::Role::Esp) {
            if let Some(size) = &part.size {
                state.esp_size_mib = match size {
                    Size::MiB(n) => *n,
                    other => other.as_gib().map(|g| g * 1024).unwrap_or(state.esp_size_mib),
                };
            }
            continue;
        }
        let (Some(id), Some(path)) = (&part.id, handle_paths.get(part.disk.as_str())) else {
            continue;
        };
        let gib = part.size.as_ref().and_then(size_gib).unwrap_or(0);
        part_info.insert(id.as_str(), (path, gib));
    }

    if storage.lvm.is_empty() {
        return;
    }
    // Pools are LVM volume groups; multi-disk documents join disks into them.
    state.use_lvm = true;
    state.storage_mode = crate::install::state::StorageMode::JoinedLvm;
    state.volume_groups = storage
        .lvm
        .iter()
        .map(|g| VolumeGroupDraft { name: g.name.clone() })
        .collect();
    let mut disk_slices: BTreeMap<String, Vec<DiskSlice>> = BTreeMap::new();
    let mut volumes = Vec::new();
    let mut assignments = BTreeMap::new();
    for group in &storage.lvm {
        for dev in &group.devices {
            let dev = crypt_over.get(dev.as_str()).copied().unwrap_or(dev.as_str());
            if let Some((path, gib)) = part_info.get(dev) {
                disk_slices
                    .entry((*path).to_string())
                    .or_default()
                    .push(DiskSlice { pool: group.name.clone(), size_gib: *gib });
            }
        }
        for vol in &group.volumes {
            let fill = vol.size.map(|s| s.is_rest()).unwrap_or(false);
            volumes.push(Volume {
                name: vol.name.clone(),
                mountpoint: match (&vol.mountpoint, vol.fs) {
                    (_, Some(lis::Fs::Swap)) => Mountpoint::Swap,
                    (Some(p), _) => Mountpoint::Path(p.clone()),
                    (None, _) => Mountpoint::Swap,
                },
                size_gib: if fill {
                    1
                } else {
                    vol.size.as_ref().and_then(size_gib).unwrap_or(1).max(1)
                },
                fs: vol.fs.map(fs_from_lis).unwrap_or(VolumeFs::Btrfs),
                subvolumes: vol
                    .subvolumes
                    .iter()
                    .map(|s| Subvolume {
                        // nox names subvolumes without the btrfs "@" prefix
                        // (disko adds it); accept either spelling.
                        name: s.name.trim_start_matches('@').to_string(),
                        mountpoint: s.mountpoint.clone(),
                    })
                    .collect(),
                fill,
            });
            assignments.insert(vol.name.clone(), group.name.clone());
        }
    }
    state.disk_slices = disk_slices;
    state.volumes = volumes;
    state.volume_volume_groups = assignments;
    // Synthetic capacities: slices plus the ESP reservation. Real device
    // sizes take over as soon as discovery runs on an actual target.
    let esp_gib = state.esp_size_mib.div_ceil(1024);
    state.disks = state
        .disk_slices
        .keys()
        .map(|path| crate::install::state::DiskChoice {
            path: path.clone(),
            size_gib: state
                .slices_for_disk(path)
                .iter()
                .map(|s| s.size_gib)
                .sum::<u64>()
                + esp_gib,
            model: None,
        })
        .collect();
}

// ── file IO ──────────────────────────────────────────────────────

pub fn document_path(repo: &Path) -> std::path::PathBuf {
    repo.join("host/generated/system.lis.json")
}

pub fn write_document(repo: &Path, doc: &Document) -> Result<()> {
    let json = doc.to_json()?;
    let path = document_path(repo);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    std::fs::write(&path, json)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))
}

pub fn read(path: &Path) -> Result<Document> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    Document::from_json(&text).map_err(|err| format!("{}: {err}", path.display()))
}

/// A fresh draft state with the document's answers folded in.
pub fn state_from(doc: &Document) -> InstallState {
    let mut state = InstallState::draft();
    apply_to_state(doc, &mut state);
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with_layout() -> InstallState {
        let mut state = InstallState::sample();
        state.hostname = "tron".to_string();
        state.role = InstallRole::Server;
        state.secrets_mode = SecretsMode::Skip;
        state.overwrite_existing_storage = true;
        state.encrypt = true;
        state.disk_slices = BTreeMap::from([
            (
                "/dev/sda".to_string(),
                vec![DiskSlice { pool: "pool".to_string(), size_gib: 400 }],
            ),
            (
                "/dev/sdb".to_string(),
                vec![DiskSlice { pool: "pool".to_string(), size_gib: 900 }],
            ),
        ]);
        state.volumes = vec![
            Volume {
                name: "root".to_string(),
                mountpoint: Mountpoint::Path("/".to_string()),
                size_gib: 100,
                fs: VolumeFs::Btrfs,
                subvolumes: vec![Subvolume {
                    name: "home".to_string(),
                    mountpoint: "/home".to_string(),
                }],
                fill: false,
            },
            Volume {
                name: "swap".to_string(),
                mountpoint: Mountpoint::Swap,
                size_gib: 8,
                fs: VolumeFs::Swap,
                subvolumes: vec![],
                fill: false,
            },
            Volume {
                name: "data".to_string(),
                mountpoint: Mountpoint::Path("/data".to_string()),
                size_gib: 1,
                fs: VolumeFs::Xfs,
                subvolumes: vec![],
                fill: true,
            },
        ];
        state.volume_volume_groups = state
            .volumes
            .iter()
            .map(|v| (v.name.clone(), "pool".to_string()))
            .collect();
        state.users[0].password_hash = Some("$6$salt$hash".to_string());
        state
    }

    #[test]
    fn emitted_document_is_semantically_valid_lis() {
        let doc = from_state(&state_with_layout());
        assert_eq!(doc.lis, lis::VERSION);
        let issues = lis::validate(&doc);
        assert!(issues.is_empty(), "{issues:?}");
        let storage = doc.storage.as_ref().unwrap();
        assert_eq!(storage.partitions.len(), 3);
        assert_eq!(storage.partitions[0].role, Some(lis::Role::Esp));
        assert_eq!(storage.lvm.len(), 1);
        assert_eq!(storage.lvm[0].devices.len(), 2);
        let data = storage.lvm[0].volumes.iter().find(|v| v.name == "data").unwrap();
        assert_eq!(data.size, Some(Size::Rest));
        // encrypt=true → one LUKS container per PV, and the doc stays valid.
        assert_eq!(storage.encryption.len(), 2);
        assert!(doc.extensions.contains_key("x-nixos"));
    }

    #[test]
    fn roundtrips_through_json_back_into_state() {
        let original = state_with_layout();
        let json = from_state(&original).to_json().unwrap();
        let doc = Document::from_json(&json).unwrap();
        let restored = state_from(&doc);

        assert_eq!(restored.hostname, "tron");
        assert!(restored.encrypt, "encryption survives the roundtrip");
        assert_eq!(restored.role, InstallRole::Server);
        assert_eq!(restored.secrets_mode, SecretsMode::Skip);
        assert!(restored.overwrite_existing_storage);
        assert_eq!(restored.esp_size_mib, original.esp_size_mib);
        assert_eq!(restored.disk_slices.len(), 2);
        assert_eq!(restored.slices_for_disk("/dev/sdb")[0].size_gib, 900);
        assert_eq!(restored.volumes.len(), 3);
        let root = restored.volumes.iter().find(|v| v.name == "root").unwrap();
        assert_eq!(root.mountpoint, Mountpoint::Path("/".to_string()));
        assert_eq!(root.subvolumes.len(), 1);
        let data = restored.volumes.iter().find(|v| v.name == "data").unwrap();
        assert!(data.fill);
        assert_eq!(restored.volume_group_for_volume("root"), "pool");
        assert_eq!(
            restored.users[0].password_hash.as_deref(),
            Some("$6$salt$hash")
        );
        assert!(restored.users[0].groups.iter().any(|g| g == "wheel"));
    }

    #[test]
    fn rejects_future_major_versions() {
        let dir = std::env::temp_dir().join("lis-version-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("doc.lis.json");
        std::fs::write(&path, r#"{ "lis": "2.0.0" }"#).unwrap();
        assert!(read(&path).unwrap_err().contains("unsupported"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
