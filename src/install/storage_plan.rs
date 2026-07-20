use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::install::state::{DiskRole, InstallScope, InstallState, Mountpoint, StorageMode};
use crate::install::storage::StorageLayout;
use crate::Result;

#[derive(Debug, Serialize)]
struct StoragePlan {
    version: u8,
    target: TargetPlan,
    storage_mode: String,
    encrypt: bool,
    overwrite_existing_storage: bool,
    disks: Vec<DiskPlan>,
    volume_groups: Vec<VolumeGroupPlan>,
    logical_volumes: Vec<LogicalVolumePlan>,
    actions: Vec<ActionPlan>,
}

#[derive(Debug, Serialize)]
struct TargetPlan {
    scope: String,
    remote: Option<String>,
    hostname: String,
    install_user: String,
}

#[derive(Debug, Serialize)]
struct DiskPlan {
    path: String,
    size_gib: u64,
    model: Option<String>,
    role: String,
    volume_group: Option<String>,
    create_esp: bool,
}

#[derive(Debug, Serialize)]
struct VolumeGroupPlan {
    name: String,
    disk_paths: Vec<String>,
    logical_volumes: Vec<String>,
    total_gib: u64,
    used_gib: u64,
    free_gib: u64,
}

#[derive(Debug, Serialize)]
struct LogicalVolumePlan {
    name: String,
    mountpoint: String,
    size_gib: u64,
    /// True when this partition absorbs the pool's remaining space; its
    /// size_gib is then a minimum, not the rendered size.
    fill: bool,
    volume_group: String,
    filesystem: String,
    subvolumes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ActionPlan {
    label: String,
    destructive: bool,
}

pub fn render(state: &InstallState) -> Result<String> {
    let layout = StorageLayout::from_state(state)?;
    let plan = StoragePlan::from_state_and_layout(state, &layout);
    serde_json::to_string_pretty(&plan)
        .map(|json| format!("{json}\n"))
        .map_err(|err| format!("failed to render storage plan JSON: {err}"))
}

pub fn write(repo: &Path, state: &InstallState) -> Result<()> {
    let file = repo.join("host/generated/storage-plan.json");
    let content = render(state)?;
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    fs::write(&file, content).map_err(|err| format!("failed to write {}: {err}", file.display()))
}

impl StoragePlan {
    fn from_state_and_layout(state: &InstallState, layout: &StorageLayout) -> Self {
        let disks = state
            .visible_disks()
            .iter()
            .map(|disk| {
                let role = state.disk_role_for_path(&disk.path);
                DiskPlan {
                    path: disk.path.clone(),
                    size_gib: disk.size_gib,
                    model: disk.model.clone(),
                    role: disk_role_name(role).to_string(),
                    volume_group: state
                        .disk_volume_group_for_path(&disk.path)
                        .map(ToString::to_string),
                    create_esp: layout
                        .disks
                        .iter()
                        .any(|layout_disk| layout_disk.path == disk.path && layout_disk.create_esp),
                }
            })
            .collect();

        let volume_groups = layout
            .volume_groups
            .iter()
            .map(|group| {
                let disk_paths = layout
                    .disks
                    .iter()
                    .filter(|disk| disk.slices.iter().any(|s| s.pool == group.name))
                    .map(|disk| disk.path.clone())
                    .collect::<Vec<_>>();
                let logical_volumes = group
                    .logical_volumes
                    .iter()
                    .map(|volume| volume.name.clone())
                    .collect::<Vec<_>>();
                let total_gib = layout
                    .disks
                    .iter()
                    .flat_map(|disk| disk.slices.iter())
                    .filter(|s| s.pool == group.name)
                    .map(|s| s.size_gib)
                    .sum();
                let used_gib = group
                    .logical_volumes
                    .iter()
                    .map(|volume| volume.size_gib)
                    .sum();
                VolumeGroupPlan {
                    name: group.name.clone(),
                    disk_paths,
                    logical_volumes,
                    total_gib,
                    used_gib,
                    free_gib: total_gib.saturating_sub(used_gib),
                }
            })
            .collect();

        let logical_volumes = state
            .volumes
            .iter()
            .map(|volume| LogicalVolumePlan {
                name: volume.name.clone(),
                mountpoint: mountpoint_label(&volume.mountpoint).to_string(),
                size_gib: volume.size_gib,
                fill: volume.fill,
                volume_group: state.volume_group_for_volume(&volume.name).to_string(),
                filesystem: volume.fs.title().to_string(),
                subvolumes: volume
                    .subvolumes
                    .iter()
                    .map(|s| format!("@{} → {}", s.name, s.mountpoint))
                    .collect(),
            })
            .collect();

        let actions = layout
            .actions()
            .into_iter()
            .map(|action| ActionPlan {
                label: action.label(),
                destructive: action.destructive(),
            })
            .collect();

        Self {
            version: 1,
            target: TargetPlan {
                scope: state.scope.title().to_string(),
                remote: match state.scope {
                    InstallScope::Remote => Some(state.remote.clone()),
                    InstallScope::Local => None,
                },
                hostname: state.hostname.clone(),
                install_user: state.install_user.clone(),
            },
            storage_mode: storage_mode_name(state.storage_mode).to_string(),
            encrypt: state.encrypt,
            overwrite_existing_storage: state.overwrite_existing_storage,
            disks,
            volume_groups,
            logical_volumes,
            actions,
        }
    }
}

fn disk_role_name(role: DiskRole) -> &'static str {
    match role {
        DiskRole::System => "system",
        DiskRole::PoolMember => "pool-member",
        DiskRole::Data => "data",
        DiskRole::Reserve => "reserve",
        DiskRole::Ignore => "ignore",
    }
}

fn storage_mode_name(mode: StorageMode) -> &'static str {
    match mode {
        StorageMode::SingleDisk => "single-disk",
        StorageMode::JoinedLvm => "joined-lvm",
        StorageMode::SeparatePools => "separate-pools",
        StorageMode::Manual => "manual",
    }
}

fn mountpoint_label(mountpoint: &Mountpoint) -> &str {
    match mountpoint {
        Mountpoint::Path(path) => path,
        Mountpoint::Swap => "swap",
    }
}

#[cfg(test)]
mod tests {
    use super::render;
    use crate::install::state::{DiskChoice, DiskRole, InstallState};
    use serde_json::Value;

    #[test]
    fn renders_storage_plan_json_from_sample_state() {
        let json = render(&InstallState::sample()).unwrap();
        let value = serde_json::from_str::<Value>(&json).unwrap();

        assert_eq!(value["version"], 1);
        assert_eq!(value["storage_mode"], "joined-lvm");
        assert_eq!(value["target"]["hostname"], "novo");
        assert_eq!(value["disks"][0]["path"], "/dev/nvme0n1");
        assert_eq!(value["disks"][0]["role"], "system");
        assert_eq!(value["disks"][0]["volume_group"], "pool");
        assert_eq!(value["volume_groups"][0]["name"], "pool");
        assert_eq!(value["logical_volumes"][0]["name"], "root");
        assert_eq!(value["actions"][0]["label"], "wipe disk /dev/nvme0n1");
        assert_eq!(value["actions"][0]["destructive"], true);
    }

    #[test]
    fn storage_plan_records_user_volume_group_assignments() {
        let mut state = InstallState::sample();
        let second_disk = DiskChoice {
            path: "/dev/nvme1n1".to_string(),
            size_gib: 465,
            model: None,
        };
        state.discovered_disks.push(second_disk.clone());
        state.set_disk_role(&second_disk.path, DiskRole::PoolMember);
        state.set_disk_volume_group(&second_disk.path, "extra");
        state.set_volume_group_for_volume("pkg", "extra");

        let json = render(&state).unwrap();
        let value = serde_json::from_str::<Value>(&json).unwrap();

        assert_eq!(value["volume_groups"][1]["name"], "extra");
        assert_eq!(value["volume_groups"][1]["disk_paths"][0], "/dev/nvme1n1");
        assert_eq!(value["volume_groups"][1]["logical_volumes"][0], "pkg");
    }
}
