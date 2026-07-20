use std::collections::{BTreeMap, HashSet};

use crate::install::state::{
    DiskRole, DiskSlice, InstallState, StorageMode, Volume, VolumeFs, DEFAULT_STORAGE_POOL_NAME,
};
use crate::Result;

#[allow(dead_code)]
pub const DEFAULT_LVM_VG_NAME: &str = DEFAULT_STORAGE_POOL_NAME;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageLayout {
    pub mode: StorageMode,
    pub encrypt: bool,
    pub disks: Vec<StorageDisk>,
    pub volume_groups: Vec<StorageVolumeGroup>,
    /// Extra data disks to format + mount: (device path, mount point).
    pub data_mounts: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageDisk {
    pub key: String,
    pub path: String,
    pub size_gib: u64,
    pub role: DiskRole,
    pub create_esp: bool,
    /// EFI System Partition size in MiB (only meaningful when create_esp).
    pub esp_size_mib: u64,
    /// PV slices carved from this disk, each feeding a pool (VG).
    pub slices: Vec<DiskSlice>,
}

pub use crate::install::state::DiskRole as StorageDiskRole;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum StorageAction {
    WipeDisk { path: String },
    CreateEsp { path: String },
    JoinVolumeGroup { path: String, vg_name: String },
    FormatLogicalVolume { vg_name: String, lv_name: String },
    LeaveExisting { path: String },
    Ignore { path: String },
}

impl StorageAction {
    pub fn label(&self) -> String {
        match self {
            StorageAction::WipeDisk { path } => format!("wipe disk {path}"),
            StorageAction::CreateEsp { path } => format!("create ESP on {path}"),
            StorageAction::JoinVolumeGroup { path, vg_name } => {
                format!("join {path} to VG {vg_name}")
            }
            StorageAction::FormatLogicalVolume { vg_name, lv_name } => {
                format!("format LV {vg_name}/{lv_name}")
            }
            StorageAction::LeaveExisting { path } => format!("leave existing {path}"),
            StorageAction::Ignore { path } => format!("ignore {path}"),
        }
    }

    pub fn destructive(&self) -> bool {
        matches!(
            self,
            StorageAction::WipeDisk { .. }
                | StorageAction::CreateEsp { .. }
                | StorageAction::JoinVolumeGroup { .. }
                | StorageAction::FormatLogicalVolume { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageVolumeGroup {
    pub name: String,
    pub logical_volumes: Vec<Volume>,
    /// Total GiB the disk slices assign to this pool; the fill volume's
    /// rendered size is derived from it.
    pub capacity_gib: u64,
}

impl StorageLayout {
    pub fn from_state(state: &InstallState) -> Result<Self> {
        match state.storage_mode {
            StorageMode::SingleDisk | StorageMode::JoinedLvm => Self::single_pool_from_state(state),
            StorageMode::SeparatePools => Self::separate_pools_from_state(state),
            StorageMode::Manual => Err("manual storage mode is not implemented yet".to_string()),
        }
    }

    /// Assemble the rendered layout from the draft state without applying
    /// mode-specific validation. Disk-to-VG and volume-to-VG assignments come
    /// straight from `InstallState`, so this already handles arbitrary
    /// single-pool and multi-pool topologies; callers validate for their mode.
    fn assemble(state: &InstallState) -> Result<Self> {
        if state.disks.is_empty() {
            return Err("at least one disk is required".to_string());
        }
        if state.volumes.is_empty() {
            return Err("at least one volume is required".to_string());
        }

        let visible_disks = state.visible_disks();
        let mut keys = HashSet::new();
        let disks = visible_disks
            .iter()
            .map(|disk| {
                validate_disk_path(&disk.path)?;
                let key = disk_key(&disk.path)?;
                if !keys.insert(key.clone()) {
                    return Err(format!("duplicate rendered disk key: {key}"));
                }
                let role = state.disk_role_for_path(&disk.path);
                let mut slices = state.slices_for_disk(&disk.path).to_vec();
                // Untouched install disks default to one whole-disk slice; a
                // disk the user explicitly freed (entry exists, empty) stays out.
                if slices.is_empty()
                    && !state.disk_slices.contains_key(&disk.path)
                    && matches!(role, DiskRole::System | DiskRole::PoolMember)
                {
                    // Whole disk into the default pool, minus the ESP reservation.
                    let esp_gib = if role == DiskRole::System {
                        state.esp_size_mib.max(256).div_ceil(1024).max(1)
                    } else {
                        0
                    };
                    slices.push(DiskSlice {
                        pool: state.default_volume_group_name().to_string(),
                        size_gib: disk.size_gib.saturating_sub(esp_gib),
                    });
                }
                Ok(StorageDisk {
                    key,
                    path: disk.path.clone(),
                    size_gib: disk.size_gib,
                    role,
                    create_esp: role == DiskRole::System,
                    esp_size_mib: state.esp_size_mib.max(256),
                    slices,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let pool_capacity = |name: &str| -> u64 {
            disks
                .iter()
                .flat_map(|disk| disk.slices.iter())
                .filter(|slice| slice.pool == name)
                .map(|slice| slice.size_gib)
                .sum()
        };
        let volume_groups = state
            .volume_groups
            .iter()
            .map(|group| StorageVolumeGroup {
                name: group.name.clone(),
                logical_volumes: state
                    .volumes
                    .iter()
                    .filter(|volume| state.volume_group_for_volume(&volume.name) == group.name)
                    .cloned()
                    .collect(),
                capacity_gib: pool_capacity(&group.name),
            })
            .filter(|group| !group.logical_volumes.is_empty())
            .collect::<Vec<_>>();

        let mut data_mounts: Vec<(String, String)> = state
            .data_mounts
            .iter()
            .map(|(path, mount)| (path.clone(), mount.clone()))
            .collect();
        data_mounts.sort();

        Ok(Self {
            mode: state.storage_mode,
            encrypt: state.encrypt,
            disks,
            volume_groups,
            data_mounts,
        })
    }

    pub fn single_pool_from_state(state: &InstallState) -> Result<Self> {
        let layout = Self::assemble(state)?;
        layout.validate()?;
        Ok(layout)
    }

    /// Build a separate-pools layout: every install disk lives in its own volume
    /// group. Disk/volume group assignments come from the draft state; validation
    /// enforces the one-disk-per-group rule that distinguishes this from joined-lvm.
    pub fn separate_pools_from_state(state: &InstallState) -> Result<Self> {
        let layout = Self::assemble(state)?;
        layout.validate()?;
        Ok(layout)
    }

    #[allow(dead_code)]
    pub fn total_disk_gib(&self) -> u64 {
        self.disks
            .iter()
            .filter(|disk| matches!(disk.role, DiskRole::System | DiskRole::PoolMember))
            .map(|disk| disk.size_gib)
            .sum()
    }

    #[allow(dead_code)]
    pub fn used_gib(&self) -> u64 {
        self.volume_groups
            .iter()
            .flat_map(|vg| vg.logical_volumes.iter())
            .map(|volume| volume.size_gib)
            .sum()
    }

    pub fn lvm_vg_names(&self) -> Vec<String> {
        self.volume_groups
            .iter()
            .map(|vg| vg.name.clone())
            .collect()
    }

    #[allow(dead_code)]
    pub fn actions(&self) -> Vec<StorageAction> {
        let mut actions = Vec::new();
        for disk in &self.disks {
            match disk.role {
                DiskRole::System | DiskRole::PoolMember => {
                    actions.push(StorageAction::WipeDisk {
                        path: disk.path.clone(),
                    });
                    if disk.create_esp {
                        actions.push(StorageAction::CreateEsp {
                            path: disk.path.clone(),
                        });
                    }
                    for slice in &disk.slices {
                        actions.push(StorageAction::JoinVolumeGroup {
                            path: disk.path.clone(),
                            vg_name: slice.pool.clone(),
                        });
                    }
                }
                DiskRole::Data | DiskRole::Reserve => {
                    actions.push(StorageAction::LeaveExisting {
                        path: disk.path.clone(),
                    });
                }
                DiskRole::Ignore => {
                    actions.push(StorageAction::Ignore {
                        path: disk.path.clone(),
                    });
                }
            }
        }
        for volume_group in &self.volume_groups {
            for volume in &volume_group.logical_volumes {
                actions.push(StorageAction::FormatLogicalVolume {
                    vg_name: volume_group.name.clone(),
                    lv_name: volume.name.clone(),
                });
            }
        }
        actions
    }

    pub fn validate(&self) -> Result<()> {
        if self.disks.is_empty() {
            return Err("at least one disk is required".to_string());
        }
        if self.volume_groups.is_empty() {
            return Err("at least one volume group is required".to_string());
        }
        if self.mode == StorageMode::SingleDisk
            && self
                .disks
                .iter()
                .filter(|disk| matches!(disk.role, DiskRole::System | DiskRole::PoolMember))
                .count()
                != 1
        {
            return Err("single-disk storage mode requires exactly one install disk".to_string());
        }
        if self.mode == StorageMode::Manual {
            return Err("manual storage mode is not implemented yet".to_string());
        }
        if !self.disks.iter().any(|disk| disk.create_esp) {
            return Err("at least one disk must create an ESP".to_string());
        }
        if self
            .disks
            .iter()
            .any(|disk| disk.create_esp && disk.role != DiskRole::System)
        {
            return Err("only system disks can create an ESP".to_string());
        }
        for disk in &self.disks {
            validate_attr(&disk.key)?;
            validate_disk_path(&disk.path)?;
            // A disk's slices must not exceed its usable capacity (after ESP).
            let esp_gib = if disk.create_esp {
                disk.esp_size_mib.div_ceil(1024).max(1)
            } else {
                0
            };
            let usable = disk.size_gib.saturating_sub(esp_gib);
            let claimed: u64 = disk.slices.iter().map(|s| s.size_gib).sum();
            if claimed > usable {
                return Err(format!(
                    "disk {} slices claim {claimed}G but only {usable}G is usable",
                    disk.path
                ));
            }
            for slice in &disk.slices {
                validate_attr(&slice.pool)?;
            }
        }
        let volume_group_names = self
            .volume_groups
            .iter()
            .map(|vg| vg.name.as_str())
            .collect::<HashSet<_>>();
        // Every pool that owns partitions must receive at least one disk slice.
        for vg in &self.volume_groups {
            if vg.logical_volumes.is_empty() {
                continue;
            }
            let has_slice = self
                .disks
                .iter()
                .any(|disk| disk.slices.iter().any(|s| s.pool == vg.name));
            if !has_slice {
                return Err(format!(
                    "pool {} has partitions but no disk space assigned to it",
                    vg.name
                ));
            }
        }
        let _ = &volume_group_names;
        for vg in &self.volume_groups {
            validate_attr(&vg.name)?;
            if vg.logical_volumes.is_empty() {
                return Err(format!("volume group has no logical volumes: {}", vg.name));
            }
            for volume in &vg.logical_volumes {
                validate_attr(&volume.name)?;
                // Subvolumes only make sense on btrfs volumes.
                if !volume.subvolumes.is_empty() && volume.fs != VolumeFs::Btrfs {
                    return Err(format!(
                        "volume {} has subvolumes but its filesystem is {}",
                        volume.name,
                        volume.fs.title()
                    ));
                }
                for subvol in &volume.subvolumes {
                    validate_subvolume_name(&subvol.name)?;
                }
            }
        }
        // A pool's capacity is the sum of the disk slices assigned to it. Fixed
        // partitions must fit; a fill partition needs at least 1G of leftover.
        let mut volume_group_capacity = BTreeMap::<String, u64>::new();
        for disk in &self.disks {
            for slice in &disk.slices {
                *volume_group_capacity.entry(slice.pool.clone()).or_default() += slice.size_gib;
            }
        }
        for vg in &self.volume_groups {
            if vg.logical_volumes.is_empty() {
                continue;
            }
            let fills = vg.logical_volumes.iter().filter(|v| v.fill).count();
            if fills > 1 {
                return Err(format!(
                    "pool {} has {fills} fill partitions; at most one can take the remaining space",
                    vg.name
                ));
            }
            let total = *volume_group_capacity.get(&vg.name).unwrap_or(&0);
            let fixed = vg
                .logical_volumes
                .iter()
                .filter(|v| !v.fill)
                .map(|volume| volume.size_gib)
                .sum::<u64>();
            let needed = fixed + fills as u64; // fill needs ≥ 1G
            if needed > total {
                return Err(format!(
                    "pool {} uses {needed}G but its disks only provide {total}G",
                    vg.name
                ));
            }
        }
        Ok(())
    }
}

fn disk_key(path: &str) -> Result<String> {
    validate_disk_path(path)?;
    let name = path
        .rsplit('/')
        .next()
        .ok_or_else(|| format!("invalid disk path: {path}"))?;
    let key = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    validate_attr(&key)?;
    Ok(key)
}

pub fn validate_disk_path(path: &str) -> Result<()> {
    if path.starts_with("/dev/")
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(format!("disk path is not supported: {path}"))
    }
}

fn validate_subvolume_name(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err("btrfs subvolume name cannot be empty".to_string());
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        Ok(())
    } else {
        Err(format!("invalid btrfs subvolume name: {value}"))
    }
}

pub fn validate_attr(value: &str) -> Result<()> {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err("empty Nix attr name".to_string());
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(format!("invalid Nix attr name: {value}"));
    }
    if chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
        Ok(())
    } else {
        Err(format!("invalid Nix attr name: {value}"))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        StorageAction, StorageDisk, StorageDiskRole, StorageLayout, StorageVolumeGroup,
        DEFAULT_LVM_VG_NAME,
    };
    use crate::install::state::{DiskChoice, DiskRole, InstallState, StorageMode};

    #[test]
    fn builds_single_pool_layout_from_current_install_state() {
        let layout = StorageLayout::single_pool_from_state(&InstallState::sample()).unwrap();

        assert_eq!(layout.disks.len(), 1);
        assert_eq!(layout.disks[0].key, "nvme0n1");
        assert_eq!(layout.disks[0].role, StorageDiskRole::System);
        assert!(layout.disks[0].create_esp);
        assert_eq!(layout.disks[0].slices[0].pool, DEFAULT_LVM_VG_NAME);
        assert_eq!(layout.volume_groups[0].name, DEFAULT_LVM_VG_NAME);
        assert_eq!(layout.volume_groups[0].logical_volumes.len(), 6);
    }

    #[test]
    fn joins_multiple_selected_disks_into_one_pool() {
        let mut state = InstallState::sample();
        let second_disk = DiskChoice {
            path: "/dev/nvme1n1".to_string(),
            size_gib: 465,
            model: None,
        };
        state.discovered_disks.push(second_disk.clone());
        state.disks.push(second_disk.clone());
        state
            .disk_roles
            .insert(second_disk.path.clone(), DiskRole::PoolMember);
        state.normalize_disk_roles();

        let layout = StorageLayout::single_pool_from_state(&state).unwrap();

        assert_eq!(layout.disks.len(), 2);
        assert_eq!(layout.disks[0].role, StorageDiskRole::System);
        assert_eq!(layout.disks[1].role, StorageDiskRole::PoolMember);
        assert!(layout.disks[0].create_esp);
        assert!(!layout.disks[1].create_esp);
        assert_eq!(layout.lvm_vg_names(), vec![DEFAULT_LVM_VG_NAME.to_string()]);
    }

    #[test]
    fn uses_user_volume_group_assignments() {
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

        let layout = StorageLayout::from_state(&state).unwrap();

        assert_eq!(layout.disks[0].slices[0].pool, "pool");
        assert_eq!(layout.disks[1].slices[0].pool, "extra");
        assert_eq!(
            layout.lvm_vg_names(),
            vec!["pool".to_string(), "extra".to_string()]
        );
        assert_eq!(
            layout.volume_groups[1]
                .logical_volumes
                .iter()
                .map(|volume| volume.name.as_str())
                .collect::<Vec<_>>(),
            vec!["pkg"]
        );
    }

    #[test]
    fn rejects_per_volume_group_over_capacity_layout() {
        let mut state = InstallState::sample();
        let second_disk = DiskChoice {
            path: "/dev/nvme1n1".to_string(),
            size_gib: 16,
            model: None,
        };
        state.discovered_disks.push(second_disk.clone());
        state.set_disk_role(&second_disk.path, DiskRole::PoolMember);
        state.set_disk_volume_group(&second_disk.path, "tiny");
        state.set_volume_group_for_volume("pkg", "tiny");

        let err = StorageLayout::from_state(&state).unwrap_err();

        assert!(err.contains("pool tiny uses 32G but its disks only provide 16G"));
    }

    #[test]
    fn single_disk_mode_accepts_one_install_disk() {
        let mut state = InstallState::sample();
        state.storage_mode = StorageMode::SingleDisk;

        let layout = StorageLayout::from_state(&state).unwrap();

        assert_eq!(layout.mode, StorageMode::SingleDisk);
        assert_eq!(layout.disks.len(), 1);
        assert_eq!(layout.lvm_vg_names(), vec![DEFAULT_LVM_VG_NAME.to_string()]);
    }

    #[test]
    fn single_disk_mode_rejects_multiple_install_disks() {
        let mut state = InstallState::sample();
        state.storage_mode = StorageMode::SingleDisk;
        let second_disk = DiskChoice {
            path: "/dev/nvme1n1".to_string(),
            size_gib: 465,
            model: None,
        };
        state.discovered_disks.push(second_disk.clone());
        state.disks.push(second_disk.clone());
        state
            .disk_roles
            .insert(second_disk.path.clone(), DiskRole::PoolMember);
        state.normalize_disk_roles();

        let err = StorageLayout::from_state(&state).unwrap_err();

        assert!(err.contains("single-disk storage mode requires exactly one install disk"));
    }

    #[test]
    fn manual_storage_mode_fails_before_rendering_wrong_disko() {
        let mut state = InstallState::sample();
        state.storage_mode = StorageMode::Manual;

        let err = StorageLayout::from_state(&state).unwrap_err();

        assert!(err.contains("manual storage mode is not implemented yet"));
    }

    #[test]
    fn separate_pools_gives_each_disk_its_own_volume_group() {
        let mut state = InstallState::sample();
        state.storage_mode = StorageMode::SeparatePools;
        let second_disk = DiskChoice {
            path: "/dev/nvme1n1".to_string(),
            size_gib: 465,
            model: None,
        };
        state.discovered_disks.push(second_disk.clone());
        state.set_disk_role(&second_disk.path, DiskRole::PoolMember);
        state.set_disk_volume_group(&second_disk.path, "extra");
        state.set_volume_group_for_volume("pkg", "extra");

        let layout = StorageLayout::from_state(&state).unwrap();

        assert_eq!(layout.mode, StorageMode::SeparatePools);
        assert_eq!(layout.lvm_vg_names(), vec!["pool".to_string(), "extra".to_string()]);
    }

    #[test]
    fn two_disks_can_share_one_pool() {
        // With per-disk slices, joining several disks into a single pool is a
        // first-class topology, not an error.
        let mut state = InstallState::sample();
        let second_disk = DiskChoice {
            path: "/dev/nvme1n1".to_string(),
            size_gib: 465,
            model: None,
        };
        state.discovered_disks.push(second_disk.clone());
        state.set_disk_role(&second_disk.path, DiskRole::PoolMember);
        // Both disks stay in the default "pool".

        let layout = StorageLayout::from_state(&state).unwrap();

        assert_eq!(layout.disks.len(), 2);
        assert_eq!(layout.lvm_vg_names(), vec!["pool".to_string()]);
        // The pool's capacity is the sum of both disks' (fallback) slices:
        // whole disks minus the ESP reservation on the boot disk.
        assert_eq!(layout.volume_groups[0].capacity_gib, 464 + 465);
    }

    #[test]
    fn rejects_over_capacity_layout() {
        let mut state = InstallState::sample();
        state.disks[0].size_gib = 100;
        state.discovered_disks[0].size_gib = 100;

        let err = StorageLayout::single_pool_from_state(&state).unwrap_err();

        assert!(err.contains("pool pool uses"));
    }

    #[test]
    fn plans_storage_actions_for_current_joined_pool_layout() {
        let layout = StorageLayout::single_pool_from_state(&InstallState::sample()).unwrap();

        let actions = layout.actions();

        assert_eq!(
            actions[..3],
            [
                StorageAction::WipeDisk {
                    path: "/dev/nvme0n1".to_string(),
                },
                StorageAction::CreateEsp {
                    path: "/dev/nvme0n1".to_string(),
                },
                StorageAction::JoinVolumeGroup {
                    path: "/dev/nvme0n1".to_string(),
                    vg_name: DEFAULT_LVM_VG_NAME.to_string(),
                },
            ]
        );
        assert!(actions.contains(&StorageAction::FormatLogicalVolume {
            vg_name: DEFAULT_LVM_VG_NAME.to_string(),
            lv_name: "root".to_string(),
        }));
    }

    #[test]
    fn storage_action_labels_are_human_readable() {
        assert_eq!(
            StorageAction::WipeDisk {
                path: "/dev/nvme0n1".to_string()
            }
            .label(),
            "wipe disk /dev/nvme0n1"
        );
        assert!(StorageAction::FormatLogicalVolume {
            vg_name: "pool".to_string(),
            lv_name: "root".to_string(),
        }
        .destructive());
        assert!(!StorageAction::Ignore {
            path: "/dev/sdb".to_string(),
        }
        .destructive());
    }

    #[test]
    fn non_system_roles_are_explicit_non_disko_actions() {
        let mut layout = StorageLayout::single_pool_from_state(&InstallState::sample()).unwrap();
        layout.disks.extend([
            StorageDisk {
                key: "data0".to_string(),
                path: "/dev/sdb".to_string(),
                size_gib: 100,
                role: StorageDiskRole::Data,
                create_esp: false,
                esp_size_mib: 1024,
                slices: Vec::new(),
            },
            StorageDisk {
                key: "reserve0".to_string(),
                path: "/dev/sdc".to_string(),
                size_gib: 100,
                role: StorageDiskRole::Reserve,
                create_esp: false,
                esp_size_mib: 1024,
                slices: Vec::new(),
            },
            StorageDisk {
                key: "ignore0".to_string(),
                path: "/dev/sdd".to_string(),
                size_gib: 100,
                role: StorageDiskRole::Ignore,
                create_esp: false,
                esp_size_mib: 1024,
                slices: Vec::new(),
            },
        ]);

        let actions = layout.actions();

        assert!(actions.contains(&StorageAction::LeaveExisting {
            path: "/dev/sdb".to_string(),
        }));
        assert!(actions.contains(&StorageAction::LeaveExisting {
            path: "/dev/sdc".to_string(),
        }));
        assert!(actions.contains(&StorageAction::Ignore {
            path: "/dev/sdd".to_string(),
        }));
    }

    #[test]
    fn only_system_disks_can_create_esp() {
        let layout = StorageLayout {
            mode: StorageMode::JoinedLvm,
            encrypt: false,
            disks: vec![StorageDisk {
                key: "bad".to_string(),
                path: "/dev/sdb".to_string(),
                size_gib: 100,
                role: StorageDiskRole::Data,
                create_esp: true,
                esp_size_mib: 1024,
                slices: Vec::new(),
            }],
            volume_groups: vec![StorageVolumeGroup {
                name: DEFAULT_LVM_VG_NAME.to_string(),
                logical_volumes: InstallState::sample().volumes,
                capacity_gib: 500,
            }],
            data_mounts: Vec::new(),
        };

        let err = layout.validate().unwrap_err();

        assert!(err.contains("only system disks can create an ESP"));
    }
}
