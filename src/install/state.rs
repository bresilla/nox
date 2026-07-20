//! Install configuration model. Retains multi-disk/role/storage-mode
//! capability the guided flow does not yet surface, so parts are dead for now.
#![allow(dead_code)]
use std::collections::BTreeMap;

pub const DEFAULT_STORAGE_POOL_NAME: &str = "pool";

#[derive(Debug, Clone)]
pub struct InstallState {
    pub current_step: InstallStep,
    pub scope: InstallScope,
    pub remote: String,
    pub hostname: String,
    pub timezone: String,
    /// EFI System Partition size in MiB (holds the bootloader).
    pub esp_size_mib: u64,
    pub install_user: String,
    pub mountpoint: String,
    pub role: InstallRole,
    pub allow_ssh: bool,
    pub overwrite_existing_storage: bool,
    pub network_route_cleanup: bool,
    /// Use LVM (pool disks into a volume group) vs a single plain-partition disk.
    pub use_lvm: bool,
    pub storage_mode: StorageMode,
    pub filesystem: Filesystem,
    pub encrypt: bool,
    pub doc_subvolumes: Vec<String>,
    pub discovered_disks: Vec<DiskChoice>,
    pub disks: Vec<DiskChoice>,
    pub disk_roles: BTreeMap<String, DiskRole>,
    pub volume_groups: Vec<VolumeGroupDraft>,
    /// Per-disk slices: device path → ordered slices assigned to pools. A disk
    /// with a single whole-disk slice is the common case; multiple slices split
    /// the disk across pools.
    pub disk_slices: BTreeMap<String, Vec<DiskSlice>>,
    pub volume_volume_groups: BTreeMap<String, String>,
    pub volumes: Vec<Volume>,
    /// Extra (non-install) disks to format + mount: disk path → mount point.
    pub data_mounts: BTreeMap<String, String>,
    /// All login accounts. `users[0]` is the primary and mirrors `install_user`
    /// / `user_password_hash` / `dotfiles_repo` for backward compatibility.
    pub users: Vec<UserAccount>,
    pub dotfiles_repo: Option<String>,
    pub skip_bin_ensure: bool,
    /// yescrypt hash for the primary user's password, or None to leave it unset.
    pub user_password_hash: Option<String>,
    pub secrets_ready: bool,
    /// How the shared system age key is obtained at install time.
    pub secrets_mode: SecretsMode,
}

/// Where the sops age key comes from — or the deliberate choice to install
/// without secrets (the target then gets `bresilla.secrets.enable = false`
/// and everything secret-dependent stays off until a key is added).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretsMode {
    /// Default: decrypt `host/secrets/key.txt` with the connected YubiKey
    /// (or `NX_AGE_KEY_FILE` when set).
    YubiKey,
    /// Use a plaintext age identity file at this path instead of a YubiKey.
    KeyFile(String),
    /// Install everything that does not need secrets; skip the rest.
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallStep {
    Target,
    Role,
    Disks,
    Pools,
    Volumes,
    Secrets,
    StoragePlan,
    Confirm,
    Install,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallRole {
    Laptop,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallScope {
    Remote,
    Local,
}

#[derive(Debug, Clone)]
pub struct DiskChoice {
    pub path: String,
    pub size_gib: u64,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskRole {
    System,
    PoolMember,
    Data,
    Reserve,
    Ignore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum StorageMode {
    SingleDisk,
    JoinedLvm,
    SeparatePools,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filesystem {
    Btrfs,
    Ext4,
}

impl Filesystem {
    pub fn title(self) -> &'static str {
        match self {
            Filesystem::Btrfs => "btrfs",
            Filesystem::Ext4 => "ext4",
        }
    }

    pub fn next(self) -> Self {
        match self {
            Filesystem::Btrfs => Filesystem::Ext4,
            Filesystem::Ext4 => Filesystem::Btrfs,
        }
    }
}

/// Default btrfs subvolumes carved out of a `/doc` volume, mirroring the shell
/// wizard's `code,data,self,work` layout mounted under `/doc/<name>`.
pub fn default_doc_subvolumes() -> Vec<String> {
    ["code", "data", "self", "work"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// Filesystem chosen for a single volume/partition (per-partition, not global).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeFs {
    Btrfs,
    Ext4,
    Xfs,
    Swap,
}

impl VolumeFs {
    pub fn title(self) -> &'static str {
        match self {
            VolumeFs::Btrfs => "btrfs",
            VolumeFs::Ext4 => "ext4",
            VolumeFs::Xfs => "xfs",
            VolumeFs::Swap => "swap",
        }
    }

    pub fn next(self) -> Self {
        match self {
            VolumeFs::Btrfs => VolumeFs::Ext4,
            VolumeFs::Ext4 => VolumeFs::Xfs,
            VolumeFs::Xfs => VolumeFs::Swap,
            VolumeFs::Swap => VolumeFs::Btrfs,
        }
    }

    pub fn is_btrfs(self) -> bool {
        matches!(self, VolumeFs::Btrfs)
    }
}

/// One btrfs subvolume: `@name` mounted at `mountpoint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subvolume {
    pub name: String,
    pub mountpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
    pub name: String,
    pub mountpoint: Mountpoint,
    pub size_gib: u64,
    /// This volume's own filesystem.
    pub fs: VolumeFs,
    /// Extra btrfs subvolumes beyond the always-present `@` root (btrfs only).
    pub subvolumes: Vec<Subvolume>,
    /// Takes whatever pool space the fixed-size partitions leave over (at most
    /// one per pool). Sizes the user typed are NEVER silently adjusted; the
    /// fill partition is the single, visible place slack goes.
    pub fill: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeGroupDraft {
    pub name: String,
}

/// A sized slice of one disk that becomes a physical volume in a pool (VG). A
/// disk may hold several slices in different pools — that is how "one disk, two
/// pools" is expressed. The last slice on a disk absorbs the remaining space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskSlice {
    pub pool: String,
    pub size_gib: u64,
}

/// Groups a user can be added to (beyond their own primary group, which NixOS
/// creates automatically). `corner` is this config's shared-files group.
pub const AVAILABLE_GROUPS: &[&str] = &[
    "wheel",
    "corner",
    "networkmanager",
    "video",
    "audio",
    "input",
    "dialout",
    "libvirtd",
    "docker",
    "plugdev",
    "flatpak",
];

/// Default extra groups for a new user.
pub fn default_user_groups() -> Vec<String> {
    ["wheel", "corner", "networkmanager", "video", "audio"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// One login account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAccount {
    pub name: String,
    /// yescrypt hash, or None for a password-less account.
    pub password_hash: Option<String>,
    pub dotfiles: Option<String>,
    /// Extra groups (the user's own primary group is implicit).
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mountpoint {
    Path(String),
    Swap,
}

impl InstallState {
    pub fn draft() -> Self {
        let volumes = default_volumes();
        Self {
            current_step: InstallStep::Target,
            scope: InstallScope::Remote,
            // Default target: the disposable test VM.
            remote: "nixos@192.168.122.107".to_string(),
            hostname: "novo".to_string(),
            timezone: "Europe/Amsterdam".to_string(),
            esp_size_mib: 1024,
            install_user: "bresilla".to_string(),
            mountpoint: "/mnt".to_string(),
            role: InstallRole::Laptop,
            allow_ssh: false,
            overwrite_existing_storage: false,
            network_route_cleanup: true,
            use_lvm: true,
            // A draft intentionally has no target disk. The TUI fills this
            // from facts; non-interactive calls must provide --disk. Never
            // carry a machine-specific device path into a destructive plan.
            storage_mode: StorageMode::SingleDisk,
            filesystem: Filesystem::Btrfs,
            encrypt: false,
            doc_subvolumes: default_doc_subvolumes(),
            discovered_disks: Vec::new(),
            disks: Vec::new(),
            disk_roles: BTreeMap::new(),
            volume_groups: default_volume_groups(),
            disk_slices: BTreeMap::new(),
            volume_volume_groups: default_volume_assignments(&volumes),
            volumes,
            data_mounts: BTreeMap::new(),
            users: vec![UserAccount {
                name: "bresilla".to_string(),
                password_hash: None,
                dotfiles: Some("https://github.com/bresilla/dot.git".to_string()),
                groups: default_user_groups(),
            }],
            dotfiles_repo: Some("https://github.com/bresilla/dot.git".to_string()),
            skip_bin_ensure: false,
            user_password_hash: None,
            secrets_ready: false,
            secrets_mode: SecretsMode::YubiKey,
        }
    }

    #[cfg(test)]
    pub fn sample() -> Self {
        let default_disk = DiskChoice {
            path: "/dev/nvme0n1".to_string(),
            size_gib: 465,
            model: None,
        };
        let disk_roles = BTreeMap::from([(default_disk.path.clone(), DiskRole::System)]);
        let volumes = sample_volumes();
        Self {
            current_step: InstallStep::Volumes,
            scope: InstallScope::Remote,
            remote: "nixos@10.10.10.7".to_string(),
            hostname: "novo".to_string(),
            timezone: "Europe/Amsterdam".to_string(),
            esp_size_mib: 1024,
            install_user: "bresilla".to_string(),
            mountpoint: "/mnt".to_string(),
            role: InstallRole::Laptop,
            allow_ssh: true,
            overwrite_existing_storage: false,
            network_route_cleanup: true,
            use_lvm: true,
            storage_mode: StorageMode::JoinedLvm,
            filesystem: Filesystem::Btrfs,
            encrypt: false,
            doc_subvolumes: default_doc_subvolumes(),
            discovered_disks: vec![default_disk.clone()],
            disks: vec![default_disk],
            disk_roles,
            volume_groups: default_volume_groups(),
            // Left empty: StorageLayout::assemble fills a whole-disk slice
            // (minus the ESP) into the default pool for the sample fixture.
            disk_slices: BTreeMap::new(),
            volume_volume_groups: default_volume_assignments(&volumes),
            volumes,
            data_mounts: BTreeMap::new(),
            users: vec![UserAccount {
                name: "bresilla".to_string(),
                password_hash: None,
                dotfiles: Some("https://github.com/bresilla/dot.git".to_string()),
                groups: default_user_groups(),
            }],
            dotfiles_repo: Some("https://github.com/bresilla/dot.git".to_string()),
            skip_bin_ensure: false,
            user_password_hash: None,
            secrets_ready: true,
            secrets_mode: SecretsMode::YubiKey,
        }
    }

    pub fn steps() -> &'static [InstallStep] {
        &[
            InstallStep::Target,
            InstallStep::Role,
            InstallStep::Disks,
            InstallStep::Pools,
            InstallStep::Volumes,
            InstallStep::Secrets,
            InstallStep::StoragePlan,
            InstallStep::Confirm,
            InstallStep::Install,
        ]
    }

    pub fn current_step_index(&self) -> usize {
        Self::steps()
            .iter()
            .position(|step| step == &self.current_step)
            .unwrap_or(0)
    }

    pub fn total_disk_gib(&self) -> u64 {
        self.disks.iter().map(|disk| disk.size_gib).sum()
    }

    pub fn used_gib(&self) -> u64 {
        self.volumes.iter().map(|volume| volume.size_gib).sum()
    }

    pub fn free_gib(&self) -> u64 {
        self.total_disk_gib().saturating_sub(self.used_gib())
    }

    /// Grow one volume to consume the disk (installer-style "use whole disk"), so
    /// the planned layout fills the target instead of leaving most of it free.
    /// Prefers `home`, then `root`, then the largest volume. No-op if the fixed
    /// volumes already exceed the disk.
    /// Mirror the primary account (`users[0]`) into the legacy scalar fields the
    /// rest of the pipeline reads. Call before generating config / building plans.
    pub fn sync_primary_user(&mut self) {
        if let Some(primary) = self.users.first() {
            self.install_user = primary.name.clone();
            self.user_password_hash = primary.password_hash.clone();
            self.dotfiles_repo = primary.dotfiles.clone();
        }
    }

    pub fn fit_volumes_to_disk(&mut self) {
        let total = self.total_disk_gib();
        if total == 0 || self.volumes.is_empty() {
            return;
        }
        let idx = self
            .volumes
            .iter()
            .position(|v| v.name == "home")
            .or_else(|| self.volumes.iter().position(|v| v.name == "root"))
            .or_else(|| {
                self.volumes
                    .iter()
                    .enumerate()
                    .max_by_key(|(_, v)| v.size_gib)
                    .map(|(i, _)| i)
            });
        let Some(idx) = idx else { return };
        let others: u64 = self
            .volumes
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != idx)
            .map(|(_, v)| v.size_gib)
            .sum();
        if total > others {
            self.volumes[idx].size_gib = total - others;
        }
    }

    pub fn used_ratio(&self) -> f64 {
        let total = self.total_disk_gib();
        if total == 0 {
            0.0
        } else {
            (self.used_gib() as f64 / total as f64).clamp(0.0, 1.0)
        }
    }

    pub fn visible_disks(&self) -> &[DiskChoice] {
        if self.discovered_disks.is_empty() {
            &self.disks
        } else {
            &self.discovered_disks
        }
    }

    pub fn disk_role_for_path(&self, path: &str) -> DiskRole {
        self.disk_roles
            .get(path)
            .copied()
            .or_else(|| {
                self.disks
                    .iter()
                    .position(|disk| disk.path == path)
                    .map(|index| {
                        if index == 0 {
                            DiskRole::System
                        } else {
                            DiskRole::PoolMember
                        }
                    })
            })
            .unwrap_or(DiskRole::Ignore)
    }

    /// Materialize the implicit default layout: an untouched install disk
    /// becomes one whole-disk slice in the default pool (minus the ESP
    /// reservation on the system disk) — the same rule StorageLayout::assemble
    /// applies at render time. Used before emitting a LIS document so the
    /// document states the layout explicitly.
    pub fn materialize_default_slices(&mut self) {
        let disks: Vec<(String, u64, DiskRole)> = self
            .visible_disks()
            .iter()
            .map(|disk| {
                (
                    disk.path.clone(),
                    disk.size_gib,
                    self.disk_role_for_path(&disk.path),
                )
            })
            .collect();
        for (path, size_gib, role) in disks {
            if self.slices_for_disk(&path).is_empty()
                && !self.disk_slices.contains_key(&path)
                && matches!(role, DiskRole::System | DiskRole::PoolMember)
            {
                let esp_gib = if role == DiskRole::System {
                    self.esp_size_mib.max(256).div_ceil(1024).max(1)
                } else {
                    0
                };
                self.disk_slices.insert(
                    path,
                    vec![DiskSlice {
                        pool: self.default_volume_group_name().to_string(),
                        size_gib: size_gib.saturating_sub(esp_gib),
                    }],
                );
            }
        }
    }

    // ── disk slices (disk → pools) ───────────────────────────────

    /// Size in GiB of a disk by path (from the selected/visible disk set).
    pub fn disk_size_gib(&self, path: &str) -> u64 {
        self.visible_disks()
            .iter()
            .find(|d| d.path == path)
            .map(|d| d.size_gib)
            .unwrap_or(0)
    }

    /// GiB reserved on a disk for the ESP (only the System/boot disk carries one).
    pub fn esp_reserved_gib(&self, path: &str) -> u64 {
        if self.disk_role_for_path(path) == DiskRole::System {
            self.esp_size_mib.div_ceil(1024).max(1)
        } else {
            0
        }
    }

    pub fn slices_for_disk(&self, path: &str) -> &[DiskSlice] {
        self.disk_slices.get(path).map(Vec::as_slice).unwrap_or(&[])
    }

    /// GiB of a disk already claimed by slices.
    pub fn disk_used_gib(&self, path: &str) -> u64 {
        self.slices_for_disk(path).iter().map(|s| s.size_gib).sum()
    }

    /// Unclaimed GiB on a disk (after the ESP and existing slices).
    pub fn disk_free_gib(&self, path: &str) -> u64 {
        self.disk_size_gib(path)
            .saturating_sub(self.esp_reserved_gib(path))
            .saturating_sub(self.disk_used_gib(path))
    }

    /// Total capacity of a pool: the sum of every slice assigned to it.
    pub fn pool_capacity_gib(&self, pool: &str) -> u64 {
        self.disk_slices
            .values()
            .flat_map(|slices| slices.iter())
            .filter(|s| s.pool == pool)
            .map(|s| s.size_gib)
            .sum()
    }

    /// Disks that contribute at least one slice to a pool.
    pub fn disks_in_pool(&self, pool: &str) -> Vec<String> {
        let mut disks: Vec<String> = self
            .disk_slices
            .iter()
            .filter(|(_, slices)| slices.iter().any(|s| s.pool == pool))
            .map(|(path, _)| path.clone())
            .collect();
        disks.sort();
        disks
    }

    /// Mark a disk as managed by the editor without allocating anything: it
    /// starts as pure free space the user pools up explicitly. The (empty)
    /// entry also tells the renderer NOT to fall back to a whole-disk default.
    pub fn ensure_disk_entry(&mut self, path: &str) {
        self.disk_slices.entry(path.to_string()).or_default();
    }

    /// Assign a whole disk (its free space) to a pool as a single slice, or grow
    /// the disk's existing slice for that pool.
    pub fn add_disk_slice(&mut self, path: &str, pool: &str, size_gib: u64) {
        let free = self.disk_free_gib(path);
        let size = size_gib.min(free);
        if size == 0 {
            return;
        }
        let slices = self.disk_slices.entry(path.to_string()).or_default();
        if let Some(existing) = slices.iter_mut().find(|s| s.pool == pool) {
            existing.size_gib += size;
        } else {
            slices.push(DiskSlice {
                pool: pool.to_string(),
                size_gib: size,
            });
        }
    }

    pub fn set_disk_role(&mut self, path: &str, role: DiskRole) {
        if role == DiskRole::System {
            for (other_path, other_role) in &mut self.disk_roles {
                if other_path != path && *other_role == DiskRole::System {
                    *other_role = DiskRole::PoolMember;
                }
            }
        }
        self.disk_roles.insert(path.to_string(), role);
        self.normalize_disk_roles();
    }

    pub fn normalize_disk_roles(&mut self) {
        let visible_disks = self.visible_disks().to_vec();
        let visible_paths = visible_disks
            .iter()
            .map(|disk| disk.path.clone())
            .collect::<std::collections::BTreeSet<_>>();

        self.disk_roles
            .retain(|path, _| visible_paths.contains(path));

        for (index, disk) in visible_disks.iter().enumerate() {
            self.disk_roles.entry(disk.path.clone()).or_insert_with(|| {
                if self.disks.iter().any(|selected| selected.path == disk.path) {
                    if index == 0 {
                        DiskRole::System
                    } else {
                        DiskRole::PoolMember
                    }
                } else {
                    DiskRole::Ignore
                }
            });
        }

        let mut system_seen = false;
        for disk in &visible_disks {
            if self.disk_roles.get(&disk.path) == Some(&DiskRole::System) {
                if system_seen {
                    self.disk_roles
                        .insert(disk.path.clone(), DiskRole::PoolMember);
                } else {
                    system_seen = true;
                }
            }
        }

        if !system_seen {
            let promote = visible_disks
                .iter()
                .find(|disk| self.disk_roles.get(&disk.path) == Some(&DiskRole::PoolMember))
                .or_else(|| visible_disks.first());
            if let Some(disk) = promote {
                self.disk_roles.insert(disk.path.clone(), DiskRole::System);
            }
        }

        self.disks = visible_disks
            .into_iter()
            .filter(|disk| {
                matches!(
                    self.disk_roles.get(&disk.path),
                    Some(DiskRole::System | DiskRole::PoolMember)
                )
            })
            .collect();
        self.normalize_storage_assignments();
    }

    pub fn default_volume_group_name(&self) -> &str {
        self.volume_groups
            .first()
            .map(|group| group.name.as_str())
            .unwrap_or(DEFAULT_STORAGE_POOL_NAME)
    }

    #[allow(dead_code)]
    pub fn ensure_volume_group(&mut self, name: &str) {
        if !self.volume_groups.iter().any(|group| group.name == name) {
            self.volume_groups.push(VolumeGroupDraft {
                name: name.to_string(),
            });
        }
        self.normalize_storage_assignments();
    }

    pub fn create_next_volume_group(&mut self) -> String {
        let mut index = 1;
        loop {
            let name = format!("{DEFAULT_STORAGE_POOL_NAME}{index}");
            if !self.volume_groups.iter().any(|group| group.name == name) {
                self.ensure_volume_group(&name);
                return name;
            }
            index += 1;
        }
    }

    pub fn rename_volume_group(&mut self, old_name: &str, new_name: &str) -> Result<(), String> {
        validate_volume_group_name(new_name)?;
        if old_name == new_name {
            return Ok(());
        }
        if self
            .volume_groups
            .iter()
            .any(|group| group.name == new_name)
        {
            return Err(format!("volume group already exists: {new_name}"));
        }
        let Some(group) = self
            .volume_groups
            .iter_mut()
            .find(|group| group.name == old_name)
        else {
            return Err(format!("volume group not found: {old_name}"));
        };
        group.name = new_name.to_string();
        for slices in self.disk_slices.values_mut() {
            for slice in slices.iter_mut() {
                if slice.pool == old_name {
                    slice.pool = new_name.to_string();
                }
            }
        }
        for value in self.volume_volume_groups.values_mut() {
            if value == old_name {
                *value = new_name.to_string();
            }
        }
        self.normalize_storage_assignments();
        Ok(())
    }

    pub fn delete_volume_group_reassigning_to_default(&mut self, name: &str) -> Result<(), String> {
        let default_group = self.default_volume_group_name().to_string();
        if name == default_group {
            return Err("default volume group cannot be deleted".to_string());
        }
        if !self.volume_groups.iter().any(|group| group.name == name) {
            return Err(format!("volume group not found: {name}"));
        }
        // The deleted pool's disk slices become free space; its partitions move
        // to the default pool so no user work is lost.
        for slices in self.disk_slices.values_mut() {
            slices.retain(|slice| slice.pool != name);
        }
        for value in self.volume_volume_groups.values_mut() {
            if value == name {
                *value = default_group.clone();
            }
        }
        self.volume_groups.retain(|group| group.name != name);
        self.normalize_storage_assignments();
        Ok(())
    }

    /// The pool of a disk's first slice, if any (whole-disk convenience view).
    /// A selected install disk with no explicit slices defaults to the default
    /// pool, matching how the layout materializes it.
    pub fn disk_volume_group_for_path(&self, path: &str) -> Option<&str> {
        if let Some(slice) = self.slices_for_disk(path).first() {
            return Some(slice.pool.as_str());
        }
        if matches!(
            self.disk_role_for_path(path),
            DiskRole::System | DiskRole::PoolMember
        ) {
            Some(self.default_volume_group_name())
        } else {
            None
        }
    }

    /// Replace all of a disk's slices with a single whole-disk slice in `pool`.
    #[allow(dead_code)]
    pub fn set_disk_volume_group(&mut self, path: &str, volume_group: &str) {
        self.ensure_volume_group(volume_group);
        let size = self
            .disk_size_gib(path)
            .saturating_sub(self.esp_reserved_gib(path));
        self.disk_slices.insert(
            path.to_string(),
            vec![DiskSlice {
                pool: volume_group.to_string(),
                size_gib: size,
            }],
        );
        self.normalize_storage_assignments();
    }

    pub fn volume_group_for_volume(&self, name: &str) -> &str {
        self.volume_volume_groups
            .get(name)
            .map(String::as_str)
            .unwrap_or_else(|| self.default_volume_group_name())
    }

    #[allow(dead_code)]
    pub fn set_volume_group_for_volume(&mut self, volume_name: &str, volume_group: &str) {
        self.ensure_volume_group(volume_group);
        self.volume_volume_groups
            .insert(volume_name.to_string(), volume_group.to_string());
        self.normalize_storage_assignments();
    }

    pub fn normalize_storage_assignments(&mut self) {
        if self.volume_groups.is_empty() {
            self.volume_groups.push(VolumeGroupDraft {
                name: DEFAULT_STORAGE_POOL_NAME.to_string(),
            });
        }

        let valid_groups = self
            .volume_groups
            .iter()
            .map(|group| group.name.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let default_group = self.default_volume_group_name().to_string();
        let selected_paths = self
            .disks
            .iter()
            .map(|disk| disk.path.clone())
            .collect::<std::collections::BTreeSet<_>>();

        // Drop slices for disks no longer selected.
        self.disk_slices
            .retain(|path, _| selected_paths.contains(path));
        // Reassign slices pointing at deleted pools to the default pool.
        for slices in self.disk_slices.values_mut() {
            for slice in slices.iter_mut() {
                if !valid_groups.contains(&slice.pool) {
                    slice.pool = default_group.clone();
                }
            }
        }
        // Clamp each disk's slices to its usable capacity. Deliberately NEVER
        // invents slices here: space the user freed stays free, so the map is
        // always truthful. Fresh disks get their whole-disk slice exactly once,
        // when they join the selection (see ensure_whole_disk_slice).
        for disk in &self.disks {
            let esp = self.esp_reserved_gib(&disk.path);
            let whole = disk.size_gib.saturating_sub(esp);
            if let Some(slices) = self.disk_slices.get_mut(&disk.path) {
                let mut budget = whole;
                for slice in slices.iter_mut() {
                    let take = slice.size_gib.min(budget);
                    slice.size_gib = take;
                    budget -= take;
                }
                slices.retain(|s| s.size_gib > 0);
            }
        }

        let volume_names = self
            .volumes
            .iter()
            .map(|volume| volume.name.clone())
            .collect::<std::collections::BTreeSet<_>>();
        self.volume_volume_groups
            .retain(|name, group| volume_names.contains(name) && valid_groups.contains(group));
        for volume in &self.volumes {
            self.volume_volume_groups
                .entry(volume.name.clone())
                .or_insert_with(|| default_group.clone());
        }
    }
}

/// The starting layout is EMPTY: the user creates every partition themselves.
/// Nothing — not even root — is pre-decided.
fn default_volumes() -> Vec<Volume> {
    Vec::new()
}

/// A rich fixture used only by tests: multiple volumes exercising per-volume
/// filesystems (btrfs, ext4, swap) and btrfs subvolumes. Kept separate from the
/// minimal production default so tests can assert on capacity, swap, and
/// subvolume rendering.
#[cfg(test)]
fn sample_volumes() -> Vec<Volume> {
    let root = Volume::filesystem("root", "/", 32).expect("root mountpoint is valid");
    let home = Volume::filesystem("home", "/home", 32).expect("home mountpoint is valid");
    let mut docs = Volume::filesystem("docs", "/doc", 128).expect("docs mountpoint is valid");
    docs.subvolumes = vec![
        Subvolume { name: "code".to_string(), mountpoint: "/doc/code".to_string() },
        Subvolume { name: "data".to_string(), mountpoint: "/doc/data".to_string() },
        Subvolume { name: "self".to_string(), mountpoint: "/doc/self".to_string() },
        Subvolume { name: "work".to_string(), mountpoint: "/doc/work".to_string() },
    ];
    let nix = Volume::filesystem("nix", "/nix", 160).expect("nix mountpoint is valid");
    let mut pkg = Volume::filesystem("pkg", "/pkg", 32).expect("pkg mountpoint is valid");
    pkg.fs = VolumeFs::Ext4;
    let swap = Volume::swap("swap", 64);
    vec![root, home, docs, nix, pkg, swap]
}

fn default_volume_groups() -> Vec<VolumeGroupDraft> {
    vec![VolumeGroupDraft {
        name: DEFAULT_STORAGE_POOL_NAME.to_string(),
    }]
}

fn default_volume_assignments(volumes: &[Volume]) -> BTreeMap<String, String> {
    volumes
        .iter()
        .map(|volume| (volume.name.clone(), DEFAULT_STORAGE_POOL_NAME.to_string()))
        .collect()
}

fn validate_volume_group_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err("volume group name cannot be empty".to_string());
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(format!("invalid volume group name: {name}"));
    }
    if chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
        Ok(())
    } else {
        Err(format!("invalid volume group name: {name}"))
    }
}

impl InstallStep {
    pub fn title(self) -> &'static str {
        match self {
            InstallStep::Target => "target",
            InstallStep::Role => "role",
            InstallStep::Disks => "disks",
            InstallStep::Pools => "pools",
            InstallStep::Volumes => "volumes",
            InstallStep::Secrets => "secrets",
            InstallStep::StoragePlan => "plan",
            InstallStep::Confirm => "confirm",
            InstallStep::Install => "install",
        }
    }
}

impl InstallRole {
    pub fn all() -> &'static [InstallRole] {
        &[InstallRole::Laptop, InstallRole::Server]
    }

    pub fn title(self) -> &'static str {
        match self {
            InstallRole::Laptop => "laptop",
            InstallRole::Server => "server",
        }
    }

    pub fn previous(self) -> Self {
        match self {
            InstallRole::Laptop => InstallRole::Server,
            InstallRole::Server => InstallRole::Laptop,
        }
    }

    pub fn next(self) -> Self {
        match self {
            InstallRole::Laptop => InstallRole::Server,
            InstallRole::Server => InstallRole::Laptop,
        }
    }
}

impl InstallScope {
    pub fn title(self) -> &'static str {
        match self {
            InstallScope::Remote => "remote",
            InstallScope::Local => "local",
        }
    }

    pub fn next(self) -> Self {
        match self {
            InstallScope::Remote => InstallScope::Local,
            InstallScope::Local => InstallScope::Remote,
        }
    }
}

impl DiskRole {
    pub fn title(self) -> &'static str {
        match self {
            DiskRole::System => "system",
            DiskRole::PoolMember => "pool",
            DiskRole::Data => "data",
            DiskRole::Reserve => "reserve",
            DiskRole::Ignore => "ignore",
        }
    }

    pub fn marker(self) -> &'static str {
        match self {
            DiskRole::System => "[S]",
            DiskRole::PoolMember => "[P]",
            DiskRole::Data => "[D]",
            DiskRole::Reserve => "[R]",
            DiskRole::Ignore => "[ ]",
        }
    }

    pub fn next(self) -> Self {
        match self {
            DiskRole::System => DiskRole::PoolMember,
            DiskRole::PoolMember => DiskRole::Data,
            DiskRole::Data => DiskRole::Reserve,
            DiskRole::Reserve => DiskRole::Ignore,
            DiskRole::Ignore => DiskRole::System,
        }
    }
}

impl StorageMode {
    pub fn title(self) -> &'static str {
        match self {
            StorageMode::SingleDisk => "single-disk",
            StorageMode::JoinedLvm => "joined-lvm",
            StorageMode::SeparatePools => "separate-pools",
            StorageMode::Manual => "manual",
        }
    }

    pub fn next_supported(self) -> Self {
        match self {
            StorageMode::SingleDisk => StorageMode::JoinedLvm,
            StorageMode::JoinedLvm => StorageMode::SingleDisk,
            StorageMode::SeparatePools | StorageMode::Manual => StorageMode::JoinedLvm,
        }
    }
}

impl Volume {
    pub fn filesystem(name: &str, mountpoint: &str, size_gib: u64) -> Result<Self, String> {
        validate_mountpoint(mountpoint)?;
        Ok(Self {
            name: name.to_string(),
            mountpoint: Mountpoint::Path(mountpoint.to_string()),
            size_gib,
            fs: VolumeFs::Btrfs,
            subvolumes: Vec::new(),
            fill: false,
        })
    }

    pub fn swap(name: &str, size_gib: u64) -> Self {
        Self {
            name: name.to_string(),
            mountpoint: Mountpoint::Swap,
            size_gib,
            fs: VolumeFs::Swap,
            subvolumes: Vec::new(),
            fill: false,
        }
    }
}

impl Mountpoint {
    pub fn label(&self) -> &str {
        match self {
            Mountpoint::Path(path) => path,
            Mountpoint::Swap => "swap",
        }
    }
}

pub fn validate_mountpoint(value: &str) -> Result<(), String> {
    if value == "/" {
        return Ok(());
    }
    if !value.starts_with('/') {
        return Err(format!("mountpoint must be absolute: {value}"));
    }
    if value.len() == 1 || value.ends_with('/') || value.contains("//") {
        return Err(format!("invalid mountpoint shape: {value}"));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_'))
    {
        return Err(format!(
            "mountpoint contains unsupported characters: {value}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        validate_mountpoint, DiskChoice, DiskRole, InstallRole, InstallState, StorageMode,
    };

    #[test]
    fn root_mountpoint_is_valid() {
        assert!(validate_mountpoint("/").is_ok());
    }

    #[test]
    fn rejects_relative_mountpoints() {
        assert!(validate_mountpoint("home").is_err());
        assert!(validate_mountpoint("swap").is_err());
    }

    #[test]
    fn rejects_weird_mountpoints() {
        assert!(validate_mountpoint("/home/user space").is_err());
        assert!(validate_mountpoint("/home/").is_err());
        assert!(validate_mountpoint("/home//cache").is_err());
    }

    #[test]
    fn computes_capacity_summary() {
        let state = InstallState::sample();
        assert_eq!(state.total_disk_gib(), 465);
        assert_eq!(state.used_gib(), 448);
        assert_eq!(state.free_gib(), 17);
        assert!(state.used_ratio() > 0.96);
    }

    #[test]
    fn role_titles_match_installer_values() {
        assert_eq!(InstallRole::Laptop.title(), "laptop");
        assert_eq!(InstallRole::Server.title(), "server");
    }

    #[test]
    fn storage_mode_titles_match_installer_values() {
        assert_eq!(StorageMode::SingleDisk.title(), "single-disk");
        assert_eq!(StorageMode::JoinedLvm.title(), "joined-lvm");
        assert_eq!(StorageMode::SeparatePools.title(), "separate-pools");
        assert_eq!(StorageMode::Manual.title(), "manual");
    }

    #[test]
    fn draft_starts_at_target_with_locked_secrets() {
        let state = InstallState::draft();
        assert_eq!(state.current_step.title(), "target");
        assert!(!state.secrets_ready);
        assert!(state.disks.is_empty());
        assert!(state.discovered_disks.is_empty());
        assert!(state.disk_roles.is_empty());
    }

    #[test]
    fn defaults_assign_all_install_storage_to_pool() {
        let state = InstallState::sample();

        assert_eq!(state.default_volume_group_name(), "pool");
        assert_eq!(
            state.disk_volume_group_for_path("/dev/nvme0n1"),
            Some("pool")
        );
        for volume in &state.volumes {
            assert_eq!(state.volume_group_for_volume(&volume.name), "pool");
        }
    }

    #[test]
    fn normalizes_storage_assignments_after_disk_roles_change() {
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

        assert_eq!(
            state.disk_volume_group_for_path(&second_disk.path),
            Some("extra")
        );
        assert_eq!(state.volume_group_for_volume("pkg"), "extra");

        state.set_disk_role(&second_disk.path, DiskRole::Ignore);

        assert_eq!(state.disk_volume_group_for_path(&second_disk.path), None);
        assert_eq!(state.volume_group_for_volume("pkg"), "extra");
    }

    #[test]
    fn creates_next_volume_group_name_without_collisions() {
        let mut state = InstallState::sample();

        assert_eq!(state.create_next_volume_group(), "pool1");
        assert_eq!(state.create_next_volume_group(), "pool2");
        assert!(state
            .volume_groups
            .iter()
            .any(|group| group.name == "pool1"));
        assert!(state
            .volume_groups
            .iter()
            .any(|group| group.name == "pool2"));
    }

    #[test]
    fn renames_volume_group_and_updates_assignments() {
        let mut state = InstallState::sample();
        state.ensure_volume_group("extra");
        state.set_disk_volume_group("/dev/nvme0n1", "extra");
        state.set_volume_group_for_volume("pkg", "extra");

        state.rename_volume_group("extra", "archive").unwrap();

        assert_eq!(
            state.disk_volume_group_for_path("/dev/nvme0n1"),
            Some("archive")
        );
        assert_eq!(state.volume_group_for_volume("pkg"), "archive");
        assert!(state
            .volume_groups
            .iter()
            .any(|group| group.name == "archive"));
        assert!(!state
            .volume_groups
            .iter()
            .any(|group| group.name == "extra"));
    }

    #[test]
    fn deletes_volume_group_by_reassigning_to_default() {
        let mut state = InstallState::sample();
        state.ensure_volume_group("extra");
        state.set_disk_volume_group("/dev/nvme0n1", "extra");
        state.set_volume_group_for_volume("pkg", "extra");

        state
            .delete_volume_group_reassigning_to_default("extra")
            .unwrap();

        assert_eq!(
            state.disk_volume_group_for_path("/dev/nvme0n1"),
            Some("pool")
        );
        assert_eq!(state.volume_group_for_volume("pkg"), "pool");
        assert!(!state
            .volume_groups
            .iter()
            .any(|group| group.name == "extra"));
    }

    #[test]
    fn rejects_deleting_default_volume_group() {
        let mut state = InstallState::sample();

        let err = state
            .delete_volume_group_reassigning_to_default("pool")
            .unwrap_err();

        assert!(err.contains("default volume group cannot be deleted"));
    }
}
