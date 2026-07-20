//! Guided install flow — one focused screen per decision, but with **every**
//! knob exposed. Simple choices (scope, role, filesystem, …) are one-question
//! cards; the storage layout is edited through four focused list editors
//! (disks, pools, volumes, doc-subvolumes), each tweaked one item/field at a
//! time. Nothing from the install model is hidden.

use std::collections::BTreeSet;
use std::sync::mpsc::{self, Receiver, TryRecvError};

use tui_input::{Input, InputRequest};

use crate::facts::TargetFacts;
use crate::install::preflight::PreflightReport;
use crate::install::state::{
    validate_mountpoint, DiskChoice, DiskRole, DiskSlice, Filesystem, InstallRole, InstallScope,
    InstallState, Mountpoint, StorageMode, Subvolume, UserAccount, Volume, VolumeFs,
    VolumeGroupDraft, DEFAULT_STORAGE_POOL_NAME,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Scope,
    Remote,
    Mountpoint,
    Hostname,
    #[allow(dead_code)]
    User,
    #[allow(dead_code)]
    Password,
    #[allow(dead_code)]
    PasswordConfirm,
    Role,
    Ssh,
    Locale,
    Lvm,
    Encrypt,
    // Filesystem is now chosen per-volume in the Storage editor, not globally.
    #[allow(dead_code)]
    Filesystem,
    // Disk selection + EFI are now folded into the single Storage editor.
    #[allow(dead_code)]
    Disks,
    #[allow(dead_code)]
    StorageMode,
    #[allow(dead_code)]
    Efi,
    Storage,
    ExtraDisks,
    // Retained for the generic editor + manual paths; the Storage two-panel
    // editor now covers pools/volumes in the default flow.
    #[allow(dead_code)]
    Pools,
    #[allow(dead_code)]
    Volumes,
    // Subvolumes are now per-btrfs-volume in the Storage editor, not a global step.
    #[allow(dead_code)]
    DocSubvols,
    Overwrite,
    NetworkCleanup,
    BinEnsure,
    Users,
    #[allow(dead_code)]
    Dotfiles,
    Review,
    Confirm,
}

impl Step {
    pub fn name(self) -> &'static str {
        match self {
            Step::Scope => "scope",
            Step::Remote => "remote",
            Step::Mountpoint => "mountpoint",
            Step::Hostname => "hostname",
            Step::User => "user",
            Step::Password => "password",
            Step::PasswordConfirm => "confirm password",
            Step::Role => "role",
            Step::Ssh => "ssh",
            Step::Locale => "locale",
            Step::Filesystem => "filesystem",
            Step::Encrypt => "encryption",
            Step::StorageMode => "storage mode",
            Step::Lvm => "lvm",
            Step::Disks => "disk",
            Step::Efi => "boot",
            Step::Storage => "storage",
            Step::ExtraDisks => "extra disks",
            Step::Pools => "pools",
            Step::Volumes => "volumes",
            Step::DocSubvols => "doc subvolumes",
            Step::Overwrite => "overwrite",
            Step::NetworkCleanup => "network cleanup",
            Step::BinEnsure => "bin provisioning",
            Step::Users => "users",
            Step::Dotfiles => "dotfiles",
            Step::Review => "review",
            Step::Confirm => "confirm",
        }
    }

    pub fn question(self) -> &'static str {
        match self {
            Step::Scope => "Where do you want to install?",
            Step::Remote => "Which machine? (user@host)",
            Step::Mountpoint => "Where is the target mounted?",
            Step::Hostname => "What should the machine be called?",
            Step::User => "What is your username?",
            Step::Password => "Set a login password",
            Step::PasswordConfirm => "Type the password again",
            Step::Role => "What kind of system is this?",
            Step::Ssh => "Enable the SSH server?",
            Step::Locale => "Where in the world are you?",
            Step::Filesystem => "Which filesystem?",
            Step::Encrypt => "Encrypt the disk?",
            Step::StorageMode => "How should storage be laid out?",
            Step::Lvm => "Use LVM?",
            Step::Disks => "Which disk(s) to install to?",
            Step::Efi => "EFI boot partition size?",
            Step::Storage => "Slice disks into pools, then partition a pool",
            Step::ExtraDisks => "Configure the remaining disks?",
            Step::Pools => "Volume groups (LVM pools)",
            Step::Volumes => "Logical volumes",
            Step::DocSubvols => "btrfs subvolumes under /doc",
            Step::Overwrite => "Existing data on the disk?",
            Step::NetworkCleanup => "Clean up competing network routes?",
            Step::BinEnsure => "Provision extra binaries after install?",
            Step::Users => "User accounts",
            Step::Dotfiles => "Dotfiles repository (optional)",
            Step::Review => "Review the plan",
            Step::Confirm => "Confirm — this will erase the disk",
        }
    }

    pub fn help(self) -> &'static str {
        match self {
            Step::Scope => "Local installs onto this machine; remote installs over SSH.",
            Step::Remote => "The target must be reachable over SSH with key auth.",
            Step::Mountpoint => "Where the new root is mounted during install (usually /mnt).",
            Step::Hostname => "Lowercase letters, digits and dashes.",
            Step::User => "Your primary account; gets sudo.",
            Step::Password => "Leave blank for a password-less account. Hidden as you type.",
            Step::PasswordConfirm => "Must match the password you just entered.",
            Step::Role => "Laptop adds a desktop; server is headless.",
            Step::Ssh => "Turn on the OpenSSH daemon at boot.",
            Step::Locale => "Sets the system timezone and clock.",
            Step::Filesystem => "btrfs supports subvolumes and snapshots; ext4 is simpler.",
            Step::Encrypt => "Full-disk encryption (LUKS), passphrase at boot.",
            Step::StorageMode => {
                "single-disk / joined-lvm are supported; the rest are experimental."
            }
            Step::Lvm => "LVM pools one or more disks into flexible volumes; plain uses a single disk.",
            Step::Disks => "space toggles a disk · every partition on selected disks is erased.",
            Step::Efi => "The ESP holds the bootloader, mounted at /boot/efi.",
            Step::Storage => "Review the plan here · e opens the editor (Enter dives in, Esc backs out).",
            Step::ExtraDisks => "Disks not used by the install — set a mount for each, or skip. Boot media is ignored.",
            Step::Pools => "One LVM volume group per pool. type rename · ^n add · ^x remove.",
            Step::Volumes => "↑↓ vol · ←→ field · space cycle · type edit · +/- size · ^n/^x.",
            Step::DocSubvols => "Subvolumes carved under /doc. type edit · ^n add · ^x remove.",
            Step::Overwrite => "Allow wiping an existing LVM volume group if one is present.",
            Step::NetworkCleanup => {
                "Remove extra default routes that can break the remote SSH link."
            }
            Step::BinEnsure => "Run the `bin` provisioner in the installed system (needs a token).",
            Step::Users => "↑↓ user · a add · d delete · n name · p password · f dotfiles · g groups.",
            Step::Dotfiles => "Cloned for your user after install. Leave blank to skip.",
            Step::Review => "Check the summary, then run preflight before continuing.",
            Step::Confirm => "Type the phrase exactly to unlock the install.",
        }
    }

    pub fn kind(self) -> StepKind {
        match self {
            Step::Scope
            | Step::Role
            | Step::Ssh
            | Step::Locale
            | Step::Lvm
            | Step::Filesystem
            | Step::Encrypt
            | Step::StorageMode
            | Step::Efi
            | Step::Overwrite
            | Step::NetworkCleanup
            | Step::BinEnsure => StepKind::Choice,
            Step::Remote | Step::Mountpoint | Step::Hostname | Step::User | Step::Dotfiles => {
                StepKind::Text
            }
            Step::Password | Step::PasswordConfirm => StepKind::Password,
            Step::Disks => StepKind::DiskSelect,
            Step::ExtraDisks => StepKind::ExtraDisks,
            Step::Users => StepKind::Users,
            Step::Storage => StepKind::Editor(Editor::Disks),
            Step::Pools => StepKind::Editor(Editor::Pools),
            Step::Volumes => StepKind::Editor(Editor::Volumes),
            Step::DocSubvols => StepKind::Editor(Editor::DocSubvols),
            Step::Review => StepKind::Review,
            Step::Confirm => StepKind::Confirm,
        }
    }
}

/// Curated timezone list for the locale step: (tz id, place, latitude, longitude).
/// The coordinates orient the globe and place the location pin.
pub const TIMEZONES: &[(&str, &str, f32, f32)] = &[
    ("UTC", "coordinated universal time", 0.0, 0.0),
    ("Europe/Amsterdam", "Netherlands", 52.37, 4.90),
    ("Europe/London", "United Kingdom", 51.51, -0.13),
    ("Europe/Berlin", "Germany", 52.52, 13.40),
    ("Europe/Tirane", "Albania", 41.33, 19.82),
    ("Europe/Belgrade", "Serbia / Balkans", 44.79, 20.45),
    ("Europe/Moscow", "Russia (west)", 55.75, 37.62),
    ("America/New_York", "US East", 40.71, -74.01),
    ("America/Chicago", "US Central", 41.88, -87.63),
    ("America/Los_Angeles", "US West", 34.05, -118.24),
    ("America/Sao_Paulo", "Brazil", -23.55, -46.63),
    ("Africa/Cairo", "Egypt", 30.04, 31.24),
    ("Asia/Dubai", "UAE / Gulf", 25.20, 55.27),
    ("Asia/Kolkata", "India", 28.61, 77.21),
    ("Asia/Shanghai", "China", 31.23, 121.47),
    ("Asia/Tokyo", "Japan", 35.68, 139.69),
    ("Australia/Sydney", "Australia (east)", -33.87, 151.21),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind {
    Choice,
    Text,
    Password,
    /// Multi-select (LVM) or single-select disk picker with checkboxes.
    DiskSelect,
    /// Per-disk mount configuration for disks not used by the install.
    ExtraDisks,
    /// Multi-user account editor.
    Users,
    Editor(Editor),
    Review,
    Confirm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Editor {
    Disks,
    Pools,
    Volumes,
    DocSubvols,
}

impl Editor {
    pub fn field_count(self) -> usize {
        match self {
            Editor::Disks => 4,   // role, pool, path, size
            Editor::Volumes => 4, // name, mount, pool, size
            Editor::Pools | Editor::DocSubvols => 1,
        }
    }

    pub fn field_name(self, field: usize) -> &'static str {
        match (self, field) {
            (Editor::Disks, 0) => "role",
            (Editor::Disks, 1) => "pool",
            (Editor::Disks, 2) => "path",
            (Editor::Disks, _) => "size",
            (Editor::Volumes, 0) => "name",
            (Editor::Volumes, 1) => "mount",
            (Editor::Volumes, 2) => "pool",
            (Editor::Volumes, _) => "size",
            (Editor::Pools, _) => "name",
            (Editor::DocSubvols, _) => "name",
        }
    }

    /// Whether the field is edited as free text (buffer-backed) vs cycled/adjusted.
    pub fn is_text(self, field: usize) -> bool {
        match self {
            Editor::Disks => matches!(field, 2 | 3),       // path, size
            Editor::Volumes => matches!(field, 0 | 1 | 3), // name, mount, size
            Editor::Pools | Editor::DocSubvols => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opt {
    pub label: String,
    pub desc: String,
}

/// The target connection is deliberately separate from install execution: a
/// remote target is contacted as soon as the address is accepted, not lazily
/// when the disk page happens to open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkState {
    Offline,
    Linking,
    Connected,
    Unreachable(String),
    Local,
}

enum LinkUpdate {
    Connected(TargetFacts),
    Unreachable(String),
}

/// Messages from the background preflight worker to the UI loop.
enum PreflightUpdate {
    Progress(String),
    Done(PreflightReport),
}

impl Opt {
    fn new(label: &str, desc: &str) -> Self {
        Self {
            label: label.to_string(),
            desc: desc.to_string(),
        }
    }
}

/// The storage editor is a nested set of full-screen sub-pages you drill through:
/// DISKS (sliced into pools) → POOLS → the selected pool's PARTITIONS. `Enter`
/// goes deeper, `Esc` walks back up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskStage {
    Disks,
    Pools,
    Partitions,
    Subvols,
}

impl DiskStage {
    pub fn title(self) -> &'static str {
        match self {
            DiskStage::Disks => "disks",
            DiskStage::Pools => "pools",
            DiskStage::Partitions => "partitions",
            DiskStage::Subvols => "subvolumes",
        }
    }
}

/// Which text field of a partition is being edited in the storage editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartField {
    Name,
    Mount,
}


/// Which text field of a btrfs subvolume is being edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubvolField {
    Name,
    Mount,
}

/// Tier inside the users editor window: the user list, or one user's detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStage {
    List,
    Detail,
}

/// Which footer button holds keyboard focus (subiquity-style: Tab reaches the
/// buttons, Enter activates the focused one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FooterFocus {
    Prev,
    Next,
}

// ── the universal `e` edit popup ────────────────────────────────

/// One editable field inside the popup.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum EditKind {
    /// Free text (name, mountpoint) — typed into `buf`.
    Text,
    /// Digits only (GiB sizes) — typed into `buf`.
    Number,
    /// One of a fixed set, cycled with ←/→/space.
    Choice { options: Vec<String>, idx: usize },
    /// Yes/no, flipped with ←/→/space.
    Toggle { on: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct EditField {
    pub label: &'static str,
    pub kind: EditKind,
    pub buf: String,
}

#[allow(dead_code)]
impl EditField {
    fn text(label: &'static str, value: &str) -> Self {
        Self {
            label,
            kind: EditKind::Text,
            buf: value.to_string(),
        }
    }
    fn number(label: &'static str, value: u64) -> Self {
        Self {
            label,
            kind: EditKind::Number,
            buf: value.to_string(),
        }
    }
    fn choice(label: &'static str, options: Vec<String>, current: &str) -> Self {
        let idx = options.iter().position(|o| o == current).unwrap_or(0);
        Self {
            label,
            kind: EditKind::Choice { options, idx },
            buf: String::new(),
        }
    }
    fn toggle(label: &'static str, on: bool) -> Self {
        Self {
            label,
            kind: EditKind::Toggle { on },
            buf: String::new(),
        }
    }
}

/// What the popup writes back to when applied.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum EditTarget {
    Disk { path: String },
    Slice { path: String, idx: usize },
    Volume { index: usize },
    Subvol { vol: usize, idx: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditPopup {
    pub title: String,
    pub target: EditTarget,
    pub fields: Vec<EditField>,
    pub cursor: usize,
}

pub struct Flow {
    pub state: InstallState,
    pub pos: usize,
    /// Highlighted option for Choice steps.
    pub cursor: usize,
    /// Editor item / field cursors.
    pub item: usize,
    pub field: usize,
    /// Working text buffer (Text/Password steps and the focused editor text field).
    pub buffer: String,
    /// Cursor-aware text state supplied by `tui-input`; `buffer` remains the
    /// serializable/editable value consumed by the installer model.
    text_input: Input,
    pub confirm_input: String,
    pub password: String,
    pub password_confirm: String,
    pub status: String,
    pub preflight: Option<PreflightReport>,
    preflight_rx: Option<Receiver<PreflightUpdate>>,
    /// The "no key found" chooser: YubiKey / age key file / install without
    /// secrets. Auto-opens when the secrets preflight check fails.
    pub secrets_popup: bool,
    pub secrets_key_edit: Option<String>,
    pub facts: Option<TargetFacts>,
    pub disk_error: Option<String>,
    pub link: LinkState,
    link_rx: Option<Receiver<LinkUpdate>>,
    /// Advanced disk/pool/volume editors are entered deliberately from the
    /// disk stage or the multi-disk layout choice.
    pub manual_storage: bool,
    /// Storage editor: which drill-down sub-page is showing, and the selection
    /// on each.
    pub disk_stage: DiskStage,
    /// True once the storage editor has been seeded, so leaving and re-entering
    /// the step preserves the user's slices/partitions instead of resetting.
    pub storage_ready: bool,
    /// Cursor on the DISKS page (index into installable_disks).
    pub disk_cursor: usize,
    /// Map cursor on the POOLS page: which disk row, and which segment on it
    /// (== slice count selects the trailing FREE segment).
    pub map_disk: usize,
    pub seg_sel: usize,
    /// Selected pool (POOLS page + the pool drilled into for partitions).
    pub pool_sel: usize,
    /// Cursor in the PARTITIONS view (index into volumes in the selected pool).
    pub vol_sel: usize,
    /// When editing a partition's name/mount, the in-progress text + field.
    pub disk_rename: Option<String>,
    pub disk_edit_field: PartField,
    /// Typing an exact size in GiB for the selected item on the current page.
    pub size_edit: Option<String>,
    /// Subvolume sub-editor: the target volume index (Some while open), the
    /// selected subvolume, and an in-progress name/mount edit.
    pub subvol_target: Option<usize>,
    pub subvol_sel: usize,
    pub subvol_edit: Option<(SubvolField, String)>,
    /// Cursor on the partition-detail page: rows 0..5 are the editable fields
    /// (name, mount, fs, size, rest), then the subvolume rows.
    pub part_cursor: usize,
    /// Vertical zone on the partitions page: 0 = pool name, 1 = pool size,
    /// 2 = the partition band.
    pub part_zone: usize,
    /// Inline edit of a pool field on the partitions page: (row, buffer).
    pub pool_edit: Option<(usize, String)>,
    /// Inline edit of a detail field: (row, buffer). Captures typing.
    pub detail_edit: Option<(usize, String)>,
    /// The universal `e` edit popup (Some while open).
    pub edit_popup: Option<EditPopup>,
    /// `?` shortcuts panel (toggled).
    pub help_open: bool,
    /// Keyboard focus on the footer buttons (Tab cycles; None = the page).
    pub footer_focus: Option<FooterFocus>,
    /// The modal storage-editor window (e on the storage step opens it; the
    /// tree lives entirely inside it, so Enter/Esc are free for the wizard
    /// outside).
    pub storage_popup: bool,
    /// The modal users-editor window — same pattern as storage.
    pub users_popup: bool,
    pub user_stage: UserStage,
    /// Cursor on the user-detail page: rows 0..3 are name/password/dotfiles,
    /// then one row per available group.
    pub user_row: usize,
    /// Inline edit of a user-detail field: (row, buffer).
    pub user_field_edit: Option<(usize, String)>,
    /// Disk paths selected for the install (multi for LVM, one for plain).
    pub disk_selected: BTreeSet<String>,
    /// Cursor + mount-edit state for the extra-disks step.
    pub extra_sel: usize,
    pub extra_edit: Option<String>,
    /// Users editor: selected user, an in-progress text field edit, and the
    /// group-selection cursor (Some while editing groups).
    pub user_sel: usize,
    pub done: bool,
    pub quit: bool,
    /// Test hook: skip the (impure) facts probe when entering the disk editor.
    pub disable_discovery: bool,
}

impl Flow {
    pub fn new(state: InstallState) -> Self {
        let mut flow = Self {
            state,
            pos: 0,
            cursor: 0,
            item: 0,
            field: 0,
            buffer: String::new(),
            text_input: Input::default(),
            confirm_input: String::new(),
            password: String::new(),
            password_confirm: String::new(),
            status: String::new(),
            preflight: None,
            preflight_rx: None,
            secrets_popup: false,
            secrets_key_edit: None,
            facts: None,
            disk_error: None,
            link: LinkState::Offline,
            link_rx: None,
            manual_storage: false,
            disk_stage: DiskStage::Disks,
            storage_ready: false,
            disk_cursor: 0,
            map_disk: 0,
            seg_sel: 0,
            pool_sel: 0,
            vol_sel: 0,
            disk_rename: None,
            disk_edit_field: PartField::Name,
            size_edit: None,
            subvol_target: None,
            subvol_sel: 0,
            subvol_edit: None,
            part_cursor: 0,
            part_zone: 2,
            pool_edit: None,
            detail_edit: None,
            edit_popup: None,
            help_open: false,
            footer_focus: None,
            storage_popup: false,
            users_popup: false,
            user_stage: UserStage::List,
            user_row: 0,
            user_field_edit: None,
            disk_selected: BTreeSet::new(),
            extra_sel: 0,
            extra_edit: None,
            user_sel: 0,
            done: false,
            quit: false,
            disable_discovery: false,
        };
        flow.load();
        flow
    }

    pub fn steps(&self) -> Vec<Step> {
        let mut steps = vec![Step::Scope];
        match self.state.scope {
            InstallScope::Remote => steps.push(Step::Remote),
            InstallScope::Local => steps.push(Step::Mountpoint),
        }
        // Machine identity + locale first.
        steps.extend([Step::Locale, Step::Hostname, Step::Role, Step::Ssh]);

        // Storage: decide the TYPE first (LVM? then LUKS?), then everything else
        // happens in ONE disk editor — pick the disks that make the pool (first
        // gets EFI), then carve partitions with per-partition fs + subvolumes.
        steps.extend([Step::Lvm, Step::Encrypt, Step::Storage]);
        steps.push(Step::Overwrite);
        // Remaining disks (not the install target, not boot media) → mounts.
        if !self.extra_disks().is_empty() {
            steps.push(Step::ExtraDisks);
        }

        // System extras.
        steps.extend([Step::NetworkCleanup, Step::BinEnsure]);

        // User accounts at the very end (name/password/dotfiles/groups per user).
        steps.push(Step::Users);

        steps.extend([Step::Review, Step::Confirm]);
        steps
    }

    pub fn current(&self) -> Step {
        let steps = self.steps();
        steps[self.pos.min(steps.len() - 1)]
    }

    pub fn prev_step(&self) -> Option<Step> {
        let steps = self.steps();
        self.pos.checked_sub(1).map(|i| steps[i])
    }

    pub fn next_step(&self) -> Option<Step> {
        self.steps().get(self.pos + 1).copied()
    }

    pub fn step_number(&self) -> (usize, usize) {
        (self.pos + 1, self.steps().len())
    }

    // ── choice options ──────────────────────────────────────────

    pub fn options(&self) -> Vec<Opt> {
        match self.current() {
            Step::Locale => TIMEZONES
                .iter()
                .map(|(tz, place, _, _)| Opt::new(tz, place))
                .collect(),
            Step::Scope => vec![
                Opt::new("local", "install onto this machine"),
                Opt::new("remote", "install onto another machine over SSH"),
            ],
            Step::Role => vec![
                Opt::new("laptop", "graphical desktop"),
                Opt::new("server", "headless"),
            ],
            Step::Ssh => vec![
                Opt::new("disabled", "no SSH server"),
                Opt::new("enabled", "start OpenSSH at boot"),
            ],
            Step::Filesystem => vec![
                Opt::new("btrfs", "subvolumes + snapshots"),
                Opt::new("ext4", "simple and battle-tested"),
            ],
            Step::Lvm => vec![
                Opt::new("LVM", "pool one or more disks into flexible volumes"),
                Opt::new("plain", "one disk, a single root partition"),
            ],
            Step::Encrypt => vec![
                Opt::new("no", "no disk encryption"),
                Opt::new("yes", "LUKS full-disk encryption"),
            ],
            Step::StorageMode => vec![
                Opt::new(
                    "use selected disk",
                    "erase one selected disk into one LVM pool",
                ),
                Opt::new(
                    "combine all disks",
                    "one LVM pool spanning every selected disk",
                ),
                Opt::new("one pool per disk", "keep selected disks as separate pools"),
                Opt::new("manual", "open the detailed disk, pool, and volume editors"),
            ],
            Step::Overwrite => vec![
                Opt::new("keep", "fail if an existing pool is present"),
                Opt::new("wipe", "remove any existing LVM volume group"),
            ],
            Step::NetworkCleanup => vec![
                Opt::new("yes", "drop competing default routes"),
                Opt::new("no", "leave routing untouched"),
            ],
            Step::BinEnsure => vec![
                Opt::new("skip", "do not run the bin provisioner"),
                Opt::new("run", "run bin ensure in the installed system"),
            ],
            Step::Disks => self
                .disk_choices()
                .iter()
                .map(|disk| {
                    let contents = self
                        .facts
                        .as_ref()
                        .and_then(|f| f.disks.iter().find(|d| d.path == disk.path))
                        .map(|d| d.content_summary())
                        .unwrap_or_else(|| "unknown".to_string());
                    Opt::new(
                        &disk.path,
                        &format!(
                            "{}G · {} · {}",
                            disk.size_gib,
                            disk.model.as_deref().unwrap_or("disk"),
                            contents
                        ),
                    )
                })
                .collect(),
            Step::Efi => vec![
                Opt::new("512 MiB", "minimal ESP"),
                Opt::new("1 GiB", "recommended — room for multiple kernels"),
                Opt::new("2 GiB", "generous"),
            ],
            _ => Vec::new(),
        }
    }

    /// Detected disks (or the current selection) for the disk picker.
    fn disk_choices(&self) -> Vec<DiskChoice> {
        if !self.state.discovered_disks.is_empty() {
            self.state.discovered_disks.clone()
        } else {
            self.state.disks.clone()
        }
    }

    // ── disk selection (multi-select) ────────────────────────────

    /// Disks that can be installed to / mounted — excludes the live boot media.
    pub fn installable_disks(&self) -> Vec<DiskChoice> {
        if let Some(facts) = &self.facts {
            facts
                .disks
                .iter()
                .filter(|d| !d.is_boot_media())
                .map(|d| DiskChoice {
                    path: d.path.clone(),
                    size_gib: d.size_bytes / (1024 * 1024 * 1024),
                    model: d.model.clone(),
                })
                .collect()
        } else {
            self.disk_choices()
        }
    }

    /// Content summary for a disk path from the facts probe.
    pub fn disk_contents(&self, path: &str) -> String {
        self.facts
            .as_ref()
            .and_then(|f| f.disks.iter().find(|d| d.path == path))
            .map(|d| d.content_summary())
            .unwrap_or_else(|| "unknown".to_string())
    }

    pub fn is_disk_selected(&self, path: &str) -> bool {
        self.disk_selected.contains(path)
    }

    /// Toggle a disk in the install set. For plain (no LVM) only one may be
    /// selected, so toggling one clears the rest.
    pub fn disk_toggle(&mut self, path: &str) {
        if self.disk_selected.contains(path) {
            self.disk_selected.remove(path);
        } else {
            if !self.state.use_lvm {
                self.disk_selected.clear();
            }
            self.disk_selected.insert(path.to_string());
        }
    }

    /// Disks detected but NOT chosen for the install (and not boot media) — the
    /// candidates for extra data mounts.
    pub fn extra_disks(&self) -> Vec<DiskChoice> {
        self.installable_disks()
            .into_iter()
            .filter(|d| !self.disk_selected.contains(&d.path))
            .collect()
    }

    // ── extra data-disk mounts ───────────────────────────────────

    pub fn extra_mount_of(&self, path: &str) -> Option<&str> {
        self.state.data_mounts.get(path).map(String::as_str)
    }

    pub fn extra_begin_edit(&mut self) {
        if let Some(disk) = self.extra_disks().get(self.extra_sel) {
            let current = self
                .state
                .data_mounts
                .get(&disk.path)
                .cloned()
                .unwrap_or_else(|| "/mnt/data".to_string());
            self.extra_edit = Some(current);
        }
    }

    pub fn extra_edit_insert(&mut self, ch: char) {
        if let Some(buf) = self.extra_edit.as_mut() {
            if !ch.is_control() && !ch.is_whitespace() {
                buf.push(ch);
            }
        }
    }

    pub fn extra_edit_backspace(&mut self) {
        if let Some(buf) = self.extra_edit.as_mut() {
            buf.pop();
        }
    }

    pub fn extra_apply_edit(&mut self) {
        let Some(buf) = self.extra_edit.take() else {
            return;
        };
        let buf = buf.trim().to_string();
        if let Some(disk) = self.extra_disks().get(self.extra_sel).cloned() {
            if buf.is_empty() || !buf.starts_with('/') {
                self.state.data_mounts.remove(&disk.path);
            } else {
                self.state.data_mounts.insert(disk.path, buf);
            }
        }
    }

    pub fn extra_cancel_edit(&mut self) {
        self.extra_edit = None;
    }

    pub fn extra_clear(&mut self) {
        if let Some(disk) = self.extra_disks().get(self.extra_sel).cloned() {
            self.state.data_mounts.remove(&disk.path);
        }
    }

    pub fn extra_sel_next(&mut self) {
        let n = self.extra_disks().len();
        if n > 0 {
            self.extra_sel = (self.extra_sel + 1) % n;
        }
    }

    pub fn extra_sel_prev(&mut self) {
        let n = self.extra_disks().len();
        if n > 0 {
            self.extra_sel = (self.extra_sel + n - 1) % n;
        }
    }

    // ── users editor ─────────────────────────────────────────────

    pub fn user_count(&self) -> usize {
        self.state.users.len()
    }

    pub fn users_sel_next(&mut self) {
        let n = self.user_count();
        if n > 0 {
            self.user_sel = (self.user_sel + 1) % n;
        }
    }

    pub fn users_sel_prev(&mut self) {
        let n = self.user_count();
        if n > 0 {
            self.user_sel = (self.user_sel + n - 1) % n;
        }
    }

    pub fn users_add(&mut self) {
        let name = unique_name(
            "user",
            &self.state.users.iter().map(|u| u.name.clone()).collect::<Vec<_>>(),
        );
        self.state.users.push(UserAccount {
            name,
            password_hash: None,
            dotfiles: None,
            groups: crate::install::state::default_user_groups(),
        });
        self.user_sel = self.state.users.len() - 1;
    }

    pub fn users_delete(&mut self) {
        // Keep at least the primary account.
        if self.state.users.len() > 1 {
            self.state.users.remove(self.user_sel);
            self.user_sel = self.user_sel.min(self.state.users.len() - 1);
        } else {
            self.status = "keep at least one user".to_string();
        }
    }


    /// Commit the multi-selected disks into the install layout (one pool across
    /// all of them for LVM; a single disk for plain).
    fn apply_disk_selection(&mut self) {
        let selected: Vec<DiskChoice> = self
            .installable_disks()
            .into_iter()
            .filter(|d| self.disk_selected.contains(&d.path))
            .collect();
        self.state.disks = selected.clone();
        self.state.disk_roles.clear();
        // Drop slices for disks that left the selection; keep the rest so a
        // user's split survives re-entering the editor.
        let keep: std::collections::BTreeSet<String> =
            selected.iter().map(|d| d.path.clone()).collect();
        self.state.disk_slices.retain(|path, _| keep.contains(path));
        for disk in &selected {
            self.state
                .disk_roles
                .insert(disk.path.clone(), DiskRole::System);
        }
        self.state.normalize_disk_roles();
        // A newly joined disk starts EMPTY — all free space, nothing allocated.
        // The user pools it up on the map; disks already carved keep their layout.
        for disk in &selected {
            self.state.ensure_disk_entry(&disk.path);
        }
        self.state.normalize_storage_assignments();
    }

    /// (latitude, longitude) of the currently highlighted timezone, for the
    /// globe on the locale step.
    pub fn locale_coords(&self) -> (f32, f32) {
        TIMEZONES
            .get(self.cursor)
            .map(|(_, _, lat, lon)| (*lat, *lon))
            .unwrap_or((0.0, 0.0))
    }

    // ── editor accessors ────────────────────────────────────────

    pub fn editor(&self) -> Option<Editor> {
        match self.current().kind() {
            StepKind::Editor(editor) => Some(editor),
            _ => None,
        }
    }

    pub fn item_count(&self) -> usize {
        match self.editor() {
            Some(Editor::Disks) => self.state.disks.len(),
            Some(Editor::Pools) => self.state.volume_groups.len(),
            Some(Editor::Volumes) => self.state.volumes.len(),
            Some(Editor::DocSubvols) => self.state.doc_subvolumes.len(),
            None => 0,
        }
    }

    fn pool_names(&self) -> Vec<String> {
        self.state
            .volume_groups
            .iter()
            .map(|g| g.name.clone())
            .collect()
    }

    // ── disk-stage pool/volume editor ────────────────────────────

    #[allow(dead_code)]
    pub fn pool_count(&self) -> usize {
        self.state.volume_groups.len()
    }

    pub fn selected_pool_name(&self) -> Option<String> {
        self.state
            .volume_groups
            .get(self.pool_sel)
            .map(|g| g.name.clone())
    }

    /// Indices into `state.volumes` for volumes assigned to the selected pool.
    pub fn volumes_in_selected_pool(&self) -> Vec<usize> {
        let Some(pool) = self.selected_pool_name() else {
            return Vec::new();
        };
        self.state
            .volumes
            .iter()
            .enumerate()
            .filter(|(_, v)| self.state.volume_group_for_volume(&v.name) == pool)
            .map(|(i, _)| i)
            .collect()
    }

    /// A pool's capacity is the sum of the disk slices assigned to it.
    pub fn pool_capacity_gib(&self, pool: &str) -> u64 {
        self.state.pool_capacity_gib(pool)
    }

    #[allow(dead_code)]
    pub fn pool_used_gib(&self, pool: &str) -> u64 {
        self.state
            .volumes
            .iter()
            .filter(|v| self.state.volume_group_for_volume(&v.name) == pool)
            .map(|v| v.size_gib)
            .sum()
    }

    // ── sub-page navigation (disks → pools → partitions) ────────

    pub fn goto_disks(&mut self) {
        self.disk_stage = DiskStage::Disks;
        self.subvol_target = None;
        self.status.clear();
        let n = self.installable_disks().len();
        if n > 0 {
            self.disk_cursor = self.disk_cursor.min(n - 1);
        }
    }

    pub fn goto_pools(&mut self) {
        self.disk_stage = DiskStage::Pools;
        self.subvol_target = None;
        self.status.clear();
        let n = self.map_disks().len();
        if n > 0 {
            self.map_disk = self.map_disk.min(n - 1);
        }
        self.clamp_seg();
    }

    /// `Enter` = go INSIDE the selected thing, one tier deeper. The wizard
    /// itself only moves with ‹ / ›.
    /// disks → pools(map) → (segment's pool) partitions → (btrfs) subvolumes.
    pub fn storage_forward(&mut self) {
        match self.disk_stage {
            DiskStage::Disks => self.goto_pools(),
            DiskStage::Pools => {
                // Enter the pool under the cursor segment.
                if let Some((path, idx)) = self.selected_slice() {
                    let pool = self.state.slices_for_disk(&path)[idx].pool.clone();
                    if let Some(i) = self
                        .state
                        .volume_groups
                        .iter()
                        .position(|g| g.name == pool)
                    {
                        self.pool_sel = i;
                    }
                    self.pool_enter();
                } else {
                    self.status =
                        "free space — p joins it to the pool · a makes a new pool".to_string();
                }
            }
            DiskStage::Partitions => self.subvols_enter(),
            DiskStage::Subvols => {
                self.status = "deepest level — esc goes back up · › continues".to_string();
            }
        }
    }

    /// Enter the selected btrfs partition's SUBVOLUMES tier.
    pub fn subvols_enter(&mut self) {
        let Some(i) = self.selected_volume_index() else {
            self.status = "free space — a adds a partition here".to_string();
            return;
        };
        if !self.state.volumes[i].fs.is_btrfs() {
            self.status = "only btrfs partitions hold subvolumes (e edits the fs)".to_string();
            return;
        }
        self.subvol_target = Some(i);
        self.subvol_sel = 0;
        self.subvol_edit = None;
        self.part_cursor = 0;
        self.disk_stage = DiskStage::Subvols;
        self.detail_focus_row();
        self.status.clear();
    }

    /// Rows on the partition-detail page: 5 fields + root subvol + extras.
    pub fn detail_row_count(&self) -> usize {
        let subs = self
            .subvol_target
            .and_then(|i| self.state.volumes.get(i))
            .map(|v| if v.fs.is_btrfs() { 1 + v.subvolumes.len() } else { 0 })
            .unwrap_or(0);
        5 + subs
    }

    /// ↑/↓ save whatever is being typed and drop the cursor straight into the
    /// next field's buffer — fields edit directly, no `e` needed.
    pub fn detail_sel_next(&mut self) {
        self.detail_edit_commit();
        let n = self.detail_row_count();
        if n > 0 {
            self.part_cursor = (self.part_cursor + 1) % n;
        }
        self.sync_subvol_sel();
        self.detail_focus_row();
    }

    pub fn detail_sel_prev(&mut self) {
        self.detail_edit_commit();
        let n = self.detail_row_count();
        if n > 0 {
            self.part_cursor = (self.part_cursor + n - 1) % n;
        }
        self.sync_subvol_sel();
        self.detail_focus_row();
    }

    /// Text rows (name/mount/size) keep a live edit buffer while the cursor
    /// sits on them; fs/rest/subvol rows have none (enter cycles/toggles).
    pub fn detail_focus_row(&mut self) {
        self.detail_edit = None;
        if matches!(self.part_cursor, 0 | 1 | 3) {
            self.detail_edit_row();
        }
    }

    /// Save the live buffer when the cursor leaves a field; invalid values
    /// revert with a status message instead of blocking.
    pub fn detail_edit_commit(&mut self) {
        self.detail_edit_apply();
        self.detail_edit = None;
    }

    /// Keep subvol_sel following the cursor for a/d on subvolume rows.
    fn sync_subvol_sel(&mut self) {
        // Row 5 is the root subvolume (fixed); extras start at 6.
        if self.part_cursor >= 6 {
            self.subvol_sel = self.part_cursor - 6;
        }
    }

    /// `e` on a detail row: edit that value in place. Text/number rows open an
    /// inline buffer (Enter commits, Esc cancels); fs cycles; rest toggles.
    pub fn detail_edit_row(&mut self) {
        let Some(i) = self.subvol_target else { return };
        match self.part_cursor {
            0 => {
                self.detail_edit = Some((0, self.state.volumes[i].name.clone()));
            }
            1 => {
                self.detail_edit =
                    Some((1, self.state.volumes[i].mountpoint.label().to_string()));
            }
            2 => {
                // fs cycles immediately (mount/subvols follow, as everywhere).
                let vol_sel_backup = self.vol_sel;
                self.vol_sel = self
                    .volumes_in_selected_pool()
                    .iter()
                    .position(|&j| j == i)
                    .unwrap_or(0);
                self.disk_stage = DiskStage::Partitions;
                self.disk_cycle_fs();
                self.disk_stage = DiskStage::Subvols;
                self.vol_sel = vol_sel_backup;
            }
            3 => {
                self.detail_edit = Some((3, self.state.volumes[i].size_gib.to_string()));
            }
            4 => {
                // rest toggles.
                if self.state.volumes[i].fill {
                    self.state.volumes[i].fill = false;
                } else if self.state.volumes[i].fs == VolumeFs::Swap {
                    self.status = "swap keeps a fixed size".to_string();
                } else {
                    let pool = self
                        .state
                        .volume_group_for_volume(&self.state.volumes[i].name)
                        .to_string();
                    let members: Vec<usize> = self
                        .state
                        .volumes
                        .iter()
                        .enumerate()
                        .filter(|(_, v)| {
                            self.state.volume_group_for_volume(&v.name) == pool
                        })
                        .map(|(j, _)| j)
                        .collect();
                    for j in members {
                        self.state.volumes[j].fill = false;
                    }
                    self.state.volumes[i].fill = true;
                }
            }
            5 => {
                self.status = "the root subvolume is fixed — a adds extra ones".to_string();
            }
            _ => {
                // Extra subvolume row: edit its name (m edits the mount).
                self.subvol_begin_edit(SubvolField::Name);
            }
        }
    }

    pub fn detail_edit_insert(&mut self, ch: char) {
        if let Some((row, buf)) = self.detail_edit.as_mut() {
            let ok = match row {
                3 => ch.is_ascii_digit(),
                _ => !ch.is_control() && !ch.is_whitespace(),
            };
            if ok && buf.len() < 40 {
                buf.push(ch);
            }
        }
    }

    pub fn detail_edit_backspace(&mut self) {
        if let Some((_, buf)) = self.detail_edit.as_mut() {
            buf.pop();
        }
    }

    pub fn detail_edit_apply(&mut self) {
        let Some((row, value)) = self.detail_edit.clone() else {
            return;
        };
        let Some(i) = self.subvol_target else { return };
        let value = value.trim().to_string();
        let result: std::result::Result<(), String> = (|| {
            match row {
                0 => {
                    if value.is_empty() {
                        return Err("name cannot be empty".into());
                    }
                    let old = self.state.volumes[i].name.clone();
                    if value != old {
                        if self.state.volumes.iter().any(|v| v.name == value) {
                            return Err(format!("partition {value} already exists"));
                        }
                        self.rename_volume(&old, &value);
                    }
                }
                1 => {
                    if value == "swap" {
                        self.state.volumes[i].mountpoint = Mountpoint::Swap;
                        self.state.volumes[i].fs = VolumeFs::Swap;
                        self.state.volumes[i].subvolumes.clear();
                    } else {
                        validate_mountpoint(&value)?;
                        self.state.volumes[i].mountpoint = Mountpoint::Path(value.clone());
                        if self.state.volumes[i].fs == VolumeFs::Swap {
                            self.state.volumes[i].fs = VolumeFs::Btrfs;
                        }
                    }
                }
                3 => {
                    let val: u64 = value
                        .parse()
                        .map_err(|_| "size must be a number".to_string())?;
                    // Only an actual change unsets fill — the cursor commits
                    // this row every time it passes through.
                    if val.max(1) != self.state.volumes[i].size_gib {
                        self.state.volumes[i].size_gib = val.max(1);
                        self.state.volumes[i].fill = false;
                    }
                }
                _ => {}
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.detail_edit = None;
                self.status.clear();
            }
            Err(err) => self.status = err,
        }
    }

    /// Open the modal storage editor (e on the storage overview).
    pub fn storage_popup_open(&mut self) {
        self.storage_popup = true;
        self.goto_disks();
    }

    /// `Esc` inside the editor: walk one tier up. It never leaves the window —
    /// only `f` (finish, at the top, with a / mount) does.
    pub fn storage_back(&mut self) {
        match self.disk_stage {
            DiskStage::Subvols => {
                self.detail_edit_commit();
                self.subvol_target = None;
                self.subvol_edit = None;
                self.disk_stage = DiskStage::Partitions;
            }
            DiskStage::Partitions => {
                self.pool_edit_commit();
                self.goto_pools();
            }
            DiskStage::Pools => self.goto_disks(),
            DiskStage::Disks => {
                self.status = if self.storage_has_root() {
                    "top of the tree — f finishes".to_string()
                } else {
                    "top of the tree — build a / mount, then f finishes".to_string()
                };
            }
        }
    }

    /// `f` at the TOP of the tree, once something mounts at `/`: close the
    /// editor. The only exit (q quits everything, as everywhere).
    pub fn storage_finish(&mut self) {
        if self.disk_stage != DiskStage::Disks {
            self.status = "climb to the top of the tree first (esc)".to_string();
            return;
        }
        if !self.storage_has_root() {
            self.status = "nothing mounts at / yet — build a root first".to_string();
            return;
        }
        self.storage_popup = false;
        self.status.clear();
    }

    // ── the users editor window (same pattern as storage) ────────

    pub fn users_popup_open(&mut self) {
        self.users_popup = true;
        self.user_stage = UserStage::List;
        self.user_field_edit = None;
        self.status.clear();
    }

    /// `f` on the user list: close the editor (every user needs a name).
    pub fn users_finish(&mut self) {
        if self.user_stage == UserStage::List {
            if self.state.users.iter().any(|u| u.name.trim().is_empty()) {
                self.status = "every user needs a name".to_string();
                return;
            }
            self.state.sync_primary_user();
            self.users_popup = false;
            self.status.clear();
        } else {
            self.status = "go back to the user list first (esc)".to_string();
        }
    }

    /// Enter the selected user's detail page. The cursor lands on the first
    /// field with its edit buffer already open — fields edit directly, no `e`.
    pub fn users_enter(&mut self) {
        if self.state.users.get(self.user_sel).is_some() {
            self.user_stage = UserStage::Detail;
            self.user_row = 0;
            self.user_focus_row();
            self.status.clear();
        }
    }

    /// Esc inside the users editor: detail → list; the list hints at f.
    pub fn users_back(&mut self) {
        match self.user_stage {
            UserStage::Detail => {
                self.user_field_commit();
                self.user_stage = UserStage::List;
            }
            UserStage::List => {
                self.status = "f finishes".to_string();
            }
        }
    }

    pub fn user_detail_row_count(&self) -> usize {
        3 + crate::install::state::AVAILABLE_GROUPS.len()
    }

    /// ↑/↓ on the detail page: save whatever is being typed, move, and put
    /// the cursor straight into the next field's buffer.
    pub fn user_row_next(&mut self) {
        self.user_field_commit();
        let n = self.user_detail_row_count();
        self.user_row = (self.user_row + 1) % n;
        self.user_focus_row();
    }

    pub fn user_row_prev(&mut self) {
        self.user_field_commit();
        let n = self.user_detail_row_count();
        self.user_row = (self.user_row + n - 1) % n;
        self.user_focus_row();
    }

    /// Text rows (name/password/dotfiles) keep a live edit buffer while the
    /// cursor sits on them; group rows have none (space toggles).
    pub fn user_focus_row(&mut self) {
        self.user_field_edit = None;
        if self.user_row <= 2 {
            self.user_edit_row();
        }
    }

    /// Save the live buffer when the cursor leaves a field. Invalid values
    /// (empty/duplicate name) revert with a status message instead of blocking.
    pub fn user_field_commit(&mut self) {
        self.user_field_apply();
        self.user_field_edit = None;
    }

    /// `e` on a user-detail row: edit the field in place, or toggle the group.
    pub fn user_edit_row(&mut self) {
        let Some(user) = self.state.users.get(self.user_sel) else {
            return;
        };
        match self.user_row {
            0 => self.user_field_edit = Some((0, user.name.clone())),
            1 => self.user_field_edit = Some((1, String::new())),
            2 => {
                self.user_field_edit =
                    Some((2, user.dotfiles.clone().unwrap_or_default()));
            }
            row => {
                let group = crate::install::state::AVAILABLE_GROUPS[row - 3];
                let user = &mut self.state.users[self.user_sel];
                if let Some(pos) = user.groups.iter().position(|g| g == group) {
                    user.groups.remove(pos);
                } else {
                    user.groups.push(group.to_string());
                }
                self.state.sync_primary_user();
            }
        }
    }

    pub fn user_field_insert(&mut self, ch: char) {
        if let Some((row, buf)) = self.user_field_edit.as_mut() {
            let ok = match row {
                0 => !ch.is_control() && !ch.is_whitespace(),
                _ => !ch.is_control(),
            };
            if ok && buf.len() < 60 {
                buf.push(ch);
            }
        }
    }

    pub fn user_field_backspace(&mut self) {
        if let Some((_, buf)) = self.user_field_edit.as_mut() {
            buf.pop();
        }
    }

    pub fn user_field_apply(&mut self) {
        let Some((row, value)) = self.user_field_edit.clone() else {
            return;
        };
        let result: std::result::Result<(), String> = (|| {
            match row {
                0 => {
                    let value = value.trim();
                    if value.is_empty() {
                        return Err("name cannot be empty".into());
                    }
                    if self
                        .state
                        .users
                        .iter()
                        .enumerate()
                        .any(|(i, u)| i != self.user_sel && u.name == value)
                    {
                        return Err(format!("user {value} already exists"));
                    }
                    self.state.users[self.user_sel].name = value.to_string();
                }
                1 => {
                    // An untouched (empty) buffer means "keep the password" —
                    // the cursor passes through this row on every ↑↓ walk.
                    if !value.is_empty() {
                        let hash = crate::install::secrets::hash_password(&value)?;
                        self.state.users[self.user_sel].password_hash = Some(hash);
                    }
                }
                2 => {
                    let value = value.trim();
                    self.state.users[self.user_sel].dotfiles = if value.is_empty() {
                        None
                    } else {
                        Some(value.to_string())
                    };
                }
                _ => {}
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.state.sync_primary_user();
                self.user_field_edit = None;
                self.status.clear();
            }
            Err(err) => self.status = err,
        }
    }

    /// Tab: page → [ next › ] → [ ‹ prev ] → page. Enter then activates the
    /// focused button — the subiquity/debian-installer pattern.
    pub fn footer_cycle(&mut self, forward: bool) {
        use FooterFocus::*;
        self.footer_focus = if forward {
            match self.footer_focus {
                None => Some(Next),
                Some(Next) => Some(Prev),
                Some(Prev) => None,
            }
        } else {
            match self.footer_focus {
                None => Some(Prev),
                Some(Prev) => Some(Next),
                Some(Next) => None,
            }
        };
    }

    /// Whether Enter can go INSIDE the current selection in the editor —
    /// powers the window's "in ›" button state.
    pub fn can_drill(&self) -> bool {
        match self.disk_stage {
            DiskStage::Disks => true,
            DiskStage::Pools => self.selected_slice().is_some(),
            DiskStage::Partitions => self
                .selected_volume_index()
                .map(|i| self.state.volumes[i].fs.is_btrfs())
                .unwrap_or(false),
            DiskStage::Subvols => false,
        }
    }

    /// Whether ‹ (previous step) is possible right now.
    pub fn can_prev(&self) -> bool {
        self.pos > 0
    }

    /// Whether › (next step) is possible right now — the button's lit state.
    pub fn can_next(&self) -> bool {
        if self.current() == Step::Storage {
            return self.storage_has_root();
        }
        match self.current().kind() {
            StepKind::Confirm => false, // installing happens via the typed phrase + enter
            StepKind::Text | StepKind::Password => !self.buffer.trim().is_empty(),
            // Review only continues once preflight has run and passed.
            StepKind::Review => self.preflight.as_ref().is_some_and(PreflightReport::pass),
            _ => true,
        }
    }

    /// True while a sub-editor is capturing raw typing (popup, renames, sizes,
    /// user fields…) — the global ‹ › ? keys stay out of the way then.
    pub fn capturing_text(&self) -> bool {
        self.edit_popup.is_some()
            || self.size_edit.is_some()
            || self.disk_rename.is_some()
            || self.pool_edit.is_some()
            || self.detail_edit.is_some()
            || self.user_field_edit.is_some()
            || self.secrets_key_edit.is_some()
            || self.subvol_edit.is_some()
            || self.extra_edit.is_some()
    }

    // ── DISKS page: plain checkbox selection ────────────────────

    /// The disk under the page-1 cursor.
    pub fn cursor_disk(&self) -> Option<String> {
        self.installable_disks()
            .get(self.disk_cursor)
            .map(|d| d.path.clone())
    }

    /// Toggle the disk under the cursor into/out of the install. The last
    /// install disk cannot be removed.
    pub fn disk_row_toggle_selected(&mut self) {
        let Some(path) = self.cursor_disk() else {
            return;
        };
        if self.disk_selected.contains(&path) && self.disk_selected.len() == 1 {
            self.status = "keep at least one disk in the install".to_string();
            return;
        }
        self.disk_toggle(&path);
        self.apply_disk_selection();
    }

    // ── POOLS page: the disk↔pool segment map ───────────────────

    /// Disks shown on the map (the selected install disks, in discovery order).
    pub fn map_disks(&self) -> Vec<String> {
        self.installable_disks()
            .into_iter()
            .filter(|d| self.disk_selected.contains(&d.path))
            .map(|d| d.path)
            .collect()
    }

    /// The disk row the map cursor is on.
    pub fn map_disk_path(&self) -> Option<String> {
        self.map_disks().get(self.map_disk).cloned()
    }

    /// Segments on a disk row: its slices, plus one trailing FREE segment when
    /// unclaimed space remains.
    pub fn seg_count(&self, path: &str) -> usize {
        let slices = self.state.slices_for_disk(path).len();
        slices + usize::from(self.state.disk_free_gib(path) > 0)
    }

    /// True when the map cursor sits on the FREE segment of its disk row.
    pub fn on_free_segment(&self) -> bool {
        let Some(path) = self.map_disk_path() else {
            return false;
        };
        self.seg_sel >= self.state.slices_for_disk(&path).len()
            && self.state.disk_free_gib(&path) > 0
    }

    /// The (disk, slice_index) under the map cursor; None on a FREE segment.
    pub fn selected_slice(&self) -> Option<(String, usize)> {
        let path = self.map_disk_path()?;
        if self.seg_sel < self.state.slices_for_disk(&path).len() {
            Some((path, self.seg_sel))
        } else {
            None
        }
    }

    fn clamp_seg(&mut self) {
        if let Some(path) = self.map_disk_path() {
            let n = self.seg_count(&path).max(1);
            self.seg_sel = self.seg_sel.min(n - 1);
        } else {
            self.seg_sel = 0;
        }
    }

    /// ←/→ on the map: move across the segments of the current disk row.
    pub fn seg_prev(&mut self) {
        let Some(path) = self.map_disk_path() else { return };
        let n = self.seg_count(&path);
        if n > 0 {
            self.seg_sel = (self.seg_sel + n - 1) % n;
        }
    }

    pub fn seg_next(&mut self) {
        let Some(path) = self.map_disk_path() else { return };
        let n = self.seg_count(&path);
        if n > 0 {
            self.seg_sel = (self.seg_sel + 1) % n;
        }
    }

    pub fn disk_sel_next(&mut self) {
        match self.disk_stage {
            DiskStage::Disks => {
                let n = self.installable_disks().len();
                if n > 0 {
                    self.disk_cursor = (self.disk_cursor + 1) % n;
                }
            }
            DiskStage::Pools => {
                let n = self.map_disks().len();
                if n > 0 {
                    self.map_disk = (self.map_disk + 1) % n;
                    self.clamp_seg();
                }
            }
            DiskStage::Partitions => {
                let n = self.part_seg_count();
                if n > 0 {
                    self.vol_sel = (self.vol_sel + 1) % n;
                }
            }
            DiskStage::Subvols => self.subvol_sel_next(),
        }
    }

    pub fn disk_sel_prev(&mut self) {
        match self.disk_stage {
            DiskStage::Disks => {
                let n = self.installable_disks().len();
                if n > 0 {
                    self.disk_cursor = (self.disk_cursor + n - 1) % n;
                }
            }
            DiskStage::Pools => {
                let n = self.map_disks().len();
                if n > 0 {
                    self.map_disk = (self.map_disk + n - 1) % n;
                    self.clamp_seg();
                }
            }
            DiskStage::Partitions => {
                let n = self.part_seg_count();
                if n > 0 {
                    self.vol_sel = (self.vol_sel + n - 1) % n;
                }
            }
            DiskStage::Subvols => self.subvol_sel_prev(),
        }
    }

    /// Drop pools that neither own disk space nor hold partitions — leftovers
    /// from repainting. The first (default) pool always survives.
    fn prune_empty_pools(&mut self) {
        let names: Vec<String> = self
            .state
            .volume_groups
            .iter()
            .skip(1)
            .map(|g| g.name.clone())
            .collect();
        for name in names {
            let has_space = self.state.pool_capacity_gib(&name) > 0;
            let has_volumes = self
                .state
                .volumes
                .iter()
                .any(|v| self.state.volume_group_for_volume(&v.name) == name);
            if !has_space && !has_volumes {
                let _ = self.state.delete_volume_group_reassigning_to_default(&name);
            }
        }
        self.pool_sel = self.pool_sel.min(self.pool_count().saturating_sub(1));
    }

    /// `a` on the map: make a pool out of the free space under the cursor. The
    /// default pool is reused while it still owns nothing; after that each `a`
    /// creates the next pool.
    pub fn pool_from_free(&mut self) {
        if !self.on_free_segment() {
            self.status = "move onto free space (→) to add a pool there".to_string();
            return;
        }
        let Some(path) = self.map_disk_path() else { return };
        let free = self.state.disk_free_gib(&path);
        let first = self
            .state
            .volume_groups
            .first()
            .map(|g| g.name.clone())
            .unwrap_or_else(|| DEFAULT_STORAGE_POOL_NAME.to_string());
        let pool = if self.state.pool_capacity_gib(&first) == 0 {
            first
        } else {
            self.state.create_next_volume_group()
        };
        self.state.add_disk_slice(&path, &pool, free);
        self.state.normalize_storage_assignments();
        self.seg_sel = self.state.slices_for_disk(&path).len().saturating_sub(1);
        self.status = format!("pool {pool} — {free}G · type a number to resize");
    }

    /// `p` on the map: move the segment to the next pool. With a single pool it
    /// creates a second one right away. On a FREE segment it JOINS the free
    /// space to the first existing pool — the way to span one pool across
    /// disks (a is the verb that makes a NEW pool instead).
    pub fn slice_cycle_pool(&mut self) {
        if self.on_free_segment() {
            let Some(path) = self.map_disk_path() else { return };
            let free = self.state.disk_free_gib(&path);
            let pool = self
                .state
                .volume_groups
                .first()
                .map(|g| g.name.clone())
                .unwrap_or_else(|| DEFAULT_STORAGE_POOL_NAME.to_string());
            self.state.add_disk_slice(&path, &pool, free);
            self.state.normalize_storage_assignments();
            self.seg_sel = self.state.slices_for_disk(&path).len().saturating_sub(1);
            self.status = format!("joined {pool} (+{free}G) · p again cycles pools");
            return;
        }
        let Some((path, idx)) = self.selected_slice() else {
            return;
        };
        // A lone pool means "move" needs a destination: make one.
        if self.state.volume_groups.len() < 2 {
            self.state.create_next_volume_group();
        }
        let pools: Vec<String> = self
            .state
            .volume_groups
            .iter()
            .map(|g| g.name.clone())
            .collect();
        if let Some(slices) = self.state.disk_slices.get_mut(&path) {
            if let Some(slice) = slices.get_mut(idx) {
                let cur = pools.iter().position(|p| *p == slice.pool).unwrap_or(0);
                slice.pool = pools[(cur + 1) % pools.len()].clone();
                self.status = format!("segment → {}", slice.pool);
            }
        }
        self.state.normalize_storage_assignments();
        self.prune_empty_pools();
    }

    /// `s` on the map: split the segment and put the new half in a NEW pool —
    /// "one disk, two pools" in a single keypress. Resize by typing a number;
    /// repaint with p.
    pub fn slice_split(&mut self) {
        let Some((path, idx)) = self.selected_slice() else {
            return;
        };
        {
            let Some(slices) = self.state.disk_slices.get_mut(&path) else {
                return;
            };
            let Some(slice) = slices.get(idx) else { return };
            if slice.size_gib <= 1 {
                self.status = "segment too small to split".to_string();
                return;
            }
        }
        let new_pool = self.state.create_next_volume_group();
        let slices = self
            .state
            .disk_slices
            .get_mut(&path)
            .expect("slice list exists");
        let half = (slices[idx].size_gib / 2).max(1);
        slices[idx].size_gib -= half;
        slices.insert(
            idx + 1,
            DiskSlice {
                pool: new_pool.clone(),
                size_gib: half,
            },
        );
        self.seg_sel = idx + 1;
        self.status = format!("new pool {new_pool} — type a size · p moves it · r renames");
    }

    /// `d` on the map: free the segment. A pool that loses its last segment is
    /// removed (its partitions move to the default pool).
    pub fn slice_delete(&mut self) {
        let Some((path, idx)) = self.selected_slice() else {
            return;
        };
        let pool = self.state.slices_for_disk(&path)[idx].pool.clone();
        if let Some(slices) = self.state.disk_slices.get_mut(&path) {
            slices.remove(idx);
        }
        // Drop the pool entirely once nothing feeds it (unless it's the last).
        if self.state.pool_capacity_gib(&pool) == 0 && self.state.volume_groups.len() > 1 {
            let _ = self.state.delete_volume_group_reassigning_to_default(&pool);
            self.status = format!("pool {pool} removed (no space left)");
        }
        self.state.normalize_storage_assignments();
        self.clamp_seg();
    }

    /// −/+ on the map: resize the segment, bounded by the disk's free space.
    pub fn slice_resize(&mut self, delta: i64) {
        let Some((path, idx)) = self.selected_slice() else {
            return;
        };
        let free = self.state.disk_free_gib(&path) as i64;
        let Some(slices) = self.state.disk_slices.get_mut(&path) else {
            return;
        };
        let Some(slice) = slices.get_mut(idx) else { return };
        let cur = slice.size_gib as i64;
        // Growing is capped by free space; shrinking floors at 1.
        let delta = delta.min(free);
        slice.size_gib = (cur + delta).max(1) as u64;
    }

    /// Free (unallocated) GiB in a pool: capacity minus fixed partitions. The
    /// fill partition, if any, is what visually absorbs this at render time —
    /// nothing is ever silently resized.
    pub fn pool_free_gib(&self, pool: &str) -> u64 {
        let cap = self.state.pool_capacity_gib(pool);
        let fixed: u64 = self
            .state
            .volumes
            .iter()
            .filter(|v| self.state.volume_group_for_volume(&v.name) == pool && !v.fill)
            .map(|v| v.size_gib)
            .sum();
        cap.saturating_sub(fixed)
    }

    /// Materialize a whole-disk slice for a disk that has none yet.
    fn ensure_slice(&mut self, path: &str) {
        if self.state.slices_for_disk(path).is_empty() {
            let esp = self.state.esp_reserved_gib(path);
            let whole = self.state.disk_size_gib(path).saturating_sub(esp);
            self.state.disk_slices.insert(
                path.to_string(),
                vec![DiskSlice {
                    pool: self
                        .selected_pool_name()
                        .unwrap_or_else(|| DEFAULT_STORAGE_POOL_NAME.to_string()),
                    size_gib: whole,
                }],
            );
        }
    }

    // ── type an exact size in GiB ────────────────────────────────

    pub fn size_editing(&self) -> bool {
        self.size_edit.is_some()
    }

    /// Start typing a size for the selected item on the current page. An
    /// optional first digit seeds the buffer (so pressing a number just works).
    pub fn size_begin(&mut self, first: Option<char>) {
        let ok = match self.disk_stage {
            // Disks page is a checkbox list; nothing to size there.
            DiskStage::Disks => false,
            // The map: type a size for the segment under the cursor.
            DiskStage::Pools => self.selected_slice().is_some(),
            DiskStage::Partitions => self.selected_volume_index().is_some(),
            // Subvolumes have no sizes (btrfs subvolumes share the partition).
            DiskStage::Subvols => false,
        };
        if !ok {
            return;
        }
        let mut buf = String::new();
        if let Some(c) = first {
            if c.is_ascii_digit() {
                buf.push(c);
            }
        }
        self.size_edit = Some(buf);
    }

    pub fn size_insert(&mut self, ch: char) {
        if let Some(buf) = self.size_edit.as_mut() {
            if ch.is_ascii_digit() && buf.len() < 7 {
                buf.push(ch);
            }
        }
    }

    pub fn size_backspace(&mut self) {
        if let Some(buf) = self.size_edit.as_mut() {
            buf.pop();
        }
    }

    pub fn size_cancel(&mut self) {
        self.size_edit = None;
    }

    pub fn size_apply(&mut self) {
        let Some(buf) = self.size_edit.take() else {
            return;
        };
        let Ok(val) = buf.trim().parse::<u64>() else {
            return;
        };
        let val = val.max(1);
        match self.disk_stage {
            DiskStage::Partitions => {
                if let Some(i) = self.selected_volume_index() {
                    // Typing a size makes the partition fixed (a fill partition
                    // has no number of its own).
                    let pool = self
                        .state
                        .volume_group_for_volume(&self.state.volumes[i].name)
                        .to_string();
                    self.state.volumes[i].fill = false;
                    // Clamp to what the pool can still provide.
                    let others: u64 = self
                        .volumes_in_selected_pool()
                        .into_iter()
                        .filter(|&j| j != i)
                        .filter(|&j| !self.state.volumes[j].fill)
                        .map(|j| self.state.volumes[j].size_gib)
                        .sum();
                    let max = self.state.pool_capacity_gib(&pool).saturating_sub(others);
                    self.state.volumes[i].size_gib = val.clamp(1, max.max(1));
                }
            }
            DiskStage::Pools => self.slice_set_size(val),
            DiskStage::Disks | DiskStage::Subvols => {}
        }
    }

    /// Set the selected slice to an absolute size (clamped to the disk). This is
    /// how pool capacity is adjusted — a pool's size IS the slices feeding it.
    fn slice_set_size(&mut self, val: u64) {
        let Some((path, idx)) = self.selected_slice() else {
            return;
        };
        self.ensure_slice(&path);
        let free = self.state.disk_free_gib(&path);
        if let Some(slices) = self.state.disk_slices.get_mut(&path) {
            if let Some(slice) = slices.get_mut(idx) {
                let max = slice.size_gib + free;
                slice.size_gib = val.clamp(1, max.max(1));
            }
        }
    }

    // ── pools ────────────────────────────────────────────────────

    /// `r` on the map: rename the pool of the segment under the cursor.
    pub fn pool_begin_rename(&mut self) {
        let Some((path, idx)) = self.selected_slice() else {
            return;
        };
        let pool = self.state.slices_for_disk(&path)[idx].pool.clone();
        if let Some(i) = self.state.volume_groups.iter().position(|g| g.name == pool) {
            self.pool_sel = i;
        }
        self.disk_edit_field = PartField::Name;
        self.disk_rename = Some(pool);
    }

    /// Drill into the selected pool to edit its partitions. The pool starts
    /// empty — the user adds every partition themselves (a).
    pub fn pool_enter(&mut self) {
        self.disk_stage = DiskStage::Partitions;
        self.subvol_target = None;
        self.status.clear();
        self.vol_sel = 0;
        self.part_zone = 2;
        self.pool_edit = None;
    }

    fn selected_volume_index(&self) -> Option<usize> {
        self.volumes_in_selected_pool().get(self.vol_sel).copied()
    }

    /// ↑/↓ on the partitions page move between the pool's field rows on top
    /// (name, size) and the partition band below. Leaving a field saves the
    /// buffer; landing on one drops the cursor straight into it.
    pub fn part_zone_up(&mut self) {
        self.pool_edit_commit();
        if self.part_zone > 0 {
            self.part_zone -= 1;
        }
        self.pool_focus_row();
    }

    pub fn part_zone_down(&mut self) {
        self.pool_edit_commit();
        if self.part_zone < 2 {
            self.part_zone += 1;
        }
        self.pool_focus_row();
    }

    /// The pool field rows keep a live edit buffer while the cursor is on
    /// them; the band below (zone 2) has none.
    pub fn pool_focus_row(&mut self) {
        self.pool_edit = None;
        if self.part_zone < 2 {
            self.pool_edit_row();
        }
    }

    /// Save the live buffer when the cursor leaves a pool field; invalid
    /// values revert with a status message instead of blocking.
    pub fn pool_edit_commit(&mut self) {
        self.pool_edit_apply();
        self.pool_edit = None;
    }

    /// `e` on a pool field row: edit it in place (Enter commits, Esc cancels).
    pub fn pool_edit_row(&mut self) {
        let Some(pool) = self.selected_pool_name() else { return };
        match self.part_zone {
            0 => self.pool_edit = Some((0, pool)),
            1 => {
                self.pool_edit =
                    Some((1, self.state.pool_capacity_gib(&pool).to_string()));
            }
            _ => {}
        }
    }

    pub fn pool_edit_insert(&mut self, ch: char) {
        if let Some((row, buf)) = self.pool_edit.as_mut() {
            let ok = match row {
                1 => ch.is_ascii_digit(),
                _ => !ch.is_control() && !ch.is_whitespace(),
            };
            if ok && buf.len() < 40 {
                buf.push(ch);
            }
        }
    }

    pub fn pool_edit_backspace(&mut self) {
        if let Some((_, buf)) = self.pool_edit.as_mut() {
            buf.pop();
        }
    }

    pub fn pool_edit_apply(&mut self) {
        let Some((row, value)) = self.pool_edit.clone() else { return };
        let Some(pool) = self.selected_pool_name() else { return };
        let value = value.trim().to_string();
        let result: std::result::Result<(), String> = (|| {
            match row {
                0 => {
                    if value.is_empty() {
                        return Err("pool name cannot be empty".into());
                    }
                    if value != pool {
                        self.state.rename_volume_group(&pool, &value)?;
                    }
                }
                1 => {
                    let val: u64 = value
                        .parse()
                        .map_err(|_| "size must be a number".to_string())?;
                    // No-op commits happen every time the cursor passes this
                    // row — only touch the slices on an actual change.
                    if val == self.state.pool_capacity_gib(&pool) {
                        return Ok(());
                    }
                    // Resize the pool via its largest backing slice, bounded by
                    // that disk's free space.
                    let mut best: Option<(String, usize, u64)> = None;
                    for (path, slices) in &self.state.disk_slices {
                        for (i, sl) in slices.iter().enumerate() {
                            if sl.pool == pool
                                && best.as_ref().map_or(true, |(_, _, sz)| sl.size_gib > *sz)
                            {
                                best = Some((path.clone(), i, sl.size_gib));
                            }
                        }
                    }
                    let Some((path, idx, cur)) = best else {
                        return Err("pool has no disk space yet — assign some on the map".into());
                    };
                    let others = self.state.pool_capacity_gib(&pool) - cur;
                    let want_slice = val.saturating_sub(others).max(1);
                    let max = cur + self.state.disk_free_gib(&path);
                    if let Some(slices) = self.state.disk_slices.get_mut(&path) {
                        slices[idx].size_gib = want_slice.min(max);
                    }
                    self.state.normalize_storage_assignments();
                }
                _ => {}
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.pool_edit = None;
                self.status.clear();
            }
            Err(err) => self.status = err,
        }
    }

    /// The partitions band shows a trailing FREE segment when the pool has
    /// unallocated space and no fill partition absorbing it.
    pub fn part_free_visible(&self) -> bool {
        let Some(pool) = self.selected_pool_name() else {
            return false;
        };
        let members = self.volumes_in_selected_pool();
        let has_fill = members.iter().any(|&i| self.state.volumes[i].fill);
        !has_fill && self.pool_free_gib(&pool) > 0
    }

    /// Number of selectable segments on the partitions band (partitions + free).
    pub fn part_seg_count(&self) -> usize {
        self.volumes_in_selected_pool().len() + usize::from(self.part_free_visible())
    }

    /// True when the partitions cursor sits on the FREE segment.
    pub fn on_free_partition(&self) -> bool {
        self.part_free_visible() && self.vol_sel >= self.volumes_in_selected_pool().len()
    }

    /// `s` on the partitions band: split the selected partition in half — the
    /// new half becomes its own partition, mirroring how the pool map splits.
    pub fn part_split(&mut self) {
        if self.disk_stage != DiskStage::Partitions {
            return;
        }
        let Some(i) = self.selected_volume_index() else {
            self.status = "free space — a adds a partition".to_string();
            return;
        };
        if self.state.volumes[i].fill {
            self.status = "this partition takes the rest — type a number to fix it first".to_string();
            return;
        }
        if self.state.volumes[i].size_gib <= 1 {
            self.status = "partition too small to split".to_string();
            return;
        }
        let pool = self
            .state
            .volume_group_for_volume(&self.state.volumes[i].name)
            .to_string();
        let half = (self.state.volumes[i].size_gib / 2).max(1);
        self.state.volumes[i].size_gib -= half;
        let fs = self.state.volumes[i].fs;
        let name = unique_name(
            "vol",
            &self.state.volumes.iter().map(|v| v.name.clone()).collect::<Vec<_>>(),
        );
        self.state.volumes.push(Volume {
            name: name.clone(),
            mountpoint: Mountpoint::Path(format!("/{name}")),
            size_gib: half,
            fs,
            subvolumes: Vec::new(),
            fill: false,
        });
        self.state.set_volume_group_for_volume(&name, &pool);
        self.vol_sel = self
            .volumes_in_selected_pool()
            .iter()
            .position(|&j| self.state.volumes[j].name == name)
            .unwrap_or(0);
        self.status = format!("new partition {name} — n renames · m mounts · f fs");
    }

    /// Resize the selected partition by `delta` GiB. Nothing else moves — the
    /// pool's free space (or its fill partition) absorbs the difference.
    pub fn disk_resize(&mut self, delta: i64) {
        if self.disk_stage != DiskStage::Partitions {
            return;
        }
        let Some(i) = self.selected_volume_index() else {
            return;
        };
        if self.state.volumes[i].fill {
            self.status = "this partition takes the rest — type a number to fix it".to_string();
            return;
        }
        let pool = self
            .state
            .volume_group_for_volume(&self.state.volumes[i].name)
            .to_string();
        let cur = self.state.volumes[i].size_gib as i64;
        let grow_room = self.pool_free_gib(&pool) as i64;
        let delta = delta.min(grow_room);
        self.state.volumes[i].size_gib = (cur + delta).max(1) as u64;
    }

    /// `*` in the partitions page: make the selected partition the fill (or
    /// unmark it). At most one partition per pool fills; swap cannot fill.
    pub fn fill_toggle(&mut self) {
        let Some(i) = self.selected_volume_index() else {
            return;
        };
        if self.state.volumes[i].fill {
            self.state.volumes[i].fill = false;
            return;
        }
        if self.state.volumes[i].fs == VolumeFs::Swap {
            self.status = "swap keeps a fixed size".to_string();
            return;
        }
        for j in self.volumes_in_selected_pool() {
            self.state.volumes[j].fill = false;
        }
        self.state.volumes[i].fill = true;
    }

    /// Add a partition to the selected pool. Like creating a pool on the map,
    /// the new partition claims ALL the remaining free space — type a number
    /// afterwards to shrink it.
    fn disk_add_to_pool(&mut self) {
        let pool = self
            .selected_pool_name()
            .unwrap_or_else(|| DEFAULT_STORAGE_POOL_NAME.to_string());
        let has_fill = self
            .volumes_in_selected_pool()
            .iter()
            .any(|&i| self.state.volumes[i].fill);
        let mut avail = self.pool_free_gib(&pool);
        if has_fill {
            // Leave the fill partition its 1G minimum.
            avail = avail.saturating_sub(1);
        }
        if avail == 0 {
            self.status = "no free space — shrink a partition first (type a size)".to_string();
            return;
        }
        // Every system needs a root: the very first partition defaults to it.
        let (name, mount) = if self.storage_has_root() {
            let name = unique_name(
                "vol",
                &self.state.volumes.iter().map(|v| v.name.clone()).collect::<Vec<_>>(),
            );
            let mount = format!("/{name}");
            (name, mount)
        } else {
            ("root".to_string(), "/".to_string())
        };
        self.state.volumes.push(Volume {
            name: name.clone(),
            mountpoint: Mountpoint::Path(mount),
            size_gib: avail,
            fs: VolumeFs::Btrfs,
            subvolumes: Vec::new(),
            fill: false,
        });
        self.state.set_volume_group_for_volume(&name, &pool);
        self.vol_sel = self.volumes_in_selected_pool().len().saturating_sub(1);
        self.status = format!("partition {name} — {avail}G · type a number to resize · e edits");
    }

    /// Add a partition (PARTITIONS view only).
    pub fn disk_add(&mut self) {
        if self.disk_stage != DiskStage::Partitions {
            return;
        }
        self.disk_add_to_pool();
    }

    /// Delete the selected partition (PARTITIONS view only). Deleting the last
    /// one is fine — the pool simply goes back to empty.
    pub fn disk_delete(&mut self) {
        if self.disk_stage != DiskStage::Partitions {
            return;
        }
        if let Some(i) = self.selected_volume_index() {
            let name = self.state.volumes[i].name.clone();
            self.state.volumes.remove(i);
            self.state.volume_volume_groups.remove(&name);
            self.vol_sel = self.vol_sel.saturating_sub(1);
        }
    }

    // ── edit the selected partition's name / mountpoint ──────────

    pub fn disk_begin_edit(&mut self, field: PartField) {
        if self.disk_stage != DiskStage::Partitions {
            return;
        }
        let Some(i) = self.selected_volume_index() else {
            return;
        };
        self.disk_edit_field = field;
        self.disk_rename = Some(match field {
            PartField::Name => self.state.volumes[i].name.clone(),
            PartField::Mount => self.state.volumes[i].mountpoint.label().to_string(),
        });
    }

    pub fn disk_rename_insert(&mut self, ch: char) {
        if let Some(buf) = self.disk_rename.as_mut() {
            // Names forbid whitespace; mount paths allow the leading slash etc.
            let ok = match self.disk_edit_field {
                PartField::Name => !ch.is_control() && !ch.is_whitespace(),
                PartField::Mount => !ch.is_control() && !ch.is_whitespace(),
            };
            if ok {
                buf.push(ch);
            }
        }
    }

    pub fn disk_rename_backspace(&mut self) {
        if let Some(buf) = self.disk_rename.as_mut() {
            buf.pop();
        }
    }

    pub fn disk_cancel_rename(&mut self) {
        self.disk_rename = None;
    }

    pub fn disk_apply_rename(&mut self) {
        let Some(new) = self.disk_rename.take() else {
            return;
        };
        let new = new.trim().to_string();
        if new.is_empty() {
            return;
        }
        // Renaming a pool (POOLS page) vs a partition (PARTITIONS page).
        if self.disk_stage == DiskStage::Pools {
            if let Some(old) = self.selected_pool_name() {
                if old != new {
                    if let Err(err) = self.state.rename_volume_group(&old, &new) {
                        self.status = err;
                    }
                }
            }
            return;
        }
        let Some(i) = self.selected_volume_index() else {
            return;
        };
        match self.disk_edit_field {
            PartField::Name => {
                let old = self.state.volumes[i].name.clone();
                if old != new {
                    self.rename_volume(&old, &new);
                }
            }
            PartField::Mount => {
                if new == "swap" {
                    self.state.volumes[i].mountpoint = Mountpoint::Swap;
                    self.state.volumes[i].fs = VolumeFs::Swap;
                    self.state.volumes[i].subvolumes.clear();
                } else if let Err(err) = validate_mountpoint(&new) {
                    self.status = err;
                } else {
                    self.state.volumes[i].mountpoint = Mountpoint::Path(new);
                    if self.state.volumes[i].fs == VolumeFs::Swap {
                        self.state.volumes[i].fs = VolumeFs::Btrfs;
                    }
                }
            }
        }
    }

    // ── per-volume filesystem & subvolumes ──────────────────────

    /// Cycle the selected volume's filesystem (btrfs → ext4 → xfs → swap → …).
    /// Swap and non-swap filesystems keep the mountpoint kind consistent, and
    /// leaving btrfs drops any subvolumes since only btrfs supports them.
    pub fn disk_cycle_fs(&mut self) {
        if self.disk_stage != DiskStage::Partitions {
            return;
        }
        let Some(i) = self.selected_volume_index() else {
            return;
        };
        let next = self.state.volumes[i].fs.next();
        let volume = &mut self.state.volumes[i];
        volume.fs = next;
        match next {
            VolumeFs::Swap => {
                volume.mountpoint = Mountpoint::Swap;
                volume.subvolumes.clear();
            }
            VolumeFs::Btrfs => {
                if matches!(volume.mountpoint, Mountpoint::Swap) {
                    volume.mountpoint = Mountpoint::Path(format!("/{}", volume.name));
                }
            }
            VolumeFs::Ext4 | VolumeFs::Xfs => {
                if matches!(volume.mountpoint, Mountpoint::Swap) {
                    volume.mountpoint = Mountpoint::Path(format!("/{}", volume.name));
                }
                // Only btrfs carries subvolumes.
                volume.subvolumes.clear();
            }
        }
    }

    /// Enter the subvolume tier for the selected volume (btrfs only).
    #[allow(dead_code)]
    pub fn subvol_open(&mut self) {
        if self.disk_stage != DiskStage::Partitions {
            return;
        }
        self.subvols_enter();
    }

    #[allow(dead_code)]
    pub fn subvol_close(&mut self) {
        self.subvol_target = None;
        self.subvol_edit = None;
        if self.disk_stage == DiskStage::Subvols {
            self.disk_stage = DiskStage::Partitions;
        }
    }

    fn subvol_count(&self) -> usize {
        self.subvol_target
            .map(|i| self.state.volumes[i].subvolumes.len())
            .unwrap_or(0)
    }

    pub fn subvol_sel_next(&mut self) {
        let n = self.subvol_count();
        if n > 0 {
            self.subvol_sel = (self.subvol_sel + 1) % n;
        }
    }

    pub fn subvol_sel_prev(&mut self) {
        let n = self.subvol_count();
        if n > 0 {
            self.subvol_sel = (self.subvol_sel + n - 1) % n;
        }
    }

    pub fn subvol_add(&mut self) {
        let Some(i) = self.subvol_target else { return };
        let existing: Vec<String> = self.state.volumes[i]
            .subvolumes
            .iter()
            .map(|s| s.name.clone())
            .collect();
        let name = unique_name("sub", &existing);
        let mount = format!("{}/{}", self.state.volumes[i].mountpoint.label(), name)
            .replace("//", "/");
        self.state.volumes[i].subvolumes.push(Subvolume {
            name: name.clone(),
            mountpoint: mount,
        });
        self.subvol_sel = self.state.volumes[i].subvolumes.len() - 1;
    }

    pub fn subvol_delete(&mut self) {
        let Some(i) = self.subvol_target else { return };
        let subs = &mut self.state.volumes[i].subvolumes;
        if self.subvol_sel < subs.len() {
            subs.remove(self.subvol_sel);
            self.subvol_sel = self.subvol_sel.saturating_sub(1);
        }
    }

    pub fn subvol_begin_edit(&mut self, field: SubvolField) {
        let Some(i) = self.subvol_target else { return };
        let Some(sub) = self.state.volumes[i].subvolumes.get(self.subvol_sel) else {
            return;
        };
        let value = match field {
            SubvolField::Name => sub.name.clone(),
            SubvolField::Mount => sub.mountpoint.clone(),
        };
        self.subvol_edit = Some((field, value));
    }

    pub fn subvol_edit_insert(&mut self, ch: char) {
        if let Some((_, value)) = self.subvol_edit.as_mut() {
            if !ch.is_control() {
                value.push(ch);
            }
        }
    }

    pub fn subvol_edit_backspace(&mut self) {
        if let Some((_, value)) = self.subvol_edit.as_mut() {
            value.pop();
        }
    }

    pub fn subvol_cancel_edit(&mut self) {
        self.subvol_edit = None;
    }

    pub fn subvol_apply_edit(&mut self) -> std::result::Result<(), String> {
        let Some(i) = self.subvol_target else {
            return Ok(());
        };
        let Some((field, value)) = self.subvol_edit.take() else {
            return Ok(());
        };
        let value = value.trim().to_string();
        if value.is_empty() {
            return Err("value cannot be empty".to_string());
        }
        let Some(sub) = self.state.volumes[i].subvolumes.get_mut(self.subvol_sel) else {
            return Ok(());
        };
        match field {
            SubvolField::Name => {
                if !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                    return Err("name: letters, digits, _ and - only".to_string());
                }
                sub.name = value;
            }
            SubvolField::Mount => {
                validate_mountpoint(&value)?;
                sub.mountpoint = value;
            }
        }
        Ok(())
    }

    // ── the universal `e` edit popup ─────────────────────────────

    #[allow(dead_code)]
    pub fn edit_open(&mut self) {
        // Subvolume overlay open → edit the selected subvolume.
        if let Some(vol) = self.subvol_target {
            if let Some(sub) = self.state.volumes[vol].subvolumes.get(self.subvol_sel) {
                self.edit_popup = Some(EditPopup {
                    title: format!("subvolume @{}", sub.name),
                    target: EditTarget::Subvol {
                        vol,
                        idx: self.subvol_sel,
                    },
                    fields: vec![
                        EditField::text("name", &sub.name),
                        EditField::text("mount", &sub.mountpoint),
                    ],
                    cursor: 0,
                });
            }
            return;
        }
        match self.disk_stage {
            // In the subvolume tier the branch above (subvol_target) handles e.
            DiskStage::Subvols => {}
            DiskStage::Disks => {
                let Some(path) = self.cursor_disk() else { return };
                let in_use = self.disk_selected.contains(&path);
                self.edit_popup = Some(EditPopup {
                    title: format!(
                        "disk {} · {}G",
                        path.rsplit('/').next().unwrap_or(&path),
                        self.state.disk_size_gib(&path)
                    ),
                    target: EditTarget::Disk { path },
                    fields: vec![EditField::toggle("use in install", in_use)],
                    cursor: 0,
                });
            }
            DiskStage::Pools => {
                let Some((path, idx)) = self.selected_slice() else {
                    self.status = "free space — p joins it to the pool · a makes a new pool".into();
                    return;
                };
                let slice = &self.state.slices_for_disk(&path)[idx];
                self.edit_popup = Some(EditPopup {
                    title: format!(
                        "segment on {} · pool {}",
                        path.rsplit('/').next().unwrap_or(&path),
                        slice.pool
                    ),
                    target: EditTarget::Slice { path: path.clone(), idx },
                    fields: vec![
                        // Typing an EXISTING pool's name moves the segment
                        // there; a new name renames this pool.
                        EditField::text("pool", &slice.pool),
                        EditField::number("size (GiB)", slice.size_gib),
                    ],
                    cursor: 0,
                });
            }
            DiskStage::Partitions => {
                let Some(i) = self.selected_volume_index() else {
                    self.status = "free space — a adds a partition here".into();
                    return;
                };
                let vol = &self.state.volumes[i];
                self.edit_popup = Some(EditPopup {
                    title: format!("partition {}", vol.name),
                    target: EditTarget::Volume { index: i },
                    fields: vec![
                        EditField::text("name", &vol.name),
                        EditField::text("mount", vol.mountpoint.label()),
                        EditField::choice(
                            "filesystem",
                            vec!["btrfs".into(), "ext4".into(), "xfs".into(), "swap".into()],
                            vol.fs.title(),
                        ),
                        EditField::number("size (GiB)", vol.size_gib),
                        EditField::toggle("take the rest", vol.fill),
                    ],
                    cursor: 0,
                });
            }
        }
    }

    pub fn edit_cancel(&mut self) {
        self.edit_popup = None;
    }

    pub fn edit_field_next(&mut self) {
        if let Some(p) = self.edit_popup.as_mut() {
            p.cursor = (p.cursor + 1) % p.fields.len();
        }
    }

    pub fn edit_field_prev(&mut self) {
        if let Some(p) = self.edit_popup.as_mut() {
            p.cursor = (p.cursor + p.fields.len() - 1) % p.fields.len();
        }
    }

    pub fn edit_input(&mut self, ch: char) {
        if let Some(p) = self.edit_popup.as_mut() {
            let field = &mut p.fields[p.cursor];
            match field.kind {
                EditKind::Text => {
                    if !ch.is_control() && !ch.is_whitespace() && field.buf.len() < 40 {
                        field.buf.push(ch);
                    }
                }
                EditKind::Number => {
                    if ch.is_ascii_digit() && field.buf.len() < 7 {
                        field.buf.push(ch);
                    }
                }
                // Space also cycles choices/toggles.
                _ if ch == ' ' => self.edit_cycle(1),
                _ => {}
            }
        }
    }

    pub fn edit_backspace(&mut self) {
        if let Some(p) = self.edit_popup.as_mut() {
            p.fields[p.cursor].buf.pop();
        }
    }

    /// ←/→ (or space) on a Choice/Toggle field.
    pub fn edit_cycle(&mut self, dir: i64) {
        if let Some(p) = self.edit_popup.as_mut() {
            match &mut p.fields[p.cursor].kind {
                EditKind::Choice { options, idx } => {
                    let n = options.len() as i64;
                    *idx = ((*idx as i64 + dir).rem_euclid(n)) as usize;
                }
                EditKind::Toggle { on } => *on = !*on,
                _ => {}
            }
        }
    }

    /// Enter: write every field back to the target. Validation errors keep the
    /// popup open (with the typed values intact) and surface in the status row.
    pub fn edit_apply(&mut self) {
        let Some(popup) = self.edit_popup.clone() else {
            return;
        };
        let result = self.edit_apply_inner(&popup);
        match result {
            Ok(()) => {
                self.edit_popup = None;
                self.status.clear();
            }
            Err(err) => self.status = err,
        }
    }

    fn edit_apply_inner(&mut self, popup: &EditPopup) -> std::result::Result<(), String> {
        match &popup.target {
            EditTarget::Disk { path } => {
                let want = matches!(popup.fields[0].kind, EditKind::Toggle { on: true });
                let have = self.disk_selected.contains(path);
                if want != have {
                    if have && self.disk_selected.len() == 1 {
                        return Err("keep at least one disk in the install".into());
                    }
                    self.disk_toggle(path);
                    self.apply_disk_selection();
                }
                Ok(())
            }
            EditTarget::Slice { path, idx } => {
                let pool_name = popup.fields[0].buf.trim().to_string();
                if pool_name.is_empty() {
                    return Err("pool name cannot be empty".into());
                }
                let size: u64 = popup.fields[1]
                    .buf
                    .trim()
                    .parse()
                    .map_err(|_| "size must be a number".to_string())?;
                let current = self
                    .state
                    .slices_for_disk(path)
                    .get(*idx)
                    .map(|s| s.pool.clone())
                    .ok_or_else(|| "segment no longer exists".to_string())?;
                if pool_name != current {
                    let exists = self
                        .state
                        .volume_groups
                        .iter()
                        .any(|g| g.name == pool_name);
                    if exists {
                        // Move the segment into the named pool.
                        if let Some(slices) = self.state.disk_slices.get_mut(path) {
                            slices[*idx].pool = pool_name.clone();
                        }
                    } else {
                        // Rename this pool.
                        self.state.rename_volume_group(&current, &pool_name)?;
                    }
                }
                // Absolute size, clamped by the disk's free space.
                let free = self.state.disk_free_gib(path);
                if let Some(slices) = self.state.disk_slices.get_mut(path) {
                    let max = slices[*idx].size_gib + free;
                    slices[*idx].size_gib = size.clamp(1, max.max(1));
                }
                self.state.normalize_storage_assignments();
                self.prune_empty_pools();
                Ok(())
            }
            EditTarget::Volume { index } => {
                let i = *index;
                if i >= self.state.volumes.len() {
                    return Err("partition no longer exists".into());
                }
                let name = popup.fields[0].buf.trim().to_string();
                let mount = popup.fields[1].buf.trim().to_string();
                let fs = match &popup.fields[2].kind {
                    EditKind::Choice { options, idx } => options[*idx].clone(),
                    _ => unreachable!(),
                };
                let size: u64 = popup.fields[3]
                    .buf
                    .trim()
                    .parse()
                    .map_err(|_| "size must be a number".to_string())?;
                let fill = matches!(popup.fields[4].kind, EditKind::Toggle { on: true });

                if name.is_empty() {
                    return Err("name cannot be empty".into());
                }
                let old_name = self.state.volumes[i].name.clone();
                if name != old_name
                    && self.state.volumes.iter().any(|v| v.name == name)
                {
                    return Err(format!("partition {name} already exists"));
                }
                let fs = match fs.as_str() {
                    "btrfs" => VolumeFs::Btrfs,
                    "ext4" => VolumeFs::Ext4,
                    "xfs" => VolumeFs::Xfs,
                    _ => VolumeFs::Swap,
                };
                // Mount: swap fs forces the swap mountpoint; otherwise validate.
                if fs == VolumeFs::Swap || mount == "swap" {
                    self.state.volumes[i].fs = VolumeFs::Swap;
                    self.state.volumes[i].mountpoint = Mountpoint::Swap;
                    self.state.volumes[i].subvolumes.clear();
                } else {
                    validate_mountpoint(&mount)?;
                    self.state.volumes[i].fs = fs;
                    self.state.volumes[i].mountpoint = Mountpoint::Path(mount);
                    if fs != VolumeFs::Btrfs {
                        self.state.volumes[i].subvolumes.clear();
                    }
                }
                if name != old_name {
                    self.rename_volume(&old_name, &name);
                }
                self.state.volumes[i].size_gib = size.max(1);
                if fill && self.state.volumes[i].fs == VolumeFs::Swap {
                    return Err("swap keeps a fixed size".into());
                }
                if fill {
                    for j in self.volumes_in_selected_pool() {
                        self.state.volumes[j].fill = false;
                    }
                }
                self.state.volumes[i].fill = fill;
                Ok(())
            }
            EditTarget::Subvol { vol, idx } => {
                let name = popup.fields[0].buf.trim().to_string();
                let mount = popup.fields[1].buf.trim().to_string();
                if name.is_empty() || mount.is_empty() {
                    return Err("name and mount cannot be empty".into());
                }
                if !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                {
                    return Err("name: letters, digits, _ and - only".into());
                }
                validate_mountpoint(&mount)?;
                let sub = self.state.volumes[*vol]
                    .subvolumes
                    .get_mut(*idx)
                    .ok_or_else(|| "subvolume no longer exists".to_string())?;
                sub.name = name;
                sub.mountpoint = mount;
                Ok(())
            }
        }
    }

    // ── navigation & load ───────────────────────────────────────

    fn load(&mut self) {
        self.cursor = 0;
        self.item = 0;
        self.field = 0;
        self.buffer.clear();
        self.disk_error = None;
        match self.current() {
            Step::Scope => self.cursor = usize::from(self.state.scope == InstallScope::Remote),
            Step::Role => self.cursor = usize::from(self.state.role == InstallRole::Server),
            Step::Ssh => self.cursor = usize::from(self.state.allow_ssh),
            Step::Locale => {
                self.cursor = TIMEZONES
                    .iter()
                    .position(|(tz, _, _, _)| *tz == self.state.timezone)
                    .unwrap_or(0)
            }
            Step::Filesystem => {
                self.cursor = usize::from(self.state.filesystem == Filesystem::Ext4)
            }
            Step::Encrypt => self.cursor = usize::from(self.state.encrypt),
            Step::Overwrite => self.cursor = usize::from(self.state.overwrite_existing_storage),
            Step::NetworkCleanup => self.cursor = usize::from(!self.state.network_route_cleanup),
            Step::BinEnsure => self.cursor = usize::from(!self.state.skip_bin_ensure),
            Step::StorageMode => {
                self.cursor = if self.manual_storage {
                    3
                } else {
                    match self.state.storage_mode {
                        StorageMode::SingleDisk => 0,
                        StorageMode::JoinedLvm => 1,
                        StorageMode::SeparatePools => 2,
                        StorageMode::Manual => 3,
                    }
                }
            }
            Step::Remote => self.buffer = self.state.remote.clone(),
            Step::Mountpoint => self.buffer = self.state.mountpoint.clone(),
            Step::Hostname => self.buffer = self.state.hostname.clone(),
            Step::User => self.buffer = self.state.install_user.clone(),
            Step::Dotfiles => self.buffer = self.state.dotfiles_repo.clone().unwrap_or_default(),
            Step::Lvm => self.cursor = usize::from(!self.state.use_lvm),
            Step::Disks => {
                // Multi-select disk picker: discover, seed the selection.
                self.discover_disks();
                if self.disk_selected.is_empty() {
                    for disk in self.state.disks.iter() {
                        self.disk_selected.insert(disk.path.clone());
                    }
                    // Default to the first installable disk if nothing chosen yet.
                    if self.disk_selected.is_empty() {
                        if let Some(first) = self.installable_disks().first() {
                            self.disk_selected.insert(first.path.clone());
                        }
                    }
                }
                self.cursor = 0;
            }
            Step::ExtraDisks => {
                self.extra_sel = 0;
                self.extra_edit = None;
            }
            Step::Users => {
                self.user_sel = self.user_sel.min(self.state.users.len().saturating_sub(1));
                self.users_popup = false;
                self.user_field_edit = None;
            }
            Step::Efi => {
                self.cursor = match self.state.esp_size_mib {
                    0..=512 => 0,
                    513..=1024 => 1,
                    _ => 2,
                }
            }
            Step::Storage => {
                self.discover_disks();
                // Seed the editor ONCE. Re-entering (after Esc/back) must keep the
                // user's slices and partition sizes, so only initialize if not
                // already done.
                if !self.storage_ready {
                    if self.disk_selected.is_empty() {
                        for disk in self.state.disks.iter() {
                            self.disk_selected.insert(disk.path.clone());
                        }
                        if self.disk_selected.is_empty() {
                            if let Some(first) = self.installable_disks().first() {
                                self.disk_selected.insert(first.path.clone());
                            }
                        }
                    }
                    self.apply_disk_selection();
                    self.storage_ready = true;
                }
                // Always re-enter at the top page, but never reset the data.
                self.disk_stage = DiskStage::Disks;
                self.disk_cursor = 0;
                self.pool_sel = 0;
                self.vol_sel = 0;
            }
            Step::Pools | Step::Volumes | Step::DocSubvols => self.sync_buffer(),
            _ => {}
        }
        self.sync_text_input();
    }

    /// Load the focused editor text field into the buffer.
    fn sync_buffer(&mut self) {
        self.buffer = self.editor_text_value().unwrap_or_default();
        self.sync_text_input();
    }

    fn sync_text_input(&mut self) {
        self.text_input = Input::new(self.buffer.clone());
    }

    fn edit_text(&mut self, request: InputRequest) {
        // Tests and callers may set the public buffer directly. Reconcile it
        // before asking tui-input to preserve cursor-aware editing.
        if self.text_input.to_string() != self.buffer {
            self.sync_text_input();
        }
        self.text_input.handle(request);
        self.buffer = self.text_input.to_string();
    }

    pub fn text_cursor(&self) -> usize {
        self.text_input.cursor()
    }

    pub fn text_cursor_prev(&mut self) {
        self.edit_text(InputRequest::GoToPrevChar);
    }

    pub fn text_cursor_next(&mut self) {
        self.edit_text(InputRequest::GoToNextChar);
    }

    fn discover_disks(&mut self) {
        if self.disable_discovery {
            return;
        }
        if self.facts.is_some() {
            return;
        }
        if self.state.scope == InstallScope::Remote {
            // The worker owns remote collection. Never stall the UI here.
            return;
        }
        let facts = crate::facts::collect();
        self.accept_facts(facts);
    }

    fn accept_facts(&mut self, facts: TargetFacts) {
        let first_facts = self.facts.is_none();
        // Merge discovered disks into the working set (new ones start Ignored).
        self.state.discovered_disks = crate::facts::disk_choices(&facts);
        for disk in crate::facts::disk_choices(&facts) {
            if !self.state.disks.iter().any(|d| d.path == disk.path) {
                self.state
                    .disk_roles
                    .entry(disk.path.clone())
                    .or_insert(DiskRole::Ignore);
                self.state.disks.push(disk);
            }
        }
        self.state.normalize_disk_roles();
        if first_facts {
            self.apply_intelligent_defaults(&facts);
        }
        self.facts = Some(facts);
    }

    fn apply_intelligent_defaults(&mut self, facts: &TargetFacts) {
        let mut candidates = facts.disks.iter().collect::<Vec<_>>();
        candidates.sort_by_key(|disk| std::cmp::Reverse(disk.size_bytes));
        let selected = candidates
            .iter()
            // Do not silently target the currently-mounted system disk. Prefer
            // a truly empty device, then an unmounted one; otherwise require a
            // deliberate user choice in the disk editor.
            .find(|disk| disk.partitions.is_empty())
            .or_else(|| {
                candidates.iter().find(|disk| {
                    disk.partitions
                        .iter()
                        .all(|partition| partition.mountpoints.is_empty())
                })
            })
            .copied();
        if let Some(disk) = selected {
            self.state.disks = crate::facts::disk_choices(facts)
                .into_iter()
                .filter(|choice| choice.path == disk.path)
                .collect();
            self.state.disk_roles.clear();
            self.state
                .disk_roles
                .insert(disk.path.clone(), DiskRole::System);
            self.state.normalize_disk_roles();
        }
        if facts.disks.len() <= 1 {
            self.state.storage_mode = StorageMode::SingleDisk;
        }
        if let Some(mem_mib) = facts.mem_mib {
            let swap_gib = (mem_mib / 1024).clamp(1, 64);
            if let Some(swap) = self
                .state
                .volumes
                .iter_mut()
                .find(|volume| matches!(volume.mountpoint, Mountpoint::Swap))
            {
                swap.size_gib = swap_gib;
            }
        }
        // No size fitting here: the default root partition is `fill`, so it
        // occupies whatever the pool provides at render time.
    }


    /// Drain the background remote probe. Called by the event loop before every
    /// frame, so the header and disk page update without a blocking transition.
    pub fn poll_link(&mut self) {
        let Some(rx) = &self.link_rx else { return };
        let update = match rx.try_recv() {
            Ok(update) => update,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                self.link_rx = None;
                self.link = LinkState::Unreachable("probe worker stopped".to_string());
                return;
            }
        };
        self.link_rx = None;
        match update {
            LinkUpdate::Connected(facts) => {
                self.link = LinkState::Connected;
                self.disk_error = None;
                self.accept_facts(facts);
            }
            LinkUpdate::Unreachable(err) => {
                self.link = LinkState::Unreachable(err.clone());
                self.disk_error = Some(err);
            }
        }
    }

    fn begin_remote_probe(&mut self) {
        let remote = self.state.remote.clone();
        self.link = LinkState::Linking;
        self.facts = None;
        self.disk_error = None;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let update = match crate::facts::collect_over_ssh(&remote) {
                Ok(facts) => LinkUpdate::Connected(facts),
                Err(err) => LinkUpdate::Unreachable(err),
            };
            let _ = tx.send(update);
        });
        self.link_rx = Some(rx);
    }

    pub fn link_badge(&self) -> (&'static str, &'static str, ratatui::style::Color) {
        match &self.link {
            LinkState::Local => ("●", "this machine", crate::install::theme::GREEN),
            LinkState::Offline => ("○", "offline", crate::install::theme::MUTED),
            LinkState::Linking => ("◐", "linking…", crate::install::theme::YELLOW),
            LinkState::Connected => ("●", "connected", crate::install::theme::GREEN),
            LinkState::Unreachable(_) => ("✗", "unreachable", crate::install::theme::RED),
        }
    }

    // ── input: choices ──────────────────────────────────────────

    pub fn select_next(&mut self) {
        let len = self.options().len();
        if len > 0 {
            self.cursor = (self.cursor + 1) % len;
        }
    }

    pub fn select_prev(&mut self) {
        let len = self.options().len();
        if len > 0 {
            self.cursor = (self.cursor + len - 1) % len;
        }
    }

    // ── input: editors ──────────────────────────────────────────

    pub fn item_next(&mut self) {
        self.flush_editor();
        let count = self.item_count();
        if count > 0 {
            self.item = (self.item + 1) % count;
        }
        self.sync_buffer();
    }

    pub fn item_prev(&mut self) {
        self.flush_editor();
        let count = self.item_count();
        if count > 0 {
            self.item = (self.item + count - 1) % count;
        }
        self.sync_buffer();
    }

    pub fn field_next(&mut self) {
        self.flush_editor();
        if let Some(editor) = self.editor() {
            self.field = (self.field + 1) % editor.field_count();
        }
        self.sync_buffer();
    }

    pub fn field_prev(&mut self) {
        self.flush_editor();
        if let Some(editor) = self.editor() {
            let n = editor.field_count();
            self.field = (self.field + n - 1) % n;
        }
        self.sync_buffer();
    }

    /// Space: cycle the enum-valued field (role/pool/mount kind).
    pub fn cycle(&mut self) {
        let Some(editor) = self.editor() else { return };
        match (editor, self.field) {
            (Editor::Disks, 0) => {
                // role
                if let Some(disk) = self.state.disks.get(self.item).cloned() {
                    let role = self.state.disk_role_for_path(&disk.path).next();
                    self.state.set_disk_role(&disk.path, role);
                    self.state.normalize_disk_roles();
                }
            }
            (Editor::Disks, 1) => {
                if let Some(disk) = self.state.disks.get(self.item).cloned() {
                    let pools = self.pool_names();
                    let current = self
                        .state
                        .disk_volume_group_for_path(&disk.path)
                        .map(str::to_string);
                    if let Some(next) = cycle_pool(&pools, current.as_deref()) {
                        self.state.set_disk_volume_group(&disk.path, &next);
                    }
                }
            }
            (Editor::Volumes, 1) => {
                // mount: toggle Path <-> Swap
                if let Some(vol) = self.state.volumes.get_mut(self.item) {
                    vol.mountpoint = match &vol.mountpoint {
                        Mountpoint::Swap => Mountpoint::Path("/".to_string()),
                        Mountpoint::Path(_) => Mountpoint::Swap,
                    };
                }
                self.sync_buffer();
            }
            (Editor::Volumes, 2) => {
                if let Some(vol) = self.state.volumes.get(self.item).cloned() {
                    let pools = self.pool_names();
                    let current = self.state.volume_group_for_volume(&vol.name).to_string();
                    if let Some(next) = cycle_pool(&pools, Some(&current)) {
                        self.state.set_volume_group_for_volume(&vol.name, &next);
                    }
                }
            }
            _ => {}
        }
    }

    /// +/- on a numeric field.
    pub fn adjust(&mut self, delta: i64) {
        let Some(editor) = self.editor() else { return };
        match (editor, self.field) {
            (Editor::Disks, 3) => {
                if let Some(disk) = self.state.disks.get_mut(self.item) {
                    disk.size_gib = apply_delta(disk.size_gib, delta);
                }
                self.sync_buffer();
            }
            (Editor::Volumes, 3) => {
                if let Some(vol) = self.state.volumes.get_mut(self.item) {
                    vol.size_gib = apply_delta(vol.size_gib, delta);
                }
                self.sync_buffer();
            }
            _ => {}
        }
    }

    /// Fit the current logical-volume plan into the selected disks without
    /// deleting mounts. This is an explicit recovery action, never an implicit
    /// destructive rewrite of a user-edited layout.
    pub fn scale_to_fit(&mut self) {
        let capacity = self.state.total_disk_gib();
        let used = self.state.used_gib();
        if capacity == 0 {
            self.status = "select a disk before scaling volumes".to_string();
            return;
        }
        let mut excess = used.saturating_sub(capacity);
        if excess == 0 {
            self.status = "layout already fits selected capacity".to_string();
            return;
        }
        while excess > 0 {
            let Some((index, _)) = self
                .state
                .volumes
                .iter()
                .enumerate()
                .filter(|(_, volume)| volume.size_gib > 1)
                .max_by_key(|(_, volume)| volume.size_gib)
            else {
                self.status = "cannot scale layout further without removing a volume".to_string();
                return;
            };
            let volume = &mut self.state.volumes[index];
            let reduction = excess.min(volume.size_gib - 1);
            volume.size_gib -= reduction;
            excess -= reduction;
        }
        self.sync_buffer();
        self.status = "scaled volumes to selected disk capacity".to_string();
    }

    #[allow(dead_code)]
    pub fn enable_manual_storage(&mut self) {
        self.manual_storage = true;
        self.status = "manual layout enabled — press Enter to edit pools and volumes".to_string();
    }

    pub fn insert(&mut self, ch: char) {
        match self.current().kind() {
            StepKind::Password => {
                if !ch.is_control() {
                    if self.current() == Step::PasswordConfirm {
                        self.password_confirm.push(ch);
                    } else {
                        self.password.push(ch);
                    }
                }
            }
            StepKind::Text => {
                if !ch.is_control() {
                    self.edit_text(InputRequest::InsertChar(ch));
                }
            }
            StepKind::Confirm => {
                if !ch.is_control() {
                    self.confirm_input.push(ch);
                }
            }
            StepKind::Editor(editor) => {
                if editor.is_text(self.field) && !ch.is_control() {
                    self.edit_text(InputRequest::InsertChar(ch));
                }
            }
            _ => {}
        }
    }

    pub fn backspace(&mut self) {
        match self.current().kind() {
            StepKind::Password => {
                if self.current() == Step::PasswordConfirm {
                    self.password_confirm.pop();
                } else {
                    self.password.pop();
                }
            }
            StepKind::Text => {
                self.edit_text(InputRequest::DeletePrevChar);
            }
            StepKind::Confirm => {
                self.confirm_input.pop();
            }
            StepKind::Editor(editor) => {
                if editor.is_text(self.field) {
                    self.edit_text(InputRequest::DeletePrevChar);
                }
            }
            _ => {}
        }
    }

    pub fn add_item(&mut self) {
        self.flush_editor();
        match self.editor() {
            Some(Editor::Disks) => {
                let path = format!("/dev/disk{}", self.state.disks.len());
                self.state
                    .disk_roles
                    .insert(path.clone(), DiskRole::PoolMember);
                self.state.disks.push(DiskChoice {
                    path,
                    size_gib: 256,
                    model: Some("manual".to_string()),
                });
                self.item = self.state.disks.len() - 1;
            }
            Some(Editor::Pools) => {
                let name = unique_name("pool", &self.pool_names());
                self.state.volume_groups.push(VolumeGroupDraft { name });
                self.item = self.state.volume_groups.len() - 1;
            }
            Some(Editor::Volumes) => {
                let name = unique_name(
                    "vol",
                    &self
                        .state
                        .volumes
                        .iter()
                        .map(|v| v.name.clone())
                        .collect::<Vec<_>>(),
                );
                let pool = self
                    .pool_names()
                    .first()
                    .cloned()
                    .unwrap_or_else(|| DEFAULT_STORAGE_POOL_NAME.to_string());
                self.state.volumes.push(Volume {
                    name: name.clone(),
                    mountpoint: Mountpoint::Path(format!("/{name}")),
                    size_gib: 16,
                    fs: crate::install::state::VolumeFs::Btrfs,
                    subvolumes: Vec::new(),
                    fill: false,
                });
                self.state.set_volume_group_for_volume(&name, &pool);
                self.item = self.state.volumes.len() - 1;
            }
            Some(Editor::DocSubvols) => {
                let name = unique_name("sub", &self.state.doc_subvolumes);
                self.state.doc_subvolumes.push(name);
                self.item = self.state.doc_subvolumes.len() - 1;
            }
            None => {}
        }
        self.field = 0;
        self.sync_buffer();
    }

    pub fn remove_item(&mut self) {
        match self.editor() {
            Some(Editor::Disks) => {
                if self.item < self.state.disks.len() {
                    let path = self.state.disks[self.item].path.clone();
                    self.state.disks.remove(self.item);
                    self.state.disk_roles.remove(&path);
                    self.state.disk_slices.remove(&path);
                    self.state.normalize_disk_roles();
                }
            }
            Some(Editor::Pools) => {
                if self.state.volume_groups.len() > 1 && self.item < self.state.volume_groups.len()
                {
                    self.state.volume_groups.remove(self.item);
                    self.state.normalize_storage_assignments();
                } else {
                    self.status = "keep at least one pool".to_string();
                }
            }
            Some(Editor::Volumes) => {
                if self.item < self.state.volumes.len() {
                    let name = self.state.volumes[self.item].name.clone();
                    self.state.volumes.remove(self.item);
                    self.state.volume_volume_groups.remove(&name);
                }
            }
            Some(Editor::DocSubvols) => {
                if self.item < self.state.doc_subvolumes.len() {
                    self.state.doc_subvolumes.remove(self.item);
                }
            }
            None => {}
        }
        let count = self.item_count();
        if count > 0 {
            self.item = self.item.min(count - 1);
        } else {
            self.item = 0;
        }
        self.field = 0;
        self.sync_buffer();
    }

    /// The text value of the currently focused editor text field.
    fn editor_text_value(&self) -> Option<String> {
        let editor = self.editor()?;
        if !editor.is_text(self.field) {
            return None;
        }
        match editor {
            Editor::Disks => {
                let disk = self.state.disks.get(self.item)?;
                Some(if self.field == 2 {
                    disk.path.clone()
                } else {
                    disk.size_gib.to_string()
                })
            }
            Editor::Volumes => {
                let vol = self.state.volumes.get(self.item)?;
                Some(match self.field {
                    0 => vol.name.clone(),
                    1 => vol.mountpoint.label().to_string(),
                    _ => vol.size_gib.to_string(),
                })
            }
            Editor::Pools => Some(self.state.volume_groups.get(self.item)?.name.clone()),
            Editor::DocSubvols => self.state.doc_subvolumes.get(self.item).cloned(),
        }
    }

    /// Write the buffer back into the focused text field, fixing any references.
    fn flush_editor(&mut self) {
        let Some(editor) = self.editor() else { return };
        if !editor.is_text(self.field) {
            return;
        }
        let value = self.buffer.trim().to_string();
        match editor {
            Editor::Disks => {
                let Some(disk) = self.state.disks.get(self.item).cloned() else {
                    return;
                };
                if self.field == 2 {
                    if !value.is_empty() && value != disk.path {
                        self.rename_disk(&disk.path, &value);
                    }
                } else if let Ok(size) = value.parse::<u64>() {
                    if let Some(d) = self.state.disks.get_mut(self.item) {
                        d.size_gib = size;
                    }
                }
            }
            Editor::Volumes => {
                let Some(vol) = self.state.volumes.get(self.item).cloned() else {
                    return;
                };
                match self.field {
                    0 => {
                        if !value.is_empty() && value != vol.name {
                            self.rename_volume(&vol.name, &value);
                        }
                    }
                    1 => {
                        if let Some(v) = self.state.volumes.get_mut(self.item) {
                            v.mountpoint = if value == "swap" {
                                Mountpoint::Swap
                            } else if value.is_empty() {
                                Mountpoint::Path("/".to_string())
                            } else {
                                Mountpoint::Path(value)
                            };
                        }
                    }
                    _ => {
                        if let Ok(size) = value.parse::<u64>() {
                            if let Some(v) = self.state.volumes.get_mut(self.item) {
                                v.size_gib = size;
                            }
                        }
                    }
                }
            }
            Editor::Pools => {
                let Some(pool) = self.state.volume_groups.get(self.item).cloned() else {
                    return;
                };
                if !value.is_empty() && value != pool.name {
                    let _ = self.state.rename_volume_group(&pool.name, &value);
                }
            }
            Editor::DocSubvols => {
                if let Some(sub) = self.state.doc_subvolumes.get_mut(self.item) {
                    if !value.is_empty() {
                        *sub = value;
                    }
                }
            }
        }
    }

    fn rename_disk(&mut self, old: &str, new: &str) {
        if let Some(disk) = self.state.disks.iter_mut().find(|d| d.path == old) {
            disk.path = new.to_string();
        }
        if let Some(role) = self.state.disk_roles.remove(old) {
            self.state.disk_roles.insert(new.to_string(), role);
        }
        if let Some(slices) = self.state.disk_slices.remove(old) {
            self.state.disk_slices.insert(new.to_string(), slices);
        }
    }

    fn rename_volume(&mut self, old: &str, new: &str) {
        if let Some(vol) = self.state.volumes.iter_mut().find(|v| v.name == old) {
            vol.name = new.to_string();
        }
        if let Some(vg) = self.state.volume_volume_groups.remove(old) {
            self.state.volume_volume_groups.insert(new.to_string(), vg);
        }
    }

    // ── back / advance ──────────────────────────────────────────

    pub fn back(&mut self) {
        if self.pos == 0 {
            return;
        }
        self.flush_editor();
        self.pos -= 1;
        self.load();
        // Stepping back into the storage step shows the overview page.
        if self.current() == Step::Storage {
            self.storage_popup = false;
        }
    }

    pub fn advance(&mut self) {
        self.flush_editor();
        if let Err(err) = self.commit() {
            self.status = err;
            return;
        }
        self.status.clear();

        if self.current() == Step::Confirm {
            self.done = true;
            return;
        }
        if self.pos + 1 < self.steps().len() {
            self.pos += 1;
            self.load();
        }
    }

    /// The storage layout is usable only when SOMETHING mounts at `/` — a
    /// plain partition, a btrfs partition (its root subvolume mounts there),
    /// or an explicit btrfs subvolume.
    pub fn storage_has_root(&self) -> bool {
        self.state.volumes.iter().any(|v| {
            v.mountpoint.label() == "/"
                || v.subvolumes.iter().any(|s| s.mountpoint == "/")
        })
    }

    fn commit(&mut self) -> Result<(), String> {
        match self.current() {
            Step::Storage if !self.storage_has_root() => {
                return Err(
                    "no root filesystem — mount a partition (or btrfs subvolume) at / first"
                        .to_string(),
                );
            }
            Step::Scope => {
                self.state.scope = if self.cursor == 0 {
                    InstallScope::Local
                } else {
                    InstallScope::Remote
                };
                self.link = if self.state.scope == InstallScope::Local {
                    LinkState::Local
                } else {
                    LinkState::Offline
                };
            }
            Step::Role => {
                self.state.role = if self.cursor == 0 {
                    InstallRole::Laptop
                } else {
                    InstallRole::Server
                };
            }
            Step::Ssh => self.state.allow_ssh = self.cursor == 1,
            Step::Locale => {
                if let Some((tz, _, _, _)) = TIMEZONES.get(self.cursor) {
                    self.state.timezone = tz.to_string();
                }
            }
            Step::Filesystem => {
                self.state.filesystem = if self.cursor == 0 {
                    Filesystem::Btrfs
                } else {
                    Filesystem::Ext4
                };
            }
            Step::Encrypt => self.state.encrypt = self.cursor == 1,
            Step::Overwrite => self.state.overwrite_existing_storage = self.cursor == 1,
            Step::NetworkCleanup => self.state.network_route_cleanup = self.cursor == 0,
            Step::BinEnsure => self.state.skip_bin_ensure = self.cursor == 0,
            Step::StorageMode => {
                self.manual_storage = self.cursor == 3;
                self.state.storage_mode = match self.cursor {
                    0 => StorageMode::SingleDisk,
                    1 => StorageMode::JoinedLvm,
                    2 => StorageMode::SeparatePools,
                    // `StorageMode::Manual` is a programmatic unsupported
                    // layout. The UI's Manual… choice instead opens the rich
                    // editors while retaining a renderable storage strategy.
                    _ if self.state.disks.len() <= 1 => StorageMode::SingleDisk,
                    _ => StorageMode::JoinedLvm,
                };
            }
            Step::Remote => {
                let value = self.buffer.trim();
                if !value.contains('@') || value.starts_with('@') || value.ends_with('@') {
                    return Err("remote should look like user@host".to_string());
                }
                self.state.remote = value.to_string();
                self.begin_remote_probe();
            }
            Step::Mountpoint => {
                let value = self.buffer.trim();
                validate_mountpoint(value).map_err(|e| e.to_string())?;
                self.state.mountpoint = value.to_string();
            }
            Step::Hostname => {
                let value = self.buffer.trim();
                validate_hostname(value)?;
                self.state.hostname = value.to_string();
            }
            Step::User => {
                let value = self.buffer.trim();
                validate_username(value)?;
                self.state.install_user = value.to_string();
            }
            Step::Dotfiles => {
                let value = self.buffer.trim();
                self.state.dotfiles_repo = (!value.is_empty()).then(|| value.to_string());
            }
            Step::Lvm => {
                self.state.use_lvm = self.cursor == 0;
                self.state.storage_mode = if self.state.use_lvm {
                    StorageMode::JoinedLvm
                } else {
                    StorageMode::SingleDisk
                };
            }
            Step::Disks => {
                if self.disk_selected.is_empty() {
                    return Err("select at least one disk (space to toggle)".to_string());
                }
                if !self.state.use_lvm && self.disk_selected.len() > 1 {
                    return Err("plain layout supports a single disk — deselect the rest".to_string());
                }
                self.apply_disk_selection();
            }
            Step::Efi => {
                self.state.esp_size_mib = match self.cursor {
                    0 => 512,
                    2 => 2048,
                    _ => 1024,
                };
            }
            Step::Storage => {
                self.state.normalize_disk_roles();
                self.state.normalize_storage_assignments();
            }
            Step::Volumes => {
                self.state.normalize_storage_assignments();
            }
            Step::PasswordConfirm => {
                if self.password_confirm != self.password {
                    return Err("passwords do not match".to_string());
                }
            }
            Step::Users => {
                for user in &self.state.users {
                    validate_username(&user.name)?;
                }
                let mut seen = std::collections::BTreeSet::new();
                for user in &self.state.users {
                    if !seen.insert(user.name.clone()) {
                        return Err(format!("duplicate username: {}", user.name));
                    }
                }
                self.state.sync_primary_user();
            }
            Step::ExtraDisks | Step::Password | Step::Pools | Step::DocSubvols => {}
            Step::Review => match self.preflight.as_ref() {
                None if self.preflight_rx.is_some() => {
                    return Err("preflight still running…".to_string());
                }
                None => return Err("run preflight first (space)".to_string()),
                Some(report) if !report.pass() => {
                    return Err(format!(
                        "preflight failing: {} — fix and rerun (␣)",
                        failing_names(report)
                    ));
                }
                _ => {}
            },
            Step::Confirm => {
                if self.confirm_input.trim() != self.confirm_phrase() {
                    return Err("confirmation phrase does not match".to_string());
                }
            }
        }
        Ok(())
    }

    /// Space on Review: run preflight on a worker thread so the UI keeps
    /// drawing; progress lands in the status line via `poll_preflight`.
    pub fn toggle(&mut self, repo: &std::path::Path) {
        if self.current() != Step::Review || self.preflight_rx.is_some() {
            return;
        }
        let repo = repo.to_path_buf();
        let state = self.state.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let progress_tx = tx.clone();
            let progress = move |message: &str| {
                let _ = progress_tx.send(PreflightUpdate::Progress(message.to_string()));
            };
            let report = crate::install::preflight::run(&repo, &state, &progress);
            let _ = tx.send(PreflightUpdate::Done(report));
        });
        self.preflight_rx = Some(rx);
        self.preflight = None;
        self.status = "preflight running…".to_string();
    }

    pub fn preflight_running(&self) -> bool {
        self.preflight_rx.is_some()
    }

    /// Called every UI tick: drain worker messages into the status line and
    /// pick up the finished report.
    pub fn poll_preflight(&mut self) {
        let Some(rx) = &self.preflight_rx else { return };
        loop {
            match rx.try_recv() {
                Ok(PreflightUpdate::Progress(message)) => {
                    self.status = format!("preflight: {message}");
                }
                Ok(PreflightUpdate::Done(report)) => {
                    self.status = if report.pass() {
                        "preflight passed — enter continues".to_string()
                    } else {
                        format!(
                            "preflight failing: {} — fix and rerun (␣)",
                            failing_names(&report)
                        )
                    };
                    // Secrets can't decrypt and no decision was made yet:
                    // offer the key/skip chooser instead of a dead end.
                    if secrets_check_failed(&report)
                        && self.state.secrets_mode
                            == crate::install::state::SecretsMode::YubiKey
                    {
                        self.secrets_popup = true;
                    }
                    self.preflight = Some(report);
                    self.preflight_rx = None;
                    return;
                }
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    self.status = "preflight worker died — rerun (␣)".to_string();
                    self.preflight_rx = None;
                    return;
                }
            }
        }
    }

    // ── the secrets chooser (no usable key at preflight) ─────────

    /// Pick "use the YubiKey" again (after plugging it in / starting pcscd).
    pub fn secrets_choose_yubikey(&mut self, repo: &std::path::Path) {
        self.state.secrets_mode = crate::install::state::SecretsMode::YubiKey;
        self.secrets_close_and_rerun(repo);
    }

    /// Pick "install without secrets": the target gets
    /// `bresilla.secrets.enable = false` and no key is copied; everything
    /// that does not need secrets still installs.
    pub fn secrets_choose_skip(&mut self, repo: &std::path::Path) {
        self.state.secrets_mode = crate::install::state::SecretsMode::Skip;
        self.secrets_close_and_rerun(repo);
    }

    /// Start typing an age key file path.
    pub fn secrets_key_begin(&mut self) {
        let prefill = match &self.state.secrets_mode {
            crate::install::state::SecretsMode::KeyFile(path) => path.clone(),
            _ => String::new(),
        };
        self.secrets_key_edit = Some(prefill);
    }

    pub fn secrets_key_insert(&mut self, ch: char) {
        if let Some(buf) = self.secrets_key_edit.as_mut() {
            if !ch.is_control() && buf.len() < 200 {
                buf.push(ch);
            }
        }
    }

    pub fn secrets_key_backspace(&mut self) {
        if let Some(buf) = self.secrets_key_edit.as_mut() {
            buf.pop();
        }
    }

    pub fn secrets_key_cancel(&mut self) {
        self.secrets_key_edit = None;
    }

    /// Apply the typed key path (with ~ expansion) and re-validate.
    pub fn secrets_key_apply(&mut self, repo: &std::path::Path) {
        let Some(path) = self.secrets_key_edit.take() else { return };
        let path = path.trim().to_string();
        if path.is_empty() {
            self.status = "type a path to an age identity file".to_string();
            self.secrets_key_edit = Some(String::new());
            return;
        }
        let path = if let Some(rest) = path.strip_prefix("~/") {
            match std::env::var("HOME") {
                Ok(home) => format!("{home}/{rest}"),
                Err(_) => path,
            }
        } else {
            path
        };
        self.state.secrets_mode = crate::install::state::SecretsMode::KeyFile(path);
        self.secrets_close_and_rerun(repo);
    }

    fn secrets_close_and_rerun(&mut self, repo: &std::path::Path) {
        self.secrets_popup = false;
        self.secrets_key_edit = None;
        self.toggle(repo);
    }

    pub fn confirm_phrase(&self) -> String {
        crate::install::confirm::DestructiveConfirmation::from_state(&self.state).phrase
    }

    pub fn confirm_armed(&self) -> bool {
        self.confirm_input.trim() == self.confirm_phrase()
    }

    /// Passwords are now hashed per user as they are entered; this just mirrors
    /// the primary account into the legacy scalar fields before install.
    pub fn commit_password(&mut self) -> Result<(), String> {
        self.state.sync_primary_user();
        Ok(())
    }
}

fn secrets_check_failed(report: &PreflightReport) -> bool {
    report.checks.iter().any(|c| {
        c.name == "secrets" && c.status == crate::install::preflight::PreflightStatus::Fail
    })
}

/// Names of the failing preflight checks, comma-joined for status messages.
fn failing_names(report: &PreflightReport) -> String {
    report
        .checks
        .iter()
        .filter(|c| c.status == crate::install::preflight::PreflightStatus::Fail)
        .map(|c| c.name)
        .collect::<Vec<_>>()
        .join(", ")
}

fn cycle_pool(pools: &[String], current: Option<&str>) -> Option<String> {
    if pools.is_empty() {
        return None;
    }
    let idx = current
        .and_then(|c| pools.iter().position(|p| p == c))
        .map(|i| (i + 1) % pools.len())
        .unwrap_or(0);
    Some(pools[idx].clone())
}

fn apply_delta(value: u64, delta: i64) -> u64 {
    if delta >= 0 {
        value.saturating_add(delta as u64)
    } else {
        value.saturating_sub((-delta) as u64)
    }
}

fn unique_name(base: &str, existing: &[String]) -> String {
    if !existing.iter().any(|n| n == base) {
        return base.to_string();
    }
    (1..)
        .map(|i| format!("{base}{i}"))
        .find(|n| !existing.contains(n))
        .unwrap()
}

fn validate_hostname(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("hostname is required".to_string());
    }
    if value.len() > 63
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || value.starts_with('-')
        || value.ends_with('-')
    {
        return Err("hostname: lowercase letters, digits, dashes".to_string());
    }
    Ok(())
}

fn validate_username(value: &str) -> Result<(), String> {
    let mut chars = value.chars();
    match chars.next() {
        None => return Err("username is required".to_string()),
        Some(c) if !(c.is_ascii_lowercase() || c == '_') => {
            return Err("username must start with a lowercase letter".to_string())
        }
        _ => {}
    }
    if chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') {
        Ok(())
    } else {
        Err("username: lowercase letters, digits, _ and -".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow() -> Flow {
        let mut f = Flow::new(InstallState::draft());
        f.disable_discovery = true; // keep unit tests pure
        let disk = DiskChoice {
            path: "/dev/testdisk".into(),
            size_gib: 465,
            model: Some("test disk".into()),
        };
        f.state.disks = vec![disk.clone()];
        f.state.disk_roles.insert(disk.path, DiskRole::System);
        f.state.normalize_storage_assignments();
        f
    }

    fn walk_to(f: &mut Flow, target: Step) {
        // advance with valid defaults until we reach target (safety-bounded)
        for _ in 0..40 {
            if f.current() == target {
                return;
            }
            // The storage gate demands a root filesystem; build the minimal
            // layout (pool over the disk + one root partition) like a user.
            if f.current() == Step::Storage && !f.storage_has_root() {
                f.goto_pools();
                f.pool_from_free();
                f.pool_enter();
                f.disk_add(); // first partition defaults to root at /
                f.goto_disks();
            }
            f.advance();
        }
        panic!("never reached {target:?}");
    }

    /// The explicit build-up a user performs from the empty start: claim the
    /// disk's free space as a pool (a on the map), then add one partition
    /// (a in the pool). Returns with the flow inside the pool's partitions.
    fn build_pool_with_partition(f: &mut Flow) {
        walk_to(f, Step::Storage);
        f.goto_pools();
        f.map_disk = 0;
        f.seg_sel = 0;
        f.pool_from_free();
        f.storage_forward(); // enter the pool
        f.disk_add(); // first partition
        f.vol_sel = 0;
    }

    #[test]
    fn resizing_a_partition_never_touches_other_partitions() {
        let mut f = flow();
        f.cursor = 0; // local
        build_pool_with_partition(&mut f); // "vol" takes the whole pool
        // Shrink it so a second partition has room.
        f.size_begin(Some('1'));
        f.size_insert('0');
        f.size_insert('0');
        f.size_apply();
        // Add a second, fixed "home" partition.
        f.state
            .volumes
            .push(crate::install::state::Volume::filesystem("home", "/home", 32).unwrap());
        f.state
            .set_volume_group_for_volume("home", DEFAULT_STORAGE_POOL_NAME);
        f.vol_sel = f
            .volumes_in_selected_pool()
            .iter()
            .position(|&i| f.state.volumes[i].name == "home")
            .unwrap();
        let home_i = f
            .state
            .volumes
            .iter()
            .position(|v| v.name == "home")
            .unwrap();
        let root_i = f
            .state
            .volumes
            .iter()
            .position(|v| v.name == "root")
            .unwrap();
        let root_before = f.state.volumes[root_i].size_gib;
        f.disk_resize(8);
        // The resized partition changed; the other one did NOT.
        assert_eq!(f.state.volumes[home_i].size_gib, 40);
        assert_eq!(f.state.volumes[root_i].size_gib, root_before);
    }

    #[test]
    fn disk_editor_add_and_delete_volume_in_pool() {
        let mut f = flow();
        f.cursor = 0;
        walk_to(&mut f, Step::Storage);
        f.goto_pools();
        f.pool_from_free(); // the pool needs space before partitions can exist
        f.pool_enter();
        let before = f.volumes_in_selected_pool().len();
        f.disk_add();
        assert_eq!(f.volumes_in_selected_pool().len(), before + 1);
        f.disk_delete();
        assert_eq!(f.volumes_in_selected_pool().len(), before);
    }

    #[test]
    fn simple_flow_skips_advanced_editors_until_manual_layout_is_enabled() {
        let mut f = flow();
        f.cursor = 0; // local
        f.advance();
        let steps = f.steps();
        for s in [
            Step::Scope,
            Step::Mountpoint,
            Step::Locale,
            Step::Hostname,
            Step::Role,
            Step::Ssh,
            Step::Lvm,
            Step::Encrypt,
            Step::Storage,
            Step::Overwrite,
            Step::NetworkCleanup,
            Step::BinEnsure,
            Step::Users,
            Step::Review,
            Step::Confirm,
        ] {
            assert!(steps.contains(&s), "missing step {s:?}");
        }
        // LVM/LUKS decided before the disk editor; accounts come last.
        let idx = |s: Step| steps.iter().position(|x| *x == s).unwrap();
        assert!(idx(Step::Lvm) < idx(Step::Storage), "LVM decided before disk editor");
        assert!(idx(Step::Encrypt) < idx(Step::Storage), "encryption decided before disk editor");
        assert!(idx(Step::Users) > idx(Step::Storage), "user accounts come last");
        // Disk selection + EFI are folded into the single Storage editor now.
        assert!(!steps.contains(&Step::Disks));
        assert!(!steps.contains(&Step::Efi));
    }

    #[test]
    fn users_editor_add_remove_and_groups() {
        let mut f = flow();
        f.cursor = 0;
        walk_to(&mut f, Step::Users);
        let n = f.user_count();
        f.users_add();
        assert_eq!(f.user_count(), n + 1);
        // toggle a group for the new user via the detail-row editor
        let g = "corner";
        let has = |f: &Flow| {
            f.state.users[f.user_sel]
                .groups
                .iter()
                .any(|x| x == g)
        };
        let had = has(&f);
        f.users_popup_open();
        f.users_enter();
        let idx = crate::install::state::AVAILABLE_GROUPS
            .iter()
            .position(|x| *x == g)
            .unwrap();
        f.user_row = 3 + idx; // rows 0-2 are name/password/dotfiles
        f.user_edit_row();
        assert_ne!(has(&f), had);
        f.users_back();
        f.users_delete();
        assert_eq!(f.user_count(), n);
    }

    #[test]
    fn everything_starts_empty_until_the_user_builds_it() {
        let mut f = flow();
        f.cursor = 0;
        walk_to(&mut f, Step::Storage);
        // No partitions and no pool allocations exist up front.
        assert!(f.state.volumes.is_empty());
        let pool = f.selected_pool_name().unwrap();
        assert_eq!(f.state.pool_capacity_gib(&pool), 0);
        // The map shows the whole disk as one free segment.
        f.goto_pools();
        assert!(f.on_free_segment());
        // a claims it as the first pool.
        f.pool_from_free();
        assert!(f.state.pool_capacity_gib(&pool) > 0);
        // The pool's partition list starts empty too.
        f.storage_forward();
        assert!(f.volumes_in_selected_pool().is_empty());
    }

    #[test]
    fn typing_a_size_sets_the_partition_exactly() {
        let mut f = flow();
        f.cursor = 0;
        build_pool_with_partition(&mut f);
        f.size_begin(Some('2'));
        f.size_insert('5');
        f.size_insert('6');
        f.size_apply();
        let i = f.selected_volume_index().unwrap();
        assert_eq!(f.state.volumes[i].size_gib, 256);
    }

    #[test]
    fn new_partition_claims_all_free_space() {
        let mut f = flow();
        f.cursor = 0;
        walk_to(&mut f, Step::Storage);
        f.goto_pools();
        f.pool_from_free();
        let pool = f.selected_pool_name().unwrap();
        let cap = f.state.pool_capacity_gib(&pool);
        f.storage_forward();
        f.disk_add();
        let i = f.selected_volume_index().unwrap();
        // Like the pool on the map: the new partition takes everything free.
        assert_eq!(f.state.volumes[i].size_gib, cap);
        assert_eq!(f.pool_free_gib(&pool), 0);
        // A second a with no free space is refused with a hint.
        let before = f.volumes_in_selected_pool().len();
        f.disk_add();
        assert_eq!(f.volumes_in_selected_pool().len(), before);
        assert!(!f.status.is_empty());
    }

    #[test]
    fn typing_a_segment_size_on_the_map_sets_pool_capacity() {
        let mut f = flow();
        f.cursor = 0;
        walk_to(&mut f, Step::Storage);
        let pool = f.selected_pool_name().unwrap();
        f.goto_pools();
        f.map_disk = 0;
        f.seg_sel = 0;
        f.pool_from_free(); // claim the disk first
        f.seg_sel = 0;
        f.size_begin(Some('1'));
        f.size_insert('0');
        f.size_insert('0');
        f.size_apply();
        assert_eq!(f.state.pool_capacity_gib(&pool), 100);
        // Nothing else was touched: still no partitions.
        assert!(f.state.volumes.is_empty());
        assert_eq!(f.pool_free_gib(&pool), 100);
    }

    #[test]
    fn re_entering_storage_preserves_partition_sizes() {
        let mut f = flow();
        f.cursor = 0;
        build_pool_with_partition(&mut f);
        f.size_begin(Some('5'));
        f.size_insert('0');
        f.size_apply();
        let i = f.selected_volume_index().unwrap();
        assert_eq!(f.state.volumes[i].size_gib, 50);
        // Leave the storage step entirely (Esc up to the top page, then out),
        // then come back — the size must survive.
        f.goto_disks();
        f.back();
        assert_ne!(f.current(), Step::Storage);
        f.advance();
        assert_eq!(f.current(), Step::Storage);
        f.goto_pools();
        f.pool_enter();
        f.vol_sel = 0;
        let i = f.selected_volume_index().unwrap();
        assert_eq!(f.state.volumes[i].size_gib, 50, "size survived leaving the step");
    }

    #[test]
    fn storage_editor_cycles_per_volume_filesystem() {
        let mut f = flow();
        f.cursor = 0;
        build_pool_with_partition(&mut f);
        let i = f.selected_volume_index().unwrap();
        assert_eq!(f.state.volumes[i].fs, VolumeFs::Btrfs);
        f.disk_cycle_fs();
        assert_eq!(f.state.volumes[i].fs, VolumeFs::Ext4);
        // cycling to swap flips the mountpoint kind to swap.
        f.disk_cycle_fs(); // xfs
        f.disk_cycle_fs(); // swap
        assert_eq!(f.state.volumes[i].fs, VolumeFs::Swap);
        assert!(matches!(f.state.volumes[i].mountpoint, Mountpoint::Swap));
    }

    #[test]
    fn subvolume_editor_only_opens_for_btrfs_and_adds_subvolumes() {
        let mut f = flow();
        f.cursor = 0;
        build_pool_with_partition(&mut f);
        let i = f.selected_volume_index().unwrap();
        // btrfs by default → sub-editor opens and can add a subvolume.
        f.subvol_open();
        assert_eq!(f.subvol_target, Some(i));
        f.subvol_add();
        assert_eq!(f.state.volumes[i].subvolumes.len(), 1);
        f.subvol_close();
        assert!(f.subvol_target.is_none());
        // ext4 → no subvolumes, and existing ones are dropped.
        f.disk_cycle_fs();
        assert_eq!(f.state.volumes[i].fs, VolumeFs::Ext4);
        assert!(f.state.volumes[i].subvolumes.is_empty());
        f.subvol_open();
        assert!(f.subvol_target.is_none());
    }

    #[test]
    fn storage_editor_renames_and_remounts_a_partition() {
        let mut f = flow();
        f.cursor = 0;
        build_pool_with_partition(&mut f);
        // rename the partition
        f.disk_begin_edit(PartField::Name);
        while f.disk_rename.as_deref().map(|s| !s.is_empty()).unwrap_or(false) {
            f.disk_rename_backspace();
        }
        for ch in "data".chars() {
            f.disk_rename_insert(ch);
        }
        f.disk_apply_rename();
        assert!(f.state.volumes.iter().any(|v| v.name == "data"));
        // change its mountpoint
        f.disk_begin_edit(PartField::Mount);
        while f.disk_rename.as_deref().map(|s| !s.is_empty()).unwrap_or(false) {
            f.disk_rename_backspace();
        }
        for ch in "/srv".chars() {
            f.disk_rename_insert(ch);
        }
        f.disk_apply_rename();
        let i = f.selected_volume_index().unwrap();
        assert_eq!(f.state.volumes[i].mountpoint.label(), "/srv");
    }

    #[test]
    fn pool_fields_are_editable_inside_the_pool() {
        let mut f = flow();
        f.cursor = 0;
        build_pool_with_partition(&mut f); // inside the pool (band zone)
        // ↑↑ to the pool name row, e, retype, Enter-commit → renamed.
        f.part_zone_up();
        f.part_zone_up();
        assert_eq!(f.part_zone, 0);
        f.pool_edit_row();
        assert!(f.pool_edit.is_some());
        f.pool_edit = Some((0, "fast".into()));
        f.pool_edit_apply();
        assert!(f.state.volume_groups.iter().any(|g| g.name == "fast"));
        // ↓ to the size row, type an exact pool capacity.
        f.part_zone_down();
        f.pool_edit = Some((1, "200".into()));
        f.pool_edit_apply();
        assert_eq!(f.state.pool_capacity_gib("fast"), 200);
    }

    #[test]
    fn detail_page_edits_fields_in_place() {
        let mut f = flow();
        f.cursor = 0;
        build_pool_with_partition(&mut f); // inside pool, "vol" selected
        f.subvols_enter(); // e: into the partition detail
        assert_eq!(f.disk_stage, DiskStage::Subvols);
        // Row 0 = name: e opens the inline buffer, Enter-commit renames.
        f.part_cursor = 0;
        f.detail_edit_row();
        assert!(f.detail_edit.is_some());
        f.detail_edit = Some((0, "data".into()));
        f.detail_edit_apply();
        assert!(f.state.volumes.iter().any(|v| v.name == "data"));
        // Row 3 = size: typing an exact number, unfills.
        f.part_cursor = 3;
        f.detail_edit = Some((3, "120".into()));
        f.detail_edit_apply();
        let v = f.state.volumes.iter().find(|v| v.name == "data").unwrap();
        assert_eq!(v.size_gib, 120);
        // Row 4 = rest toggle.
        f.part_cursor = 4;
        f.detail_edit_row();
        let v = f.state.volumes.iter().find(|v| v.name == "data").unwrap();
        assert!(v.fill);
        // b climbs back out to the partitions tier.
        f.storage_back();
        assert_eq!(f.disk_stage, DiskStage::Partitions);
    }

    #[test]
    fn finish_only_works_at_top_with_a_root() {
        let mut f = flow();
        f.cursor = 0;
        walk_to(&mut f, Step::Storage);
        f.storage_popup_open();
        // No root yet → f refuses.
        f.storage_finish();
        assert!(f.storage_popup);
        assert!(f.status.contains("root"));
        // Build a root, but try f from deep in the tree → refused.
        f.goto_pools();
        f.pool_from_free();
        f.pool_enter();
        f.disk_add();
        f.storage_finish();
        assert!(f.storage_popup);
        assert!(f.status.contains("top"));
        // At the top with a root, f closes the editor.
        f.goto_disks();
        f.storage_finish();
        assert!(!f.storage_popup);
    }

    #[test]
    fn tab_focuses_next_button_for_enter_activation() {
        use crate::install::flow::FooterFocus;
        let mut f = flow();
        f.cursor = 0;
        walk_to(&mut f, Step::Storage);
        f.storage_forward(); // deep inside the tree (pools)
        // Tab reaches [ next › ]; Tab again reaches [ ‹ prev ]; again → page.
        f.footer_cycle(true);
        assert_eq!(f.footer_focus, Some(FooterFocus::Next));
        f.footer_cycle(true);
        assert_eq!(f.footer_focus, Some(FooterFocus::Prev));
        f.footer_cycle(true);
        assert_eq!(f.footer_focus, None);
    }

    #[test]
    fn enter_drills_inside_storage_instead_of_advancing() {
        let mut f = flow();
        f.cursor = 0;
        walk_to(&mut f, Step::Storage);
        // Inside the storage TREE, e goes INSIDE (to pools) — never onward.
        f.storage_forward();
        assert_eq!(f.current(), Step::Storage);
        assert_eq!(f.disk_stage, DiskStage::Pools);
        // Advancing is blocked until something mounts at /.
        f.advance();
        assert_eq!(f.current(), Step::Storage);
        assert!(f.status.contains("root"));
        // Build the root, then the wizard moves on.
        f.pool_from_free();
        f.pool_enter();
        f.disk_add();
        f.advance();
        assert_eq!(f.current(), Step::Overwrite);
    }

    #[test]
    fn esc_from_overwrite_returns_to_storage_overview() {
        let mut f = flow();
        f.cursor = 0;
        build_pool_with_partition(&mut f);
        // Finish the storage step, landing on Overwrite.
        f.advance();
        assert_eq!(f.current(), Step::Overwrite);
        // Esc re-enters storage on the calm overview (editor closed)…
        f.back();
        assert_eq!(f.current(), Step::Storage);
        assert!(!f.storage_popup);
        // …and e re-opens the editor with the layout intact.
        f.storage_popup_open();
        assert!(f.storage_popup);
        assert!(f.storage_has_root());
        // Esc never leaves the window — only f (at the top, with a root) does.
        f.storage_back();
        assert!(f.storage_popup);
        f.storage_finish();
        assert!(!f.storage_popup);
    }

    #[test]
    fn edit_popup_rewrites_a_partition_in_one_apply() {
        let mut f = flow();
        f.cursor = 0;
        build_pool_with_partition(&mut f); // "vol" 1G btrfs /vol
        f.edit_open();
        assert!(f.edit_popup.is_some());
        // name → data
        {
            let p = f.edit_popup.as_mut().unwrap();
            p.fields[0].buf = "data".into();
            p.fields[1].buf = "/srv".into();
            p.fields[3].buf = "120".into();
        }
        // filesystem → ext4 (cursor to field 2, cycle once)
        f.edit_popup.as_mut().unwrap().cursor = 2;
        f.edit_cycle(1);
        f.edit_apply();
        assert!(f.edit_popup.is_none());
        let v = f.state.volumes.iter().find(|v| v.name == "data").unwrap();
        assert_eq!(v.mountpoint.label(), "/srv");
        assert_eq!(v.fs, VolumeFs::Ext4);
        assert_eq!(v.size_gib, 120);
    }

    #[test]
    fn edit_popup_validation_keeps_popup_open() {
        let mut f = flow();
        f.cursor = 0;
        build_pool_with_partition(&mut f);
        f.edit_open();
        f.edit_popup.as_mut().unwrap().fields[1].buf = "no-slash".into();
        f.edit_apply();
        // Bad mountpoint → error surfaced, popup still open with the input.
        assert!(f.edit_popup.is_some());
        assert!(!f.status.is_empty());
    }

    #[test]
    fn edit_popup_moves_segment_by_typing_existing_pool_name() {
        let mut f = flow();
        f.cursor = 0;
        walk_to(&mut f, Step::Storage);
        f.goto_pools();
        f.pool_from_free();
        f.seg_sel = 0;
        f.slice_split(); // creates pool1 on the new half, cursor on it
        f.edit_open();
        // Typing the EXISTING pool's name moves the segment there.
        f.edit_popup.as_mut().unwrap().fields[0].buf = "pool".into();
        f.edit_apply();
        assert!(f.edit_popup.is_none());
        let (path, idx) = f.selected_slice().unwrap();
        assert_eq!(f.state.slices_for_disk(&path)[idx].pool, "pool");
        // pool1 dissolved.
        assert_eq!(f.state.volume_groups.len(), 1);
    }

    #[test]
    fn two_disks_join_one_pool_with_p() {
        let mut f = flow();
        f.cursor = 0;
        // Second disk available + selected.
        let second = DiskChoice {
            path: "/dev/sdb".into(),
            size_gib: 932,
            model: None,
        };
        f.state.discovered_disks = vec![
            DiskChoice {
                path: "/dev/testdisk".into(),
                size_gib: 465,
                model: None,
            },
            second.clone(),
        ];
        walk_to(&mut f, Step::Storage);
        f.disk_cursor = 1;
        f.disk_row_toggle_selected(); // sdb joins the install
        f.goto_pools();
        // Claim disk 1 for the pool.
        f.map_disk = 0;
        f.seg_sel = 0;
        f.pool_from_free();
        let cap_one = f.state.pool_capacity_gib("pool");
        assert!(cap_one > 0);
        // On disk 2's free space, p JOINS the existing pool directly.
        f.map_disk = 1;
        f.clamp_seg();
        assert!(f.on_free_segment());
        f.slice_cycle_pool();
        assert_eq!(f.state.pool_capacity_gib("pool"), cap_one + 932);
        // Still exactly one pool.
        assert_eq!(f.state.volume_groups.len(), 1);
    }

    #[test]
    fn p_on_a_stray_pool_segment_merges_it_back() {
        // The scenario from the field: a made pool1 on the second disk; p on
        // that segment must fold it into the main pool and dissolve pool1.
        let mut f = flow();
        f.cursor = 0;
        let second = DiskChoice {
            path: "/dev/sdb".into(),
            size_gib: 932,
            model: None,
        };
        f.state.discovered_disks = vec![
            DiskChoice {
                path: "/dev/testdisk".into(),
                size_gib: 465,
                model: None,
            },
            second.clone(),
        ];
        walk_to(&mut f, Step::Storage);
        f.disk_cursor = 1;
        f.disk_row_toggle_selected();
        f.goto_pools();
        f.map_disk = 0;
        f.seg_sel = 0;
        f.pool_from_free(); // pool ← disk1
        f.map_disk = 1;
        f.clamp_seg();
        f.pool_from_free(); // pool1 ← disk2 (a makes a NEW pool)
        assert_eq!(f.state.volume_groups.len(), 2);
        // p on the pool1 segment cycles it into "pool"; empty pool1 dissolves.
        f.slice_cycle_pool();
        let (path, idx) = f.selected_slice().unwrap();
        assert_eq!(f.state.slices_for_disk(&path)[idx].pool, "pool");
        assert_eq!(f.state.volume_groups.len(), 1);
        assert_eq!(f.state.pool_capacity_gib("pool"), 464 + 932);
    }

    #[test]
    fn moving_a_segment_with_p_creates_and_fills_a_second_pool() {
        let mut f = flow();
        f.cursor = 0;
        walk_to(&mut f, Step::Storage);
        f.goto_pools();
        f.map_disk = 0;
        f.seg_sel = 0;
        f.pool_from_free(); // claim the empty disk first
        f.seg_sel = 0;
        let cap_before = f.state.pool_capacity_gib("pool");
        assert!(cap_before > 0);
        // One keypress: with a single pool, p invents the second and moves the
        // segment there. The emptied original pool dissolves.
        f.slice_cycle_pool();
        let (path, idx) = f.selected_slice().unwrap();
        let now = f.state.slices_for_disk(&path)[idx].pool.clone();
        assert_ne!(now, "pool");
        assert_eq!(f.state.pool_capacity_gib(&now), cap_before);
    }

    #[test]
    fn splitting_a_segment_creates_a_new_pool_in_one_keypress() {
        let mut f = flow();
        f.cursor = 0;
        walk_to(&mut f, Step::Storage);
        f.goto_pools();
        f.map_disk = 0;
        f.seg_sel = 0;
        f.pool_from_free(); // claim the empty disk first
        f.seg_sel = 0;
        let (path, _) = f.selected_slice().unwrap();
        let cap = f.state.pool_capacity_gib("pool");
        let pools_before = f.state.volume_groups.len();
        // s = split → the new half lands in a brand-new pool.
        f.slice_split();
        assert_eq!(f.state.slices_for_disk(&path).len(), 2);
        assert_eq!(f.state.volume_groups.len(), pools_before + 1);
        let second = f.state.volume_groups.last().unwrap().name.clone();
        assert_eq!(f.state.pool_capacity_gib(&second), cap / 2);
        assert_eq!(f.state.pool_capacity_gib("pool"), cap - cap / 2);
        // Deleting the new segment frees the space and dissolves its pool.
        f.slice_delete();
        assert_eq!(f.state.slices_for_disk(&path).len(), 1);
        assert!(!f.state.volume_groups.iter().any(|g| g.name == second));
        assert_eq!(f.state.disk_free_gib(&path), cap / 2);
    }

    #[test]
    fn storage_step_is_followed_by_overwrite_confirmation() {
        let mut f = flow();
        f.cursor = 0;
        build_pool_with_partition(&mut f); // root at / exists
        f.advance();
        assert_eq!(f.current(), Step::Overwrite);
    }

    #[test]
    fn discovered_empty_disk_is_selected_instead_of_a_draft_path() {
        let mut f = flow();
        f.state.disks.clear();
        f.state.disk_roles.clear();
        let facts = TargetFacts {
            mem_mib: Some(16 * 1024),
            disks: vec![
                crate::facts::DiskFacts {
                    path: "/dev/system".into(),
                    size_bytes: 2_000 * 1024 * 1024 * 1024,
                    partitions: vec![crate::facts::PartitionFacts {
                        path: "/dev/system1".into(),
                        size_bytes: 1_000 * 1024 * 1024 * 1024,
                        fstype: Some("ext4".into()),
                        label: None,
                        mountpoints: vec!["/".into()],
                    }],
                    ..crate::facts::DiskFacts::default()
                },
                crate::facts::DiskFacts {
                    path: "/dev/empty".into(),
                    size_bytes: 500 * 1024 * 1024 * 1024,
                    ..crate::facts::DiskFacts::default()
                },
            ],
            ..TargetFacts::default()
        };

        f.accept_facts(facts);

        assert_eq!(f.state.disks.len(), 1);
        assert_eq!(f.state.disks[0].path, "/dev/empty");
        assert_eq!(f.state.storage_mode, StorageMode::SingleDisk);
        // NOTHING is pre-decided: the layout starts with zero partitions and
        // the user builds pools + partitions explicitly in the editor.
        assert!(f.state.volumes.is_empty());
    }

    #[test]
    fn text_input_edits_at_the_tui_input_cursor() {
        let mut f = flow();
        f.cursor = 0; // local
        f.advance();
        assert_eq!(f.current(), Step::Mountpoint);
        f.text_cursor_prev();
        f.insert('X');
        assert_eq!(f.buffer, "/mnXt");
        assert_eq!(f.text_cursor(), 4);
    }

    #[test]
    fn scale_to_fit_reduces_an_over_capacity_plan() {
        let mut f = flow();
        f.state.disks[0].size_gib = 100;
        // Seed an over-capacity plan: two volumes summing past the disk size.
        f.state.volumes = vec![
            crate::install::state::Volume::filesystem("root", "/", 80).unwrap(),
            crate::install::state::Volume::filesystem("home", "/home", 80).unwrap(),
        ];
        let names: Vec<String> = f.state.volumes.iter().map(|v| v.name.clone()).collect();
        for name in names {
            f.state
                .set_volume_group_for_volume(&name, DEFAULT_STORAGE_POOL_NAME);
        }
        assert!(f.state.used_gib() > f.state.total_disk_gib());
        f.scale_to_fit();
        assert_eq!(f.state.used_gib(), f.state.total_disk_gib());
        assert!(f.state.volumes.iter().all(|volume| volume.size_gib >= 1));
    }

    #[test]
    fn network_and_bin_toggles_apply() {
        let mut f = flow();
        f.cursor = 0;
        walk_to(&mut f, Step::NetworkCleanup);
        f.cursor = 1; // no
        f.advance();
        assert!(!f.state.network_route_cleanup);
        assert_eq!(f.current(), Step::BinEnsure);
        f.cursor = 1; // run
        f.advance();
        assert!(!f.state.skip_bin_ensure);
    }
}
