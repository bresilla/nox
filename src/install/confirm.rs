use crate::install::state::{InstallScope, InstallState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestructiveConfirmation {
    pub phrase: String,
    pub target: String,
    pub hostname: String,
    pub disks: Vec<String>,
}

impl DestructiveConfirmation {
    pub fn from_state(state: &InstallState) -> Self {
        let target = match state.scope {
            InstallScope::Remote => state.remote.clone(),
            InstallScope::Local => format!("local:{}", state.mountpoint),
        };
        let disks = state
            .disks
            .iter()
            .map(|disk| disk.path.clone())
            .collect::<Vec<_>>();
        let disk_text = disks.join(" ");
        let overwrite_text = if state.overwrite_existing_storage {
            let vgs = crate::install::disko::lvm_vg_names(state).unwrap_or_else(|_| Vec::new());
            if vgs.is_empty() {
                " OVERWRITE STORAGE".to_string()
            } else {
                format!(" OVERWRITE STORAGE {}", vgs.join(" "))
            }
        } else {
            String::new()
        };
        Self {
            phrase: format!(
                "WIPE {} ON {} DISKS {}{}",
                state.hostname, target, disk_text, overwrite_text
            ),
            target,
            hostname: state.hostname.clone(),
            disks,
        }
    }

    #[allow(dead_code)]
    pub fn matches(&self, input: &str) -> bool {
        input.trim() == self.phrase
    }

    #[allow(dead_code)]
    pub fn disk_summary(&self) -> String {
        self.disks.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::DestructiveConfirmation;
    use crate::install::state::{DiskChoice, InstallScope, InstallState};

    #[test]
    fn builds_remote_wipe_phrase() {
        let mut state = InstallState::sample();
        state.hostname = "novo".to_string();
        state.remote = "nixos@10.10.10.7".to_string();
        state.disks = vec![DiskChoice {
            path: "/dev/nvme0n1".to_string(),
            size_gib: 465,
            model: None,
        }];

        let confirmation = DestructiveConfirmation::from_state(&state);

        assert_eq!(
            confirmation.phrase,
            "WIPE novo ON nixos@10.10.10.7 DISKS /dev/nvme0n1"
        );
        assert!(confirmation.matches("WIPE novo ON nixos@10.10.10.7 DISKS /dev/nvme0n1"));
        assert!(confirmation.matches(" WIPE novo ON nixos@10.10.10.7 DISKS /dev/nvme0n1 "));
        assert!(!confirmation.matches("WIPE wrong ON nixos@10.10.10.7 DISKS /dev/nvme0n1"));
    }

    #[test]
    fn builds_local_wipe_phrase() {
        let mut state = InstallState::sample();
        state.scope = InstallScope::Local;
        state.mountpoint = "/mnt".to_string();

        let confirmation = DestructiveConfirmation::from_state(&state);

        assert!(confirmation
            .phrase
            .starts_with("WIPE novo ON local:/mnt DISKS "));
    }

    #[test]
    fn summarizes_multiple_disks() {
        let mut state = InstallState::sample();
        state.disks.push(DiskChoice {
            path: "/dev/sda".to_string(),
            size_gib: 118,
            model: None,
        });

        let confirmation = DestructiveConfirmation::from_state(&state);

        assert_eq!(confirmation.disk_summary(), "/dev/nvme0n1, /dev/sda");
        assert!(confirmation.phrase.ends_with("/dev/nvme0n1 /dev/sda"));
    }

    #[test]
    fn overwrite_mode_is_part_of_wipe_phrase() {
        let mut state = InstallState::sample();
        state.overwrite_existing_storage = true;

        let confirmation = DestructiveConfirmation::from_state(&state);

        assert!(confirmation
            .phrase
            .ends_with("/dev/nvme0n1 OVERWRITE STORAGE pool"));
        assert!(confirmation
            .matches("WIPE novo ON nixos@10.10.10.7 DISKS /dev/nvme0n1 OVERWRITE STORAGE pool"));
    }
}
