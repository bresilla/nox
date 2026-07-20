//! Storage-layout helpers for install planning.
//!
//! nox no longer renders disko.nix — the config repo translates the emitted
//! LIS document to disko devices at Nix evaluation time (host/lis/). What
//! remains here is the layout-derived data the install plan itself needs.

use crate::install::state::InstallState;
use crate::install::storage::StorageLayout;
use crate::Result;

/// Volume-group names the destructive overwrite step must dismantle before
/// disko re-creates them.
pub fn lvm_vg_names(state: &InstallState) -> Result<Vec<String>> {
    let layout = StorageLayout::from_state(state)?;
    Ok(layout.lvm_vg_names())
}

#[cfg(test)]
mod tests {
    use super::lvm_vg_names;
    use crate::install::state::InstallState;

    #[test]
    fn exposes_lvm_vg_names_for_destructive_cleanup() {
        let names = lvm_vg_names(&InstallState::sample()).unwrap();
        assert_eq!(names, vec!["pool".to_string()]);
    }

    #[test]
    fn over_capacity_layout_is_rejected() {
        let mut state = InstallState::sample();
        state.disks[0].size_gib = 100;
        state.discovered_disks[0].size_gib = 100;
        let err = lvm_vg_names(&state).unwrap_err();
        assert!(err.contains("pool pool uses"));
    }
}
