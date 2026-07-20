use std::fs;
use std::path::Path;

use crate::install::state::{InstallState, Volume, VolumeFs};
use crate::install::storage::{
    StorageDisk, StorageDiskRole, StorageLayout, StorageVolumeGroup,
};
use crate::Result;

/// Read-only view of the layout-level rendering options shared by every disk.
/// The filesystem is now decided per-volume, so the only shared knob left is
/// whether physical volumes are wrapped in LUKS.
struct RenderOptions {
    encrypt: bool,
}

pub fn render(state: &InstallState) -> Result<String> {
    let layout = StorageLayout::from_state(state)?;
    render_layout(&layout)
}

pub fn render_layout(layout: &StorageLayout) -> Result<String> {
    layout.validate()?;

    let options = RenderOptions {
        encrypt: layout.encrypt,
    };

    let mut out = String::new();
    out.push_str("{ lib, ... }:\n\n");
    out.push_str("{\n");
    out.push_str("  disko.devices = lib.mkForce {\n");
    out.push_str("    disk = {\n");
    for disk in &layout.disks {
        if matches!(
            disk.role,
            StorageDiskRole::System | StorageDiskRole::PoolMember
        ) {
            render_disk(&mut out, disk, &options)?;
        }
    }
    // Extra data disks: whole-disk single partition, formatted + mounted.
    for (index, (path, mount)) in layout.data_mounts.iter().enumerate() {
        render_data_disk(&mut out, index, path, mount);
    }
    out.push_str("    };\n");
    out.push_str("    lvm_vg = {\n");
    for volume_group in &layout.volume_groups {
        render_volume_group(&mut out, volume_group, &options)?;
    }
    out.push_str("    };\n");
    out.push_str("  };\n");
    out.push_str("}\n");
    Ok(out)
}

pub fn lvm_vg_names(state: &InstallState) -> Result<Vec<String>> {
    let layout = StorageLayout::from_state(state)?;
    Ok(layout.lvm_vg_names())
}

pub fn write(repo: &Path, state: &InstallState) -> Result<()> {
    let file = repo.join("host/generated/disko.nix");
    let content = render(state)?;
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    fs::write(&file, content).map_err(|err| format!("failed to write {}: {err}", file.display()))
}

fn render_disk(out: &mut String, disk: &StorageDisk, options: &RenderOptions) -> Result<()> {
    crate::install::storage::validate_attr(&disk.key)?;
    crate::install::storage::validate_disk_path(&disk.path)?;
    for slice in &disk.slices {
        crate::install::storage::validate_attr(&slice.pool)?;
    }

    out.push_str(&format!("      {} = {{\n", disk.key));
    out.push_str("        type = \"disk\";\n");
    out.push_str(&format!("        device = \"{}\";\n", disk.path));
    out.push_str("        content = {\n");
    out.push_str("          type = \"gpt\";\n");
    out.push_str("          partitions = {\n");
    if disk.create_esp {
        out.push_str("            ESP = {\n");
        out.push_str("              priority = 1;\n");
        out.push_str("              name = \"ESP\";\n");
        out.push_str("              start = \"1MiB\";\n");
        out.push_str(&format!("              end = \"{}MiB\";\n", disk.esp_size_mib));
        out.push_str("              type = \"EF00\";\n");
        out.push_str("              content = {\n");
        out.push_str("                type = \"filesystem\";\n");
        out.push_str("                format = \"vfat\";\n");
        out.push_str("                mountpoint = \"/boot/efi\";\n");
        out.push_str("                mountOptions = [ \"umask=0077\" ];\n");
        out.push_str("              };\n");
        out.push_str("            };\n");
    }
    // One physical-volume partition per slice, each feeding its pool (VG). The
    // last slice absorbs the remainder ("100%"); earlier ones are fixed-size.
    let last = disk.slices.len().saturating_sub(1);
    for (i, slice) in disk.slices.iter().enumerate() {
        let part = format!("pv_{}", slice.pool);
        let size = if i == last {
            "100%".to_string()
        } else {
            format!("{}G", slice.size_gib)
        };
        out.push_str(&format!("            {part} = {{\n"));
        out.push_str(&format!("              size = \"{size}\";\n"));
        if options.encrypt {
            // Wrap the physical volume in LUKS (luks -> lvm_pv nesting).
            out.push_str("              content = {\n");
            out.push_str("                type = \"luks\";\n");
            out.push_str(&format!(
                "                name = \"luks_{}_{}\";\n",
                disk.key, slice.pool
            ));
            out.push_str("                settings.allowDiscards = true;\n");
            out.push_str("                content = {\n");
            out.push_str("                  type = \"lvm_pv\";\n");
            out.push_str(&format!("                  vg = \"{}\";\n", slice.pool));
            out.push_str("                };\n");
            out.push_str("              };\n");
        } else {
            out.push_str("              content = {\n");
            out.push_str("                type = \"lvm_pv\";\n");
            out.push_str(&format!("                vg = \"{}\";\n", slice.pool));
            out.push_str("              };\n");
        }
        out.push_str("            };\n");
    }
    out.push_str("          };\n");
    out.push_str("        };\n");
    out.push_str("      };\n");
    Ok(())
}

/// A non-install data disk: whole disk, single partition, formatted ext4 and
/// mounted at `mount`.
fn render_data_disk(out: &mut String, index: usize, path: &str, mount: &str) {
    let format = "ext4";
    out.push_str(&format!("      data{index} = {{\n"));
    out.push_str("        type = \"disk\";\n");
    out.push_str(&format!("        device = \"{path}\";\n"));
    out.push_str("        content = {\n");
    out.push_str("          type = \"gpt\";\n");
    out.push_str("          partitions = {\n");
    out.push_str("            data = {\n");
    out.push_str("              size = \"100%\";\n");
    out.push_str("              content = {\n");
    out.push_str("                type = \"filesystem\";\n");
    out.push_str(&format!("                format = \"{format}\";\n"));
    out.push_str(&format!("                mountpoint = \"{mount}\";\n"));
    out.push_str("              };\n");
    out.push_str("            };\n");
    out.push_str("          };\n");
    out.push_str("        };\n");
    out.push_str("      };\n");
}

fn render_volume_group(
    out: &mut String,
    volume_group: &StorageVolumeGroup,
    _options: &RenderOptions,
) -> Result<()> {
    crate::install::storage::validate_attr(&volume_group.name)?;

    // The fill volume's concrete size: pool capacity minus every fixed size,
    // with 1G headroom for LVM metadata/extent rounding. Computed at render
    // time so user-typed sizes are never touched.
    let fixed: u64 = volume_group
        .logical_volumes
        .iter()
        .filter(|v| !v.fill)
        .map(|v| v.size_gib)
        .sum();
    let fill_gib = volume_group
        .capacity_gib
        .saturating_sub(fixed)
        .saturating_sub(1)
        .max(1);

    out.push_str(&format!("      {} = {{\n", volume_group.name));
    out.push_str("        type = \"lvm_vg\";\n");
    out.push_str("        lvs = {\n");
    for volume in &volume_group.logical_volumes {
        render_volume(out, volume, fill_gib)?;
    }
    out.push_str("        };\n");
    out.push_str("      };\n");
    Ok(())
}

/// Render one logical volume, dispatching on its own per-volume filesystem.
fn render_volume(out: &mut String, volume: &Volume, fill_gib: u64) -> Result<()> {
    crate::install::storage::validate_attr(&volume.name)?;
    let size = if volume.fill { fill_gib } else { volume.size_gib };
    out.push_str(&format!("          {} = {{\n", volume.name));
    out.push_str(&format!("            size = \"{size}G\";\n"));
    match volume.fs {
        VolumeFs::Swap => render_swap_volume(out, volume),
        VolumeFs::Ext4 => render_simple_fs_volume(out, "ext4", volume.mountpoint.label()),
        VolumeFs::Xfs => render_simple_fs_volume(out, "xfs", volume.mountpoint.label()),
        VolumeFs::Btrfs => render_btrfs_volume(out, volume),
    }
    out.push_str("          };\n");
    Ok(())
}

fn render_swap_volume(out: &mut String, volume: &Volume) {
    out.push_str("            content = {\n");
    out.push_str("              type = \"swap\";\n");
    out.push_str(&format!(
        "              extraArgs = [ \"-L\" \"{}\" ];\n",
        volume.name
    ));
    out.push_str("              resumeDevice = true;\n");
    out.push_str("            };\n");
}

fn render_simple_fs_volume(out: &mut String, format: &str, mount: &str) {
    out.push_str("            content = {\n");
    out.push_str("              type = \"filesystem\";\n");
    out.push_str(&format!("              format = \"{format}\";\n"));
    out.push_str(&format!("              mountpoint = \"{mount}\";\n"));
    out.push_str("            };\n");
}

/// A btrfs volume always carries a root `@<name>` subvolume mounted at the
/// volume's mountpoint, plus any extra user-defined subvolumes.
fn render_btrfs_volume(out: &mut String, volume: &Volume) {
    out.push_str("            content = {\n");
    out.push_str("              type = \"btrfs\";\n");
    out.push_str(&format!(
        "              extraArgs = [ \"-f\" \"-L\" \"{}\" ];\n",
        volume.name
    ));
    out.push_str("              subvolumes = {\n");
    // Always-present root subvolume.
    out.push_str(&format!("                \"/@{}\" = {{\n", volume.name));
    out.push_str(&format!(
        "                  mountpoint = \"{}\";\n",
        volume.mountpoint.label()
    ));
    push_btrfs_mount_options(out, "                  ");
    out.push_str("                };\n");
    // User-defined subvolumes.
    for subvol in &volume.subvolumes {
        out.push_str(&format!("                \"/@{}\" = {{\n", subvol.name));
        out.push_str(&format!(
            "                  mountpoint = \"{}\";\n",
            subvol.mountpoint
        ));
        push_btrfs_mount_options(out, "                  ");
        out.push_str("                };\n");
    }
    out.push_str("              };\n");
    out.push_str("            };\n");
}

fn push_btrfs_mount_options(out: &mut String, indent: &str) {
    out.push_str(&format!("{indent}mountOptions = [\n"));
    out.push_str(&format!("{indent}  \"noatime\"\n"));
    out.push_str(&format!("{indent}  \"compress=zstd:3\"\n"));
    out.push_str(&format!("{indent}  \"ssd\"\n"));
    out.push_str(&format!("{indent}  \"space_cache=v2\"\n"));
    out.push_str(&format!("{indent}];\n"));
}

#[cfg(test)]
mod tests {
    use super::{lvm_vg_names, render};
    use crate::install::state::{DiskChoice, InstallState};

    #[test]
    fn renders_root_mountpoint_without_rejecting_slash() {
        let output = render(&InstallState::sample()).unwrap();
        assert!(output.contains("mountpoint = \"/\";"));
    }

    #[test]
    fn renders_lvm_pool_and_swap() {
        let output = render(&InstallState::sample()).unwrap();
        assert!(output.contains("lvm_vg = {"));
        assert!(output.contains("pool = {"));
        assert!(output.contains("type = \"swap\";"));
    }

    #[test]
    fn exposes_lvm_vg_names_for_destructive_cleanup() {
        let names = lvm_vg_names(&InstallState::sample()).unwrap();

        assert_eq!(names, vec!["pool".to_string()]);
    }

    #[test]
    fn rejects_over_capacity_layout() {
        let mut state = InstallState::sample();
        state.disks[0].size_gib = 100;
        state.discovered_disks[0].size_gib = 100;
        let err = render(&state).unwrap_err();
        assert!(err.contains("pool pool uses"));
    }

    #[test]
    fn renders_per_volume_ext4_alongside_btrfs() {
        // The sample fixture has a btrfs root and an ext4 "pkg" volume: each
        // volume renders its own filesystem, not a global one.
        let output = render(&InstallState::sample()).unwrap();

        assert!(output.contains("format = \"ext4\";"));
        assert!(output.contains("mountpoint = \"/pkg\";"));
        assert!(output.contains("type = \"btrfs\";"));
        assert!(output.contains("type = \"swap\";"));
    }

    #[test]
    fn renders_luks_wrapped_pv_when_encryption_enabled() {
        let mut state = InstallState::sample();
        state.encrypt = true;

        let output = render(&state).unwrap();

        assert!(output.contains("type = \"luks\";"));
        assert!(output.contains("name = \"luks_nvme0n1_pool\";"));
        assert!(output.contains("settings.allowDiscards = true;"));
        // luks must nest the lvm_pv, not replace it
        let luks_at = output.find("type = \"luks\";").unwrap();
        let pv_at = output.find("type = \"lvm_pv\";").unwrap();
        assert!(luks_at < pv_at);
    }

    #[test]
    fn renders_btrfs_volume_with_multiple_subvolumes() {
        let output = render(&InstallState::sample()).unwrap();

        // The always-present root subvolume of the docs volume, plus each
        // user-defined subvolume, render as "/@<name>" with their mountpoints.
        assert!(output.contains("\"/@docs\" = {"));
        assert!(output.contains("\"/@code\" = {"));
        assert!(output.contains("mountpoint = \"/doc/code\";"));
        assert!(output.contains("mountpoint = \"/doc/data\";"));
        assert!(output.contains("mountpoint = \"/doc/self\";"));
        assert!(output.contains("mountpoint = \"/doc/work\";"));
    }

    #[test]
    fn renders_multiple_selected_disks_as_joined_lvm_pool() {
        let mut state = InstallState::sample();
        let second_disk = DiskChoice {
            path: "/dev/nvme1n1".to_string(),
            size_gib: 465,
            model: None,
        };
        state.discovered_disks.push(second_disk.clone());
        state.disks.push(second_disk.clone());
        state.disk_roles.insert(
            second_disk.path.clone(),
            crate::install::state::DiskRole::PoolMember,
        );
        state.normalize_disk_roles();

        let output = render(&state).unwrap();

        assert!(output.contains("nvme0n1 = {"));
        assert!(output.contains("device = \"/dev/nvme0n1\";"));
        assert!(output.contains("ESP = {"));
        assert!(output.contains("nvme1n1 = {"));
        assert!(output.contains("device = \"/dev/nvme1n1\";"));
        assert_eq!(output.matches("vg = \"pool\";").count(), 2);
    }
}

