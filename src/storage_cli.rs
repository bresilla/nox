use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::Result;

pub fn plan(repo: &Path) -> Result<u8> {
    let plan = load_plan(repo)?;
    print!("{}", format_plan(&plan)?);
    Ok(0)
}

pub fn apply(repo: &Path, dry_run: bool) -> Result<u8> {
    if !dry_run {
        return Err(
            "storage apply currently requires --dry-run; execution is TUI-gated later".to_string(),
        );
    }

    let plan = load_plan(repo)?;
    print!("{}", format_apply_dry_run(&plan)?);
    Ok(0)
}

fn load_plan(repo: &Path) -> Result<Value> {
    let file = repo.join("host/generated/storage-plan.json");
    let raw = fs::read_to_string(&file).map_err(|err| {
        format!(
            "failed to read {}: {err}; generate the installer storage plan first",
            file.display()
        )
    })?;
    serde_json::from_str::<Value>(&raw)
        .map_err(|err| format!("failed to parse {}: {err}", file.display()))
}

pub fn format_plan(plan: &Value) -> Result<String> {
    let mut lines = Vec::new();

    lines.push("storage plan".to_string());
    lines.push(format!(
        "  target: {}{}",
        string_at(plan, &["target", "scope"]).unwrap_or("unknown"),
        optional_remote_suffix(plan)
    ));
    lines.push(format!(
        "  host: {}",
        string_at(plan, &["target", "hostname"]).unwrap_or("unknown")
    ));
    lines.push(format!(
        "  user: {}",
        string_at(plan, &["target", "install_user"]).unwrap_or("unknown")
    ));
    lines.push(format!(
        "  mode: {}",
        string_at(plan, &["storage_mode"]).unwrap_or("unknown")
    ));
    lines.push(format!(
        "  overwrite existing storage: {}",
        yes_no(bool_at(plan, &["overwrite_existing_storage"]).unwrap_or(false))
    ));

    lines.push(String::new());
    lines.push("volume groups".to_string());
    let volume_groups = array_at(plan, &["volume_groups"])?;
    if volume_groups.is_empty() {
        lines.push("  none".to_string());
    } else {
        for group in volume_groups {
            lines.push(format!(
                "  {}  used={}G total={}G free={}G",
                string_at(group, &["name"]).unwrap_or("unknown"),
                number_at(group, &["used_gib"]).unwrap_or(0),
                number_at(group, &["total_gib"]).unwrap_or(0),
                number_at(group, &["free_gib"]).unwrap_or(0),
            ));
            lines.push(format!(
                "    disks: {}",
                string_array_at(group, &["disk_paths"])?.join(", ")
            ));
            lines.push(format!(
                "    lvs: {}",
                string_array_at(group, &["logical_volumes"])?.join(", ")
            ));
        }
    }

    lines.push(String::new());
    lines.push("disks".to_string());
    let disks = array_at(plan, &["disks"])?;
    if disks.is_empty() {
        lines.push("  none".to_string());
    } else {
        for disk in disks {
            let mut detail = format!(
                "  {}  {}G  role={}",
                string_at(disk, &["path"]).unwrap_or("unknown"),
                number_at(disk, &["size_gib"]).unwrap_or(0),
                string_at(disk, &["role"]).unwrap_or("unknown"),
            );
            if let Some(group) = string_at(disk, &["volume_group"]) {
                detail.push_str(&format!(" vg={group}"));
            }
            if bool_at(disk, &["create_esp"]).unwrap_or(false) {
                detail.push_str(" esp=yes");
            }
            if let Some(model) = string_at(disk, &["model"]) {
                detail.push_str(&format!(" model={model}"));
            }
            lines.push(detail);
        }
    }

    lines.push(String::new());
    lines.push("logical volumes".to_string());
    let logical_volumes = array_at(plan, &["logical_volumes"])?;
    if logical_volumes.is_empty() {
        lines.push("  none".to_string());
    } else {
        for volume in logical_volumes {
            lines.push(format!(
                "  {}  {}G  mount={}  vg={}",
                string_at(volume, &["name"]).unwrap_or("unknown"),
                number_at(volume, &["size_gib"]).unwrap_or(0),
                string_at(volume, &["mountpoint"]).unwrap_or("unknown"),
                string_at(volume, &["volume_group"]).unwrap_or("unknown"),
            ));
        }
    }

    lines.push(String::new());
    lines.push("actions".to_string());
    let actions = array_at(plan, &["actions"])?;
    if actions.is_empty() {
        lines.push("  none".to_string());
    } else {
        for action in actions {
            let marker = if bool_at(action, &["destructive"]).unwrap_or(false) {
                "!"
            } else {
                "-"
            };
            lines.push(format!(
                "  {marker} {}",
                string_at(action, &["label"]).unwrap_or("unknown action")
            ));
        }
    }

    lines.push(String::new());
    Ok(lines.join("\n"))
}

pub fn format_apply_dry_run(plan: &Value) -> Result<String> {
    let mut lines = Vec::new();

    lines.push("storage apply: dry-run".to_string());
    lines.push(format!(
        "  target: {}{}",
        string_at(plan, &["target", "scope"]).unwrap_or("unknown"),
        optional_remote_suffix(plan)
    ));
    lines.push(format!(
        "  host: {}",
        string_at(plan, &["target", "hostname"]).unwrap_or("unknown")
    ));
    lines.push(format!(
        "  mode: {}",
        string_at(plan, &["storage_mode"]).unwrap_or("unknown")
    ));
    lines.push("  execution: disabled".to_string());

    lines.push(String::new());
    lines.push("actions".to_string());
    let actions = array_at(plan, &["actions"])?;
    if actions.is_empty() {
        lines.push("  none".to_string());
    } else {
        for action in actions {
            let label = string_at(action, &["label"]).unwrap_or("unknown action");
            if bool_at(action, &["destructive"]).unwrap_or(false) {
                lines.push(format!("  refused destructive: {label}"));
            } else {
                lines.push(format!("  would run: {label}"));
            }
        }
    }

    lines.push(String::new());
    Ok(lines.join("\n"))
}

fn optional_remote_suffix(plan: &Value) -> String {
    string_at(plan, &["target", "remote"])
        .map(|remote| format!(" ({remote})"))
        .unwrap_or_default()
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn array_at<'a>(value: &'a Value, path: &[&str]) -> Result<&'a Vec<Value>> {
    value_at(value, path)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            format!(
                "storage plan field `{}` is missing or not an array",
                path.join(".")
            )
        })
}

fn string_array_at(value: &Value, path: &[&str]) -> Result<Vec<String>> {
    Ok(array_at(value, path)?
        .iter()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect())
}

fn string_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    value_at(value, path).and_then(Value::as_str)
}

fn bool_at(value: &Value, path: &[&str]) -> Option<bool> {
    value_at(value, path).and_then(Value::as_bool)
}

fn number_at(value: &Value, path: &[&str]) -> Option<u64> {
    value_at(value, path).and_then(Value::as_u64)
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::{apply, format_apply_dry_run, format_plan};
    use serde_json::json;
    use std::fs;

    #[test]
    fn formats_generated_storage_plan_for_terminal() {
        let plan = json!({
            "target": {
                "scope": "remote",
                "remote": "nixos@10.10.10.7",
                "hostname": "novo",
                "install_user": "bresilla"
            },
            "storage_mode": "joined-lvm",
            "overwrite_existing_storage": true,
            "volume_groups": [{
                "name": "pool",
                "disk_paths": ["/dev/nvme0n1"],
                "logical_volumes": ["root", "home"],
                "total_gib": 464,
                "used_gib": 64,
                "free_gib": 400
            }],
            "disks": [{
                "path": "/dev/nvme0n1",
                "size_gib": 464,
                "model": "Samsung",
                "role": "system",
                "volume_group": "pool",
                "create_esp": true
            }],
            "logical_volumes": [{
                "name": "root",
                "mountpoint": "/",
                "size_gib": 32,
                "volume_group": "pool"
            }],
            "actions": [{
                "label": "wipe disk /dev/nvme0n1",
                "destructive": true
            }]
        });

        let formatted = format_plan(&plan).unwrap();

        assert!(formatted.contains("target: remote (nixos@10.10.10.7)"));
        assert!(formatted.contains("pool  used=64G total=464G free=400G"));
        assert!(formatted.contains("/dev/nvme0n1  464G  role=system vg=pool esp=yes model=Samsung"));
        assert!(formatted.contains("! wipe disk /dev/nvme0n1"));
    }

    #[test]
    fn rejects_missing_array_sections() {
        let plan = json!({
            "target": {},
            "storage_mode": "joined-lvm",
            "overwrite_existing_storage": false
        });

        let err = format_plan(&plan).unwrap_err();

        assert!(err.contains("volume_groups"));
    }

    #[test]
    fn formats_storage_apply_as_refused_dry_run() {
        let plan = json!({
            "target": {
                "scope": "remote",
                "remote": "nixos@10.10.10.7",
                "hostname": "novo"
            },
            "storage_mode": "joined-lvm",
            "actions": [
                {"label": "wipe disk /dev/nvme0n1", "destructive": true},
                {"label": "ignore /dev/sdb", "destructive": false}
            ]
        });

        let formatted = format_apply_dry_run(&plan).unwrap();

        assert!(formatted.contains("storage apply: dry-run"));
        assert!(formatted.contains("execution: disabled"));
        assert!(formatted.contains("refused destructive: wipe disk /dev/nvme0n1"));
        assert!(formatted.contains("would run: ignore /dev/sdb"));
    }

    #[test]
    fn storage_apply_without_dry_run_is_refused_before_loading_plan() {
        let repo =
            std::env::temp_dir().join(format!("nx-storage-apply-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&repo);
        fs::create_dir_all(&repo).unwrap();

        let err = apply(&repo, false).unwrap_err();

        assert!(err.contains("requires --dry-run"));
        let _ = fs::remove_dir_all(&repo);
    }
}
