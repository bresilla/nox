//! Target introspection: one structured report describing everything the
//! installer (and later the TUI) needs to know about a machine — hardware,
//! firmware, disks with their current contents, LVM state, mounts, tools.
//!
//! `collect()` always runs on the machine being described: the agent handles
//! `AgentRequest::Facts` by calling it, and a local install calls it directly.
//! Every field is best-effort — a missing tool or unreadable file degrades to
//! `None`/empty instead of failing, so facts collection never blocks an install.

use std::fs;
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetFacts {
    pub hostname: Option<String>,
    pub kernel: Option<String>,
    pub os_name: Option<String>,
    pub nixos_version: Option<String>,
    pub arch: Option<String>,
    pub virtualization: Option<String>,
    pub efi: bool,
    pub mem_mib: Option<u64>,
    pub cpu_count: Option<u32>,
    pub cpu_model: Option<String>,
    /// Booted from an installer ISO (live system, safe to wipe disks).
    pub live_iso: bool,
    /// Something is mounted at /mnt (a previous install attempt or manual mount).
    pub mnt_mounted: bool,
    pub disks: Vec<DiskFacts>,
    pub volume_groups: Vec<VgFacts>,
    pub logical_volumes: Vec<LvFacts>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskFacts {
    pub path: String,
    pub size_bytes: u64,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub transport: Option<String>,
    pub rotational: Option<bool>,
    pub partitions: Vec<PartitionFacts>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionFacts {
    pub path: String,
    pub size_bytes: u64,
    pub fstype: Option<String>,
    pub label: Option<String>,
    pub mountpoints: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VgFacts {
    pub name: String,
    pub size_bytes: u64,
    pub free_bytes: u64,
    pub pv_count: u32,
    pub lv_count: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LvFacts {
    pub name: String,
    pub vg_name: String,
    pub size_bytes: u64,
    pub active: bool,
}

impl TargetFacts {
    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!(
            "host: {}  os: {}  kernel: {}",
            self.hostname.as_deref().unwrap_or("?"),
            self.nixos_version
                .as_deref()
                .or(self.os_name.as_deref())
                .unwrap_or("?"),
            self.kernel.as_deref().unwrap_or("?"),
        ));
        lines.push(format!(
            "arch: {}  firmware: {}  virt: {}  live-iso: {}  /mnt mounted: {}",
            self.arch.as_deref().unwrap_or("?"),
            if self.efi { "UEFI" } else { "BIOS" },
            self.virtualization.as_deref().unwrap_or("none"),
            yes_no(self.live_iso),
            yes_no(self.mnt_mounted),
        ));
        lines.push(format!(
            "cpu: {} x {}  memory: {} MiB",
            self.cpu_count.unwrap_or(0),
            self.cpu_model.as_deref().unwrap_or("?"),
            self.mem_mib.unwrap_or(0),
        ));
        for disk in &self.disks {
            let mut line = format!(
                "disk {}  {}  {}",
                disk.path,
                format_bytes(disk.size_bytes),
                disk.model.as_deref().unwrap_or(""),
            );
            if let Some(transport) = &disk.transport {
                line.push_str(&format!("  [{transport}]"));
            }
            lines.push(line.trim_end().to_string());
            for part in &disk.partitions {
                lines.push(format!(
                    "  {}  {}  {}{}{}",
                    part.path,
                    format_bytes(part.size_bytes),
                    part.fstype.as_deref().unwrap_or("-"),
                    part.label
                        .as_deref()
                        .map(|label| format!("  label={label}"))
                        .unwrap_or_default(),
                    if part.mountpoints.is_empty() {
                        String::new()
                    } else {
                        format!("  mounted: {}", part.mountpoints.join(", "))
                    },
                ));
            }
        }
        for vg in &self.volume_groups {
            lines.push(format!(
                "vg {}  {} total, {} free, {} PVs, {} LVs",
                vg.name,
                format_bytes(vg.size_bytes),
                format_bytes(vg.free_bytes),
                vg.pv_count,
                vg.lv_count,
            ));
        }
        for lv in &self.logical_volumes {
            lines.push(format!(
                "lv {}/{}  {}  {}",
                lv.vg_name,
                lv.name,
                format_bytes(lv.size_bytes),
                if lv.active { "active" } else { "inactive" },
            ));
        }
        lines
    }
}

impl DiskFacts {
    /// Short description of what currently lives on this disk, so the disk
    /// picker can show "what am I about to wipe" without extra lookups.
    pub fn content_summary(&self) -> String {
        if self.partitions.is_empty() {
            return "empty".to_string();
        }
        self.partitions
            .iter()
            .map(|part| {
                let mut piece = part.fstype.clone().unwrap_or_else(|| "?".to_string());
                if let Some(label) = &part.label {
                    piece.push_str(&format!("({label})"));
                }
                piece
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// True when this disk is the live installer medium (mounted ISO / squashfs
    /// store, or a removable USB stick) — never a valid install/mount target.
    pub fn is_boot_media(&self) -> bool {
        if self.transport.as_deref() == Some("usb") {
            return true;
        }
        self.partitions.iter().any(|part| {
            part.mountpoints.iter().any(|mount| {
                mount == "/iso"
                    || mount.starts_with("/run/media")
                    || mount.contains("iso")
                    || mount == "/nix/.ro-store"
            })
        })
    }
}

/// Convert introspected disks into the wizard's disk choices, preserving the
/// richer facts for display.
pub fn disk_choices(facts: &TargetFacts) -> Vec<crate::install::state::DiskChoice> {
    facts
        .disks
        .iter()
        .map(|disk| crate::install::state::DiskChoice {
            path: disk.path.clone(),
            size_gib: disk.size_bytes.div_ceil(1024 * 1024 * 1024),
            model: disk.model.clone(),
        })
        .collect()
}

const LSBLK_ARGS: &str =
    "--json --bytes --output NAME,PATH,SIZE,TYPE,MODEL,SERIAL,TRAN,ROTA,FSTYPE,LABEL,MOUNTPOINTS";
const VGS_ARGS: &str =
    "--reportformat json --units b --nosuffix -o vg_name,vg_size,vg_free,pv_count,lv_count";
const LVS_ARGS: &str = "--reportformat json --units b --nosuffix -o lv_name,vg_name,lv_size,lv_active";

/// Raw text sections gathered from the target, before parsing. Native local
/// collection and the one-shot SSH probe both produce this shape, so assembly
/// happens in exactly one place.
#[derive(Debug, Clone, Default)]
struct RawFacts {
    hostname: Option<String>,
    kernel: Option<String>,
    arch: Option<String>,
    os_release: Option<String>,
    nixos_version: Option<String>,
    virtualization: Option<String>,
    efi: bool,
    live_iso: bool,
    mnt_mounted: bool,
    meminfo: Option<String>,
    cpuinfo: Option<String>,
    lsblk: Option<String>,
    vgs: Option<String>,
    lvs: Option<String>,
}

fn assemble(raw: RawFacts) -> TargetFacts {
    let mut facts = TargetFacts {
        hostname: raw.hostname,
        kernel: raw.kernel,
        arch: raw.arch,
        nixos_version: raw.nixos_version,
        virtualization: raw.virtualization.filter(|value| value != "none"),
        efi: raw.efi,
        live_iso: raw.live_iso,
        mnt_mounted: raw.mnt_mounted,
        ..TargetFacts::default()
    };
    if let Some(os_release) = raw.os_release {
        facts.os_name = parse_os_release(&os_release, "PRETTY_NAME");
    }
    if let Some(meminfo) = raw.meminfo {
        facts.mem_mib = parse_mem_total_mib(&meminfo);
    }
    if let Some(cpuinfo) = raw.cpuinfo {
        let (count, model) = parse_cpuinfo(&cpuinfo);
        facts.cpu_count = count;
        facts.cpu_model = model;
    }
    if let Some(json) = raw.lsblk {
        facts.disks = parse_lsblk_facts(&json).unwrap_or_default();
    }
    if let Some(json) = raw.vgs {
        facts.volume_groups = parse_vgs_facts(&json).unwrap_or_default();
    }
    if let Some(json) = raw.lvs {
        facts.logical_volumes = parse_lvs_facts(&json).unwrap_or_default();
    }
    facts
}

/// Gather every fact about the machine this code runs on.
pub fn collect() -> TargetFacts {
    let lsblk_args = LSBLK_ARGS.split_whitespace().collect::<Vec<_>>();
    let mut vgs_args = vec!["--non-interactive", "vgs"];
    vgs_args.extend(VGS_ARGS.split_whitespace());
    let mut lvs_args = vec!["--non-interactive", "lvs"];
    lvs_args.extend(LVS_ARGS.split_whitespace());

    assemble(RawFacts {
        hostname: read_trimmed("/proc/sys/kernel/hostname"),
        kernel: read_trimmed("/proc/sys/kernel/osrelease"),
        arch: command_line("uname", &["-m"]),
        os_release: read_to_string("/etc/os-release"),
        nixos_version: command_line("nixos-version", &[]),
        virtualization: command_line("systemd-detect-virt", &[]),
        efi: Path::new("/sys/firmware/efi").exists(),
        live_iso: Path::new("/iso").exists(),
        mnt_mounted: command_status("findmnt", &["/mnt"]),
        meminfo: read_to_string("/proc/meminfo"),
        cpuinfo: read_to_string("/proc/cpuinfo"),
        lsblk: command_output("lsblk", &lsblk_args),
        vgs: command_output("sudo", &vgs_args),
        lvs: command_output("sudo", &lvs_args),
    })
}

const PROBE_MARKER: &str = "-----NOX-FACTS:";

/// Shell script that emits every fact section in one SSH round trip, delimited
/// by markers. Parsed by [`parse_probe`]. Every command is best-effort.
pub fn probe_script() -> String {
    let section = |key: &str, command: &str| {
        format!("echo '{PROBE_MARKER}{key}-----'; {command} 2>/dev/null || true\n")
    };
    let mut script = String::from("set +e\n");
    script.push_str(&section("hostname", "cat /proc/sys/kernel/hostname"));
    script.push_str(&section("kernel", "cat /proc/sys/kernel/osrelease"));
    script.push_str(&section("arch", "uname -m"));
    script.push_str(&section("os-release", "cat /etc/os-release"));
    script.push_str(&section("nixos-version", "nixos-version"));
    script.push_str(&section("virt", "systemd-detect-virt"));
    script.push_str(&section(
        "efi",
        "test -d /sys/firmware/efi && echo yes || echo no",
    ));
    script.push_str(&section("iso", "test -e /iso && echo yes || echo no"));
    script.push_str(&section(
        "mnt",
        "findmnt /mnt >/dev/null 2>&1 && echo yes || echo no",
    ));
    script.push_str(&section("meminfo", "cat /proc/meminfo"));
    script.push_str(&section("cpuinfo", "cat /proc/cpuinfo"));
    script.push_str(&section("lsblk", &format!("lsblk {LSBLK_ARGS}")));
    script.push_str(&section(
        "vgs",
        &format!("sudo --non-interactive vgs {VGS_ARGS}"),
    ));
    script.push_str(&section(
        "lvs",
        &format!("sudo --non-interactive lvs {LVS_ARGS}"),
    ));
    script
}

/// Parse the output of [`probe_script`] into facts. Pure and fixture-testable.
pub fn parse_probe(output: &str) -> TargetFacts {
    let mut sections: std::collections::BTreeMap<String, String> = Default::default();
    let mut current: Option<String> = None;
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix(PROBE_MARKER) {
            current = Some(rest.trim_end_matches('-').to_string());
            continue;
        }
        if let Some(key) = &current {
            let entry = sections.entry(key.clone()).or_default();
            entry.push_str(line);
            entry.push('\n');
        }
    }

    let get = |key: &str| -> Option<String> {
        sections
            .get(key)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    let get_line =
        |key: &str| -> Option<String> { get(key).and_then(|v| v.lines().next().map(String::from)) };
    let yes = |key: &str| get_line(key).as_deref() == Some("yes");

    assemble(RawFacts {
        hostname: get_line("hostname"),
        kernel: get_line("kernel"),
        arch: get_line("arch"),
        os_release: get("os-release"),
        nixos_version: get_line("nixos-version"),
        virtualization: get_line("virt"),
        efi: yes("efi"),
        live_iso: yes("iso"),
        mnt_mounted: yes("mnt"),
        meminfo: get("meminfo"),
        cpuinfo: get("cpuinfo"),
        lsblk: get("lsblk"),
        vgs: get("vgs"),
        lvs: get("lvs"),
    })
}

/// Collect facts from a remote target over plain SSH in a single round trip —
/// no agent bootstrap required, so this is fast enough for interactive use
/// (the wizard's target/disk steps).
pub fn collect_over_ssh(remote: &str) -> crate::Result<TargetFacts> {
    let output = crate::install::ssh::run_command(remote, &probe_script())?;
    if output.status != 0 && output.stdout.is_empty() {
        return Err(format!(
            "remote facts probe failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(parse_probe(&String::from_utf8_lossy(&output.stdout)))
}

fn read_to_string(path: &str) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn read_trimmed(path: &str) -> Option<String> {
    read_to_string(path).map(|value| value.trim().to_string())
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

fn command_line(program: &str, args: &[&str]) -> Option<String> {
    let out = command_output(program, args)?;
    let line = out.lines().next()?.trim();
    (!line.is_empty()).then(|| line.to_string())
}

fn command_status(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

pub fn parse_os_release(content: &str, key: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let value = line.strip_prefix(&format!("{key}="))?;
        Some(value.trim().trim_matches('"').to_string())
    })
}

pub fn parse_mem_total_mib(meminfo: &str) -> Option<u64> {
    meminfo.lines().find_map(|line| {
        let rest = line.strip_prefix("MemTotal:")?;
        let kib = rest.trim().trim_end_matches(" kB").trim().parse::<u64>().ok()?;
        Some(kib / 1024)
    })
}

pub fn parse_cpuinfo(cpuinfo: &str) -> (Option<u32>, Option<String>) {
    let count = cpuinfo
        .lines()
        .filter(|line| line.starts_with("processor"))
        .count() as u32;
    let model = cpuinfo.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == "model name").then(|| value.trim().to_string())
    });
    ((count > 0).then_some(count), model)
}

pub fn parse_lsblk_facts(json: &str) -> Option<Vec<DiskFacts>> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let devices = value.get("blockdevices")?.as_array()?;
    let mut disks = Vec::new();
    for device in devices {
        if device.get("type").and_then(|v| v.as_str()) != Some("disk") {
            continue;
        }
        let Some(path) = string_field(device, "path") else {
            continue;
        };
        let mut disk = DiskFacts {
            path,
            size_bytes: u64_field(device, "size").unwrap_or(0),
            model: string_field(device, "model"),
            serial: string_field(device, "serial"),
            transport: string_field(device, "tran"),
            rotational: device.get("rota").and_then(|v| v.as_bool()),
            partitions: Vec::new(),
        };
        if let Some(children) = device.get("children").and_then(|v| v.as_array()) {
            for child in children {
                let Some(path) = string_field(child, "path") else {
                    continue;
                };
                disk.partitions.push(PartitionFacts {
                    path,
                    size_bytes: u64_field(child, "size").unwrap_or(0),
                    fstype: string_field(child, "fstype"),
                    label: string_field(child, "label"),
                    mountpoints: child
                        .get("mountpoints")
                        .and_then(|v| v.as_array())
                        .map(|values| {
                            values
                                .iter()
                                .filter_map(|v| v.as_str())
                                .map(ToString::to_string)
                                .collect()
                        })
                        .unwrap_or_default(),
                });
            }
        }
        disks.push(disk);
    }
    Some(disks)
}

pub fn parse_vgs_facts(json: &str) -> Option<Vec<VgFacts>> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let rows = lvm_report_rows(&value, "vg")?;
    Some(
        rows.iter()
            .filter_map(|row| {
                Some(VgFacts {
                    name: string_field(row, "vg_name")?,
                    size_bytes: lvm_number(row, "vg_size").unwrap_or(0),
                    free_bytes: lvm_number(row, "vg_free").unwrap_or(0),
                    pv_count: lvm_number(row, "pv_count").unwrap_or(0) as u32,
                    lv_count: lvm_number(row, "lv_count").unwrap_or(0) as u32,
                })
            })
            .collect(),
    )
}

pub fn parse_lvs_facts(json: &str) -> Option<Vec<LvFacts>> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let rows = lvm_report_rows(&value, "lv")?;
    Some(
        rows.iter()
            .filter_map(|row| {
                Some(LvFacts {
                    name: string_field(row, "lv_name")?,
                    vg_name: string_field(row, "vg_name").unwrap_or_default(),
                    size_bytes: lvm_number(row, "lv_size").unwrap_or(0),
                    active: string_field(row, "lv_active")
                        .map(|value| value == "active")
                        .unwrap_or(false),
                })
            })
            .collect(),
    )
}

fn lvm_report_rows<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a Vec<serde_json::Value>> {
    value
        .get("report")?
        .as_array()?
        .first()?
        .get(key)?
        .as_array()
}

fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    let field = value.get(key)?;
    let text = field.as_str()?.trim();
    (!text.is_empty()).then(|| text.to_string())
}

fn u64_field(value: &serde_json::Value, key: &str) -> Option<u64> {
    let field = value.get(key)?;
    field
        .as_u64()
        .or_else(|| field.as_str().and_then(|text| text.trim().parse().ok()))
}

fn lvm_number(value: &serde_json::Value, key: &str) -> Option<u64> {
    let field = value.get(key)?;
    field.as_u64().or_else(|| {
        field
            .as_str()
            .and_then(|text| text.trim().parse::<f64>().ok())
            .map(|number| number as u64)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Insight {
    pub severity: Severity,
    pub message: String,
}

/// What the installer intends to do, distilled for assessment.
#[derive(Debug, Clone, Default)]
pub struct InstallAssessment {
    pub selected_disks: Vec<String>,
    pub planned_vgs: Vec<String>,
    pub planned_gib: u64,
    pub overwrite: bool,
}

/// Derive human-relevant conclusions from the target facts and the planned
/// install: firmware mismatches, disks that are in use, VG collisions,
/// capacity problems. This is the "understand what's going on" layer the TUI
/// surfaces before anything destructive runs.
pub fn assess(facts: &TargetFacts, plan: &InstallAssessment) -> Vec<Insight> {
    let mut insights = Vec::new();
    let mut push = |severity: Severity, message: String| {
        insights.push(Insight { severity, message });
    };

    if !facts.efi {
        push(
            Severity::Critical,
            "target booted in BIOS mode, but the config installs systemd-boot (UEFI); the bootloader install will fail".to_string(),
        );
    }
    if !facts.live_iso {
        push(
            Severity::Warning,
            "target is not running an installer ISO — this would wipe disks under a live system".to_string(),
        );
    }
    if facts.mnt_mounted {
        push(
            Severity::Info,
            "/mnt is already mounted (previous install attempt?); disk preparation will unmount it".to_string(),
        );
    }
    if let Some(mem_mib) = facts.mem_mib {
        if mem_mib < 2048 {
            push(
                Severity::Warning,
                format!("only {mem_mib} MiB of memory; nixos-install may run out during the build"),
            );
        }
    }

    for disk_path in &plan.selected_disks {
        let Some(disk) = facts.disks.iter().find(|disk| &disk.path == disk_path) else {
            push(
                Severity::Critical,
                format!("selected disk {disk_path} was not found on the target"),
            );
            continue;
        };

        let mounted: Vec<String> = disk
            .partitions
            .iter()
            .flat_map(|part| part.mountpoints.iter())
            .filter(|mount| !mount.starts_with("/mnt"))
            .cloned()
            .collect();
        if !mounted.is_empty() {
            push(
                Severity::Critical,
                format!(
                    "selected disk {disk_path} has partitions mounted outside /mnt ({}) — it is in use by the running system",
                    mounted.join(", ")
                ),
            );
        }

        let disk_gib = disk.size_bytes / (1024 * 1024 * 1024);
        if plan.planned_gib > 0 && plan.selected_disks.len() == 1 && disk_gib < plan.planned_gib {
            push(
                Severity::Critical,
                format!(
                    "planned volumes need {} GiB but {disk_path} only provides {disk_gib} GiB",
                    plan.planned_gib
                ),
            );
        }

        if !disk.partitions.is_empty() {
            push(
                Severity::Info,
                format!(
                    "disk {disk_path} currently holds: {}",
                    disk.content_summary()
                ),
            );
        }
    }

    for vg in &facts.volume_groups {
        if plan.planned_vgs.contains(&vg.name) {
            if plan.overwrite {
                push(
                    Severity::Info,
                    format!(
                        "existing volume group '{}' will be removed (overwrite enabled)",
                        vg.name
                    ),
                );
            } else {
                push(
                    Severity::Critical,
                    format!(
                        "volume group '{}' already exists on the target; enable overwrite or the install will fail",
                        vg.name
                    ),
                );
            }
        }
    }

    insights
}

pub fn format_bytes(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1}G", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{}M", bytes / MIB)
    } else {
        format!("{bytes}B")
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_os_release_pretty_name() {
        let content = "NAME=NixOS\nPRETTY_NAME=\"NixOS 26.05 (Yarara)\"\n";
        assert_eq!(
            parse_os_release(content, "PRETTY_NAME").as_deref(),
            Some("NixOS 26.05 (Yarara)")
        );
        assert_eq!(parse_os_release(content, "MISSING"), None);
    }

    #[test]
    fn parses_mem_total() {
        let meminfo = "MemTotal:       16303492 kB\nMemFree:         1234 kB\n";
        assert_eq!(parse_mem_total_mib(meminfo), Some(15921));
    }

    #[test]
    fn parses_cpuinfo_count_and_model() {
        let cpuinfo = "processor\t: 0\nmodel name\t: AMD Ryzen 7\nprocessor\t: 1\nmodel name\t: AMD Ryzen 7\n";
        let (count, model) = parse_cpuinfo(cpuinfo);
        assert_eq!(count, Some(2));
        assert_eq!(model.as_deref(), Some("AMD Ryzen 7"));
    }

    #[test]
    fn parses_lsblk_disks_with_partitions() {
        let json = r#"{
          "blockdevices": [
            {"name":"loop0","path":"/dev/loop0","size":1000,"type":"loop"},
            {"name":"sda","path":"/dev/sda","size":4000000000000,"type":"disk",
             "model":"QEMU HARDDISK","serial":"QM00001","tran":"sata","rota":true,
             "children":[
               {"name":"sda1","path":"/dev/sda1","size":1072693248,"type":"part",
                "fstype":"vfat","label":null,"mountpoints":[null]},
               {"name":"sda2","path":"/dev/sda2","size":3998000000000,"type":"part",
                "fstype":"LVM2_member","label":null,"mountpoints":["/mnt"]}
             ]}
          ]
        }"#;

        let disks = parse_lsblk_facts(json).unwrap();
        assert_eq!(disks.len(), 1);
        let disk = &disks[0];
        assert_eq!(disk.path, "/dev/sda");
        assert_eq!(disk.model.as_deref(), Some("QEMU HARDDISK"));
        assert_eq!(disk.transport.as_deref(), Some("sata"));
        assert_eq!(disk.rotational, Some(true));
        assert_eq!(disk.partitions.len(), 2);
        assert_eq!(disk.partitions[0].fstype.as_deref(), Some("vfat"));
        assert!(disk.partitions[0].mountpoints.is_empty());
        assert_eq!(disk.partitions[1].mountpoints, vec!["/mnt".to_string()]);
    }

    #[test]
    fn parses_vgs_and_lvs_reports() {
        let vgs = r#"{"report":[{"vg":[
          {"vg_name":"pool","vg_size":"3997999300608","vg_free":"3505999300608","pv_count":"1","lv_count":"6"}
        ]}]}"#;
        let lvs = r#"{"report":[{"lv":[
          {"lv_name":"root","vg_name":"pool","lv_size":"34359738368","lv_active":"active"},
          {"lv_name":"swap","vg_name":"pool","lv_size":"68719476736","lv_active":""}
        ]}]}"#;

        let vg = &parse_vgs_facts(vgs).unwrap()[0];
        assert_eq!(vg.name, "pool");
        assert_eq!(vg.pv_count, 1);
        assert_eq!(vg.lv_count, 6);
        assert_eq!(vg.free_bytes, 3505999300608);

        let lvs = parse_lvs_facts(lvs).unwrap();
        assert_eq!(lvs.len(), 2);
        assert!(lvs[0].active);
        assert!(!lvs[1].active);
        assert_eq!(lvs[1].vg_name, "pool");
    }

    #[test]
    fn probe_output_round_trips_through_parser() {
        let output = "\
-----NOX-FACTS:hostname-----
nixos
-----NOX-FACTS:kernel-----
6.18.37
-----NOX-FACTS:arch-----
x86_64
-----NOX-FACTS:os-release-----
NAME=NixOS
PRETTY_NAME=\"NixOS 26.05 (Yarara)\"
-----NOX-FACTS:nixos-version-----
26.05.20260630 (Yarara)
-----NOX-FACTS:virt-----
kvm
-----NOX-FACTS:efi-----
yes
-----NOX-FACTS:iso-----
yes
-----NOX-FACTS:mnt-----
no
-----NOX-FACTS:meminfo-----
MemTotal:        8123456 kB
-----NOX-FACTS:cpuinfo-----
processor\t: 0
model name\t: QEMU Virtual CPU
-----NOX-FACTS:lsblk-----
{\"blockdevices\":[{\"name\":\"sda\",\"path\":\"/dev/sda\",\"size\":4000000000000,\"type\":\"disk\",\"model\":\"QEMU HARDDISK\"}]}
-----NOX-FACTS:vgs-----
{\"report\":[{\"vg\":[{\"vg_name\":\"pool\",\"vg_size\":\"100\",\"vg_free\":\"50\",\"pv_count\":\"1\",\"lv_count\":\"2\"}]}]}
-----NOX-FACTS:lvs-----
";

        let facts = parse_probe(output);
        assert_eq!(facts.hostname.as_deref(), Some("nixos"));
        assert_eq!(facts.arch.as_deref(), Some("x86_64"));
        assert_eq!(facts.os_name.as_deref(), Some("NixOS 26.05 (Yarara)"));
        assert_eq!(facts.virtualization.as_deref(), Some("kvm"));
        assert!(facts.efi);
        assert!(facts.live_iso);
        assert!(!facts.mnt_mounted);
        assert_eq!(facts.mem_mib, Some(7933));
        assert_eq!(facts.cpu_count, Some(1));
        assert_eq!(facts.disks.len(), 1);
        assert_eq!(facts.disks[0].path, "/dev/sda");
        assert_eq!(facts.volume_groups.len(), 1);
        assert_eq!(facts.volume_groups[0].name, "pool");
        assert!(facts.logical_volumes.is_empty());
    }

    #[test]
    fn probe_parser_tolerates_missing_and_failed_sections() {
        let facts = parse_probe("-----NOX-FACTS:hostname-----\nbox\n");
        assert_eq!(facts.hostname.as_deref(), Some("box"));
        assert!(!facts.efi);
        assert!(facts.disks.is_empty());

        let empty = parse_probe("");
        assert_eq!(empty.hostname, None);
    }

    #[test]
    fn probe_script_covers_every_section() {
        let script = probe_script();
        for key in [
            "hostname", "kernel", "arch", "os-release", "nixos-version", "virt", "efi", "iso",
            "mnt", "meminfo", "cpuinfo", "lsblk", "vgs", "lvs",
        ] {
            assert!(
                script.contains(&format!("-----NOX-FACTS:{key}-----")),
                "probe script is missing section {key}"
            );
        }
    }

    fn assessment_fixture() -> (TargetFacts, InstallAssessment) {
        let facts = TargetFacts {
            efi: true,
            live_iso: true,
            mem_mib: Some(8192),
            disks: vec![DiskFacts {
                path: "/dev/sda".into(),
                size_bytes: 500 * 1024 * 1024 * 1024,
                partitions: vec![PartitionFacts {
                    path: "/dev/sda1".into(),
                    size_bytes: 1024,
                    fstype: Some("ext4".into()),
                    label: None,
                    mountpoints: vec![],
                }],
                ..DiskFacts::default()
            }],
            volume_groups: vec![VgFacts {
                name: "pool".into(),
                ..VgFacts::default()
            }],
            ..TargetFacts::default()
        };
        let plan = InstallAssessment {
            selected_disks: vec!["/dev/sda".into()],
            planned_vgs: vec!["pool".into()],
            planned_gib: 448,
            overwrite: true,
        };
        (facts, plan)
    }

    #[test]
    fn clean_target_yields_only_informational_insights() {
        let (facts, plan) = assessment_fixture();
        let insights = assess(&facts, &plan);
        assert!(insights
            .iter()
            .all(|insight| insight.severity == Severity::Info));
    }

    #[test]
    fn bios_firmware_is_critical() {
        let (mut facts, plan) = assessment_fixture();
        facts.efi = false;
        let insights = assess(&facts, &plan);
        assert!(insights.iter().any(|i| i.severity == Severity::Critical
            && i.message.contains("BIOS mode")));
    }

    #[test]
    fn disk_in_use_by_running_system_is_critical() {
        let (mut facts, plan) = assessment_fixture();
        facts.disks[0].partitions[0].mountpoints = vec!["/home".into()];
        let insights = assess(&facts, &plan);
        assert!(insights.iter().any(|i| i.severity == Severity::Critical
            && i.message.contains("mounted outside /mnt")));

        // Mounts under /mnt (a previous attempt) are fine.
        facts.disks[0].partitions[0].mountpoints = vec!["/mnt/boot/efi".into()];
        let insights = assess(&facts, &plan);
        assert!(!insights.iter().any(|i| i.severity == Severity::Critical));
    }

    #[test]
    fn vg_collision_depends_on_overwrite() {
        let (facts, mut plan) = assessment_fixture();
        plan.overwrite = false;
        let insights = assess(&facts, &plan);
        assert!(insights.iter().any(|i| i.severity == Severity::Critical
            && i.message.contains("already exists")));

        plan.overwrite = true;
        let insights = assess(&facts, &plan);
        assert!(insights
            .iter()
            .any(|i| i.severity == Severity::Info && i.message.contains("will be removed")));
    }

    #[test]
    fn missing_selected_disk_and_capacity_are_critical() {
        let (facts, mut plan) = assessment_fixture();
        plan.selected_disks = vec!["/dev/nvme9n9".into()];
        let insights = assess(&facts, &plan);
        assert!(insights.iter().any(|i| i.severity == Severity::Critical
            && i.message.contains("was not found")));

        let (facts, mut plan) = assessment_fixture();
        plan.planned_gib = 9999;
        let insights = assess(&facts, &plan);
        assert!(insights.iter().any(|i| i.severity == Severity::Critical
            && i.message.contains("only provides")));
    }

    #[test]
    fn non_iso_target_warns() {
        let (mut facts, plan) = assessment_fixture();
        facts.live_iso = false;
        let insights = assess(&facts, &plan);
        assert!(insights.iter().any(|i| i.severity == Severity::Warning
            && i.message.contains("not running an installer ISO")));
    }

    #[test]
    fn summary_renders_key_facts() {
        let facts = TargetFacts {
            hostname: Some("nixos".into()),
            nixos_version: Some("26.05".into()),
            kernel: Some("6.18".into()),
            arch: Some("x86_64".into()),
            efi: true,
            live_iso: true,
            mem_mib: Some(15921),
            cpu_count: Some(8),
            cpu_model: Some("AMD".into()),
            disks: vec![DiskFacts {
                path: "/dev/sda".into(),
                size_bytes: 4000000000000,
                model: Some("QEMU".into()),
                ..DiskFacts::default()
            }],
            ..TargetFacts::default()
        };

        let lines = facts.summary_lines().join("\n");
        assert!(lines.contains("host: nixos"));
        assert!(lines.contains("UEFI"));
        assert!(lines.contains("live-iso: yes"));
        assert!(lines.contains("/dev/sda"));
    }
}
