use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{Args, Parser, Subcommand};

mod agent;
mod edit;
mod facts;
mod generate;
mod install;
mod nix_ast;
mod repo;
mod report;
mod sops;
mod storage_cli;
mod ui;
mod yubikey_probe;

type Result<T> = std::result::Result<T, String>;

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<u8> {
    let cli = Cli::parse();

    match cli.command {
        CommandName::Install => {
            let repo = repo::find()?;
            crate::install::ui::run(&repo, true)
        }
        CommandName::Generate(args) => {
            let repo = repo::find()?;
            generate::dispatch(
                &repo,
                generate::Options {
                    role: args.role,
                    check_only: args.check_only,
                },
            )
        }
        CommandName::Check(args) => {
            let repo = repo::find()?;
            generate::dispatch(
                &repo,
                generate::Options {
                    role: args.role,
                    check_only: true,
                },
            )
        }
        CommandName::Edit => {
            let repo = repo::find()?;
            edit::dispatch(&repo)
        }
        CommandName::Status => {
            let repo = repo::find()?;
            let mut command = Command::new("git");
            command.current_dir(&repo).arg("status").arg("--short");
            exec_status(&mut command)
        }
        CommandName::Agent => agent::run_stdio(),
        CommandName::AgentPing => agent_ping_dispatch(),
        CommandName::AgentRemotePing(args) => {
            agent_remote_ping_dispatch(&args.remote, &args.agent_binary)
        }
        CommandName::AgentRemoteDiskScan(args) => {
            agent_remote_disk_scan_dispatch(&args.remote, &args.agent_binary)
        }
        CommandName::AgentUpload(args) => agent_upload_dispatch(&args),
        CommandName::AgentBootstrapPing(args) => agent_bootstrap_ping_dispatch(&args),
        CommandName::AgentNixBootstrapPing(args) => {
            let repo = repo::find()?;
            agent_nix_bootstrap_ping_dispatch(&repo, &args.remote)
        }
        CommandName::AgentNixBootstrapDiskScan(args) => {
            let repo = repo::find()?;
            agent_nix_bootstrap_disk_scan_dispatch(&repo, &args.remote)
        }
        CommandName::AgentNixBootstrapRun(args) => {
            let repo = repo::find()?;
            agent_nix_bootstrap_run_dispatch(&repo, &args)
        }
        CommandName::AgentNixBootstrapToolsCheck(args) => {
            let repo = repo::find()?;
            agent_nix_bootstrap_tools_check_dispatch(&repo, &args.remote)
        }
        CommandName::AgentNixBootstrapSessionCheck(args) => {
            let repo = repo::find()?;
            agent_nix_bootstrap_session_check_dispatch(&repo, &args.remote)
        }
        CommandName::AgentNixBootstrapStepCheck(args) => {
            let repo = repo::find()?;
            agent_nix_bootstrap_step_check_dispatch(&repo, &args.remote)
        }
        CommandName::AgentNixBootstrapTransferGenerated(args) => {
            let repo = repo::find()?;
            agent_nix_bootstrap_transfer_generated_dispatch(&repo, &args)
        }
        CommandName::RemoteInstallPlan(args) => remote_install_plan_dispatch(
            &args.source_dir,
            args.allow_ssh,
            args.overwrite_existing_storage,
            !args.no_network_route_cleanup,
        ),
        CommandName::RemoteInstallExec(args) => {
            let repo = repo::find()?;
            remote_install_exec_dispatch(&repo, &args)
        }
        CommandName::LocalInstallExec(args) => {
            let repo = repo::find()?;
            local_install_exec_dispatch(&repo, &args)
        }
        CommandName::PrepareGenerated(args) => {
            let repo = repo::find()?;
            prepare_generated_dispatch(&repo, args.allow_ssh)
        }
        CommandName::LisApply(args) => {
            let repo = repo::find()?;
            lis_apply_dispatch(&repo, &args.file)
        }
        CommandName::InstallPreview => {
            let repo = repo::find()?;
            crate::install::ui::run(&repo, false)
        }
        CommandName::Facts(args) => facts_dispatch(&args),
        CommandName::DiskScan(args) => disk_scan_dispatch(args.remote),
        CommandName::DiskPrepPreview(args) => disk_prep_preview_dispatch(&args.disk),
        CommandName::Preflight => {
            let repo = repo::find()?;
            preflight_dispatch(&repo)
        }
        CommandName::SecretsCheck => {
            let repo = repo::find()?;
            secrets_check_dispatch(&repo)
        }
        CommandName::SshCheck(args) => ssh_check_dispatch(&args.remote),
        CommandName::SopsRule(args) => {
            let repo = repo::find()?;
            sops_rule_dispatch(&repo, &args.file)
        }
        CommandName::SopsInfo(args) => sops_info_dispatch(
            &args.file,
            args.stanzas,
            args.match_yubikey,
            args.unwrap_check,
            args.unwrap_file_key,
            args.unwrap_data_key,
            args.check_values,
        ),
        CommandName::NixParse(args) => nix_parse_dispatch(&args.file),
        CommandName::Storage { command } => storage_dispatch(command),
        CommandName::Yubikey { command } => yubikey_dispatch(command),
    }
}

#[derive(Parser)]
#[command(name = "nox", version, about = "NixOS repo control tool")]
struct Cli {
    #[command(subcommand)]
    command: CommandName,
}

#[derive(Subcommand)]
enum CommandName {
    /// Run the clean installer.
    Install,
    /// Apply this system flake.
    #[command(hide = true)]
    Generate(GenerateArgs),
    /// Validate the current role.
    #[command(hide = true)]
    Check(CheckArgs),
    /// Pick a file to edit.
    #[command(hide = true)]
    Edit,
    /// Show git status.
    #[command(hide = true)]
    Status,
    /// Run remote-side nx agent over framed stdin/stdout.
    #[command(hide = true)]
    Agent,
    /// Exercise the framed agent protocol locally.
    #[command(hide = true)]
    AgentPing,
    /// Ping a remote nx agent over russh.
    #[command(hide = true)]
    AgentRemotePing(AgentRemoteArgs),
    /// Ask a remote nx agent to scan disks over russh.
    #[command(hide = true)]
    AgentRemoteDiskScan(AgentRemoteArgs),
    /// Upload this binary as the remote nx agent.
    #[command(hide = true)]
    AgentUpload(AgentUploadArgs),
    /// Upload this binary, then ping the remote nx agent.
    #[command(hide = true)]
    AgentBootstrapPing(AgentUploadArgs),
    /// Build this binary with Nix, copy the closure, then ping the remote nx agent.
    #[command(hide = true)]
    AgentNixBootstrapPing(SshCheckArgs),
    /// Build this binary with Nix, copy the closure, then scan disks through the remote nx agent.
    #[command(hide = true)]
    AgentNixBootstrapDiskScan(SshCheckArgs),
    /// Build this binary with Nix, copy the closure, then run a command through the remote nx agent.
    #[command(hide = true)]
    AgentNixBootstrapRun(AgentRunArgs),
    /// Build this binary with Nix, copy the closure, then check target tools through the remote nx agent.
    #[command(hide = true)]
    AgentNixBootstrapToolsCheck(SshCheckArgs),
    /// Build this binary with Nix, copy the closure, then send multiple RPCs over one remote nx agent session.
    #[command(hide = true)]
    AgentNixBootstrapSessionCheck(SshCheckArgs),
    /// Build this binary with Nix, copy the closure, then run safe typed remote steps.
    #[command(hide = true)]
    AgentNixBootstrapStepCheck(SshCheckArgs),
    /// Build this binary with Nix, copy the closure, then transfer generated files through the remote nx agent.
    #[command(hide = true)]
    AgentNixBootstrapTransferGenerated(AgentTransferGeneratedArgs),
    /// Preview the future Rust remote install steps without running them.
    #[command(hide = true)]
    RemoteInstallPlan(RemoteInstallPlanArgs),
    /// Execute the future Rust remote install plan through the remote nx agent.
    #[command(hide = true)]
    RemoteInstallExec(RemoteInstallExecArgs),
    /// Execute the install plan in-process on this machine (native local install).
    #[command(hide = true)]
    LocalInstallExec(LocalInstallExecArgs),
    /// Generate installer Nix files from the Rust installer state.
    #[command(hide = true)]
    PrepareGenerated(PrepareGeneratedArgs),
    /// Apply a LIS document: generate disko.nix/host.nix/user.nix from it (dry, no disk actions).
    LisApply(LisApplyArgs),
    /// Preview the Rust install wizard UI.
    #[command(hide = true)]
    InstallPreview,
    /// Scan install disks with lsblk JSON.
    #[command(hide = true)]
    DiskScan(DiskScanArgs),
    /// Print the remote disk preparation command without running it.
    #[command(hide = true)]
    DiskPrepPreview(DiskPrepPreviewArgs),
    /// Show everything about a target machine (hardware, disks, LVM, mounts).
    #[command(hide = true)]
    Facts(FactsArgs),
    /// Run Rust install preflight on the draft state.
    #[command(hide = true)]
    Preflight,
    /// Check native YubiKey/SOPS system secrets.
    #[command(hide = true)]
    SecretsCheck,
    /// Check SSH key auth for a remote installer target.
    #[command(hide = true)]
    SshCheck(SshCheckArgs),
    /// Show the .sops.yaml rule for a secret file.
    #[command(hide = true)]
    SopsRule(SopsRuleArgs),
    /// Show SOPS metadata for an encrypted file.
    #[command(hide = true)]
    SopsInfo(SopsInfoArgs),
    /// Parse a Nix file with rnix.
    #[command(hide = true)]
    NixParse(NixParseArgs),
    /// Hidden storage inspection commands used by the installer TUI.
    #[command(hide = true)]
    Storage {
        #[command(subcommand)]
        command: StorageCommand,
    },
    /// Probe YubiKey readers with yubikey.rs.
    #[command(hide = true)]
    Yubikey {
        #[command(subcommand)]
        command: YubikeyCommand,
    },
}


#[derive(Args)]
struct GenerateArgs {
    #[arg(long, value_parser = ["laptop", "server"])]
    role: Option<String>,
    #[arg(long)]
    check_only: bool,
}

#[derive(Args)]
struct CheckArgs {
    #[arg(long, value_parser = ["laptop", "server"])]
    role: Option<String>,
}

#[derive(Args)]
struct NixParseArgs {
    file: PathBuf,
}

#[derive(Args)]
struct SopsRuleArgs {
    file: PathBuf,
}

#[derive(Args)]
struct DiskScanArgs {
    #[arg(long)]
    remote: Option<String>,
}

#[derive(Args)]
struct FactsArgs {
    /// Inspect this remote target (user@host) through the nox agent; omit for
    /// the local machine.
    #[arg(long)]
    remote: Option<String>,
    /// Reuse an already-bootstrapped remote agent binary instead of building one.
    #[arg(long)]
    agent_binary: Option<String>,
    /// Emit the full report as JSON (for the TUI and scripts).
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct DiskPrepPreviewArgs {
    #[arg(long)]
    disk: String,
}

#[derive(Args)]
struct AgentRemoteArgs {
    #[arg(long)]
    remote: String,
    #[arg(long, default_value = "/tmp/nox")]
    agent_binary: String,
}

#[derive(Args)]
struct AgentUploadArgs {
    #[arg(long)]
    remote: String,
    #[arg(long, default_value = "/tmp/nox")]
    agent_binary: String,
    #[arg(long)]
    local_binary: Option<PathBuf>,
}

#[derive(Args)]
struct SshCheckArgs {
    #[arg(long)]
    remote: String,
}

#[derive(Args)]
struct AgentRunArgs {
    #[arg(long)]
    remote: String,
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

#[derive(Args)]
struct AgentTransferGeneratedArgs {
    #[arg(long)]
    remote: String,
    #[arg(long, default_value = "/tmp/nx-generated")]
    remote_dir: String,
}

#[derive(Args)]
struct RemoteInstallPlanArgs {
    #[arg(long, default_value = "/tmp/nx-source")]
    source_dir: String,
    #[arg(long)]
    allow_ssh: bool,
    #[arg(long)]
    overwrite_existing_storage: bool,
    #[arg(long)]
    no_network_route_cleanup: bool,
}

#[derive(Args)]
struct RemoteInstallExecArgs {
    #[arg(long)]
    remote: String,
    #[arg(long)]
    agent_binary: Option<String>,
    #[arg(long, default_value = "/tmp/nx-source")]
    source_dir: String,
    #[arg(long)]
    transfer_source: bool,
    #[arg(long)]
    allow_ssh: bool,
    /// Install disk(s) to lay out. Repeat for multiple; defaults to the draft disk.
    #[arg(long = "disk")]
    disks: Vec<String>,
    #[arg(long)]
    overwrite_existing_storage: bool,
    #[arg(long)]
    no_network_route_cleanup: bool,
    #[arg(long)]
    allow_destructive: bool,
    #[arg(long)]
    confirm_destructive_target: Option<String>,
    #[arg(long)]
    max_destructive_steps: Option<usize>,
    /// Decrypt secrets with this local age key file instead of the YubiKey.
    #[arg(long)]
    age_key_file: Option<PathBuf>,
    /// Skip the `bin ensure` step (avoids needing a real GitHub token).
    #[arg(long)]
    skip_bin_ensure: bool,
    /// Skip the dotfiles step.
    #[arg(long)]
    skip_dotfiles: bool,
    /// Set the primary user's password (hashed to sha512-crypt in-process).
    #[arg(long)]
    password: Option<String>,
    /// Use a pre-computed yescrypt password hash read from this file.
    #[arg(long)]
    password_hash_file: Option<PathBuf>,
}

#[derive(Args)]
struct LocalInstallExecArgs {
    /// Mountpoint of the target system to finalize (must already be Disko-mounted).
    #[arg(long, default_value = "/mnt")]
    mountpoint: String,
    #[arg(long, default_value = "/tmp/nx-source")]
    source_dir: String,
    #[arg(long)]
    allow_ssh: bool,
    /// Install disk(s) to lay out. Repeat for multiple; defaults to the draft disk.
    #[arg(long = "disk")]
    disks: Vec<String>,
    #[arg(long)]
    overwrite_existing_storage: bool,
    #[arg(long)]
    no_network_route_cleanup: bool,
    #[arg(long)]
    allow_destructive: bool,
    #[arg(long)]
    confirm_destructive_target: Option<String>,
    #[arg(long)]
    max_destructive_steps: Option<usize>,
    /// Decrypt secrets with this local age key file instead of the YubiKey.
    #[arg(long)]
    age_key_file: Option<PathBuf>,
    /// Skip the `bin ensure` step (avoids needing a real GitHub token).
    #[arg(long)]
    skip_bin_ensure: bool,
    /// Skip the dotfiles step.
    #[arg(long)]
    skip_dotfiles: bool,
    /// Set the primary user's password (hashed to sha512-crypt in-process).
    #[arg(long)]
    password: Option<String>,
    /// Use a pre-computed yescrypt password hash read from this file.
    #[arg(long)]
    password_hash_file: Option<PathBuf>,
}

#[derive(Args)]
struct PrepareGeneratedArgs {
    #[arg(long)]
    allow_ssh: bool,
}

#[derive(Args)]
struct LisApplyArgs {
    /// Path to a .lis.json document.
    #[arg(long)]
    file: PathBuf,
}

#[derive(Args)]
struct SopsInfoArgs {
    #[arg(long)]
    stanzas: bool,
    #[arg(long)]
    match_yubikey: bool,
    #[arg(long)]
    unwrap_check: bool,
    #[arg(long)]
    unwrap_file_key: bool,
    #[arg(long)]
    unwrap_data_key: bool,
    #[arg(long)]
    check_values: bool,
    file: PathBuf,
}

#[derive(Subcommand)]
enum YubikeyCommand {
    /// Show PC/SC readers visible to yubikey.rs.
    Status,
    /// List age-compatible recipients from YubiKey retired PIV slots.
    Recipients,
}

#[derive(Subcommand)]
enum StorageCommand {
    /// Print the generated storage plan.
    #[command(hide = true)]
    Plan,
    /// Apply the storage layout to a target (or preview with --dry-run).
    #[command(hide = true)]
    Apply(StorageApplyArgs),
}

#[derive(Args)]
struct StorageApplyArgs {
    /// Preview the generated storage actions without touching any target.
    #[arg(long)]
    dry_run: bool,
    /// Target to apply the storage layout to (user@host). Required unless --dry-run.
    #[arg(long)]
    remote: Option<String>,
    /// Reuse an already-bootstrapped remote agent binary instead of building one.
    #[arg(long)]
    agent_binary: Option<String>,
    /// Remote directory that receives the transferred flake source.
    #[arg(long, default_value = "/tmp/nx-source")]
    source_dir: String,
    /// Regenerate installer files and transfer the flake source before applying.
    #[arg(long)]
    transfer_source: bool,
    /// Install disk(s) to lay out. Repeat for multiple; defaults to the draft disk.
    #[arg(long = "disk")]
    disks: Vec<String>,
    /// Filesystem for the logical volumes.
    #[arg(long, value_parser = ["btrfs", "ext4"], default_value = "btrfs")]
    filesystem: String,
    /// Encrypt the physical volumes with LUKS.
    #[arg(long)]
    encrypt: bool,
    #[arg(long)]
    overwrite_existing_storage: bool,
    #[arg(long)]
    no_network_route_cleanup: bool,
    #[arg(long)]
    allow_destructive: bool,
    #[arg(long)]
    confirm_destructive_target: Option<String>,
    #[arg(long)]
    max_destructive_steps: Option<usize>,
}

fn exec_status(command: &mut Command) -> Result<u8> {
    let status = command
        .status()
        .map_err(|err| format!("failed to run {:?}: {err}", command.get_program()))?;
    Ok(status.code().unwrap_or(1) as u8)
}

fn nix_parse_dispatch(path: &Path) -> Result<u8> {
    let report = nix_ast::parse_file(path)?;
    if report.is_ok() {
        println!("nix parse: ok ({} syntax nodes)", report.node_count);
        return Ok(0);
    }

    eprintln!("nix parse: {} error(s)", report.errors.len());
    for error in report.errors {
        eprintln!("  {error}");
    }
    Ok(1)
}

fn facts_dispatch(args: &FactsArgs) -> Result<u8> {
    let facts = match args.remote.as_deref() {
        None => facts::collect(),
        // One-shot SSH probe by default: no agent bootstrap, interactive speed.
        Some(remote) => match args.agent_binary.as_deref() {
            None => facts::collect_over_ssh(remote)?,
            Some(agent_binary) => {
                let mut session =
                    install::remote::RemoteInstallSession::connect_existing(remote, agent_binary)?;
                let facts = session.facts()?;
                let _ = session.close();
                facts
            }
        },
    };

    if args.json {
        let json = serde_json::to_string_pretty(&facts)
            .map_err(|err| format!("failed to render facts JSON: {err}"))?;
        println!("{json}");
    } else {
        for line in facts.summary_lines() {
            println!("{line}");
        }
    }
    Ok(0)
}

fn disk_scan_dispatch(remote: Option<String>) -> Result<u8> {
    let (scope, remote_value) = match remote {
        Some(remote) => (crate::install::state::InstallScope::Remote, remote),
        None => (crate::install::state::InstallScope::Local, String::new()),
    };
    let disks = crate::install::disk::discover(scope, &remote_value)?;
    println!("install disks:");
    for disk in disks {
        match disk.model {
            Some(model) => println!("  {}  {}G  {}", disk.path, disk.size_gib, model),
            None => println!("  {}  {}G", disk.path, disk.size_gib),
        }
    }
    Ok(0)
}

fn agent_ping_dispatch() -> Result<u8> {
    let mut input = Vec::new();
    agent::write_frame(&mut input, &agent::AgentRequest::Ping)?;
    let mut output = Vec::new();
    agent::run(Cursor::new(input), &mut output)?;
    match agent::read_frame::<_, agent::AgentResponse>(&mut output.as_slice())? {
        Some(agent::AgentResponse::Pong) => {
            println!("agent: pong");
            Ok(0)
        }
        Some(response) => Err(format!("unexpected agent response: {response:?}")),
        None => Err("agent returned no response".to_string()),
    }
}

fn agent_remote_ping_dispatch(remote: &str, agent_binary: &str) -> Result<u8> {
    let mut session = crate::agent::client::AgentSession::connect(remote, agent_binary)?;
    session.ping()?;
    let _ = session.close();
    println!("remote agent: pong");
    Ok(0)
}

fn agent_remote_disk_scan_dispatch(remote: &str, agent_binary: &str) -> Result<u8> {
    let mut session = crate::agent::client::AgentSession::connect(remote, agent_binary)?;
    let response = session.request(agent::AgentRequest::DiskScan)?;
    let _ = session.close();
    match response {
        agent::AgentResponse::DiskScan { disks } => {
            println!("remote agent disks:");
            for disk in disks {
                match disk.model {
                    Some(model) => println!("  {}  {}G  {}", disk.path, disk.size_gib, model),
                    None => println!("  {}  {}G", disk.path, disk.size_gib),
                }
            }
            Ok(0)
        }
        agent::AgentResponse::Error { message } => Err(message),
        response => Err(format!("unexpected remote agent response: {response:?}")),
    }
}

fn agent_upload_dispatch(args: &AgentUploadArgs) -> Result<u8> {
    let local_binary = local_agent_binary(args.local_binary.as_deref())?;
    crate::agent::client::upload(&args.remote, &local_binary, &args.agent_binary)?;
    println!(
        "uploaded agent: {} -> {}:{}",
        local_binary.display(),
        args.remote,
        args.agent_binary
    );
    Ok(0)
}

fn agent_bootstrap_ping_dispatch(args: &AgentUploadArgs) -> Result<u8> {
    agent_upload_dispatch(args)?;
    agent_remote_ping_dispatch(&args.remote, &args.agent_binary)
}

fn agent_nix_bootstrap_ping_dispatch(repo: &Path, remote: &str) -> Result<u8> {
    let agent = crate::agent::bootstrap::bootstrap_with_progress(repo, remote, |message| {
        println!("bootstrap: {message}");
    })?;
    println!("bootstrapped agent: {}", agent.binary.display());
    agent_remote_ping_dispatch(remote, &agent.binary.to_string_lossy())
}

fn agent_nix_bootstrap_disk_scan_dispatch(repo: &Path, remote: &str) -> Result<u8> {
    let agent = crate::agent::bootstrap::bootstrap_with_progress(repo, remote, |message| {
        println!("bootstrap: {message}");
    })?;
    println!("bootstrapped agent: {}", agent.binary.display());
    agent_remote_disk_scan_dispatch(remote, &agent.binary.to_string_lossy())
}

fn agent_nix_bootstrap_run_dispatch(repo: &Path, args: &AgentRunArgs) -> Result<u8> {
    let agent = crate::agent::bootstrap::bootstrap_with_progress(repo, &args.remote, |message| {
        println!("bootstrap: {message}");
    })?;
    println!("bootstrapped agent: {}", agent.binary.display());

    let (program, command_args) = args
        .command
        .split_first()
        .ok_or_else(|| "remote command is required".to_string())?;
    let mut session =
        crate::agent::client::AgentSession::connect(&args.remote, &agent.binary.to_string_lossy())?;
    let result = session.run_command(program, command_args, &[])?;
    let _ = session.close();

    print!("{}", String::from_utf8_lossy(&result.stdout));
    eprint!("{}", String::from_utf8_lossy(&result.stderr));
    Ok(result.status.min(255) as u8)
}

fn agent_nix_bootstrap_tools_check_dispatch(repo: &Path, remote: &str) -> Result<u8> {
    let agent = crate::agent::bootstrap::bootstrap_with_progress(repo, remote, |message| {
        println!("bootstrap: {message}");
    })?;
    println!("bootstrapped agent: {}", agent.binary.display());

    let required = ["bash", "lsblk", "sudo"]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let mut session = crate::agent::client::AgentSession::connect(remote, &agent.binary.to_string_lossy())?;
    let result = session.tools_check(&required, true)?;
    let _ = session.close();

    if let Some(user) = result.user {
        println!("remote user: {user}");
    }
    for tool in &result.found {
        println!("found: {} -> {}", tool.name, tool.path);
    }
    for name in &result.missing {
        println!("missing: {name}");
    }
    match result.sudo_ok {
        Some(true) => println!("sudo -n: ok"),
        Some(false) if result.sudo_stderr.is_empty() => println!("sudo -n: failed"),
        Some(false) => println!("sudo -n: failed ({})", result.sudo_stderr),
        None => {}
    }

    Ok(
        if result.missing.is_empty() && result.sudo_ok != Some(false) {
            0
        } else {
            1
        },
    )
}

fn agent_nix_bootstrap_session_check_dispatch(repo: &Path, remote: &str) -> Result<u8> {
    let mut session = crate::install::remote::RemoteInstallSession::connect(repo, remote, |message| {
        println!("bootstrap: {message}");
    })?;
    println!("bootstrapped agent: {}", session.agent_binary());

    session.ping()?;
    println!("session rpc: ping ok");

    let required = ["bash", "lsblk", "sudo"]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let tools = session.tools_check(&required, true)?;
    println!(
        "session rpc: tools ok user={} found={} missing={}",
        tools.user.unwrap_or_else(|| "unknown".to_string()),
        tools.found.len(),
        tools.missing.len()
    );

    let user = session.remote_user_check()?;
    println!("session step: {} -> {}", user.name, user.stdout);

    let disks = session.disk_scan()?;
    println!("session rpc: disk scan ok disks={}", disks.len());
    for disk in disks {
        match disk.model {
            Some(model) => println!("  {}  {}G  {}", disk.path, disk.size_gib, model),
            None => println!("  {}  {}G", disk.path, disk.size_gib),
        }
    }

    session.close()?;
    Ok(0)
}

fn agent_nix_bootstrap_step_check_dispatch(repo: &Path, remote: &str) -> Result<u8> {
    let mut session = crate::install::remote::RemoteInstallSession::connect(repo, remote, |message| {
        println!("bootstrap: {message}");
    })?;
    println!("bootstrapped agent: {}", session.agent_binary());

    let user = session.remote_user_check()?;
    println!(
        "step: {} status={} stdout={}",
        user.name, user.status, user.stdout
    );

    match session.remote_nixos_version() {
        Ok(version) => println!(
            "step: {} status={} stdout={}",
            version.name, version.status, version.stdout
        ),
        Err(err) => println!("step: remote nixos version skipped/failed: {err}"),
    }

    match session.remote_mount_check() {
        Ok(mount) => println!(
            "step: {} status={} stdout={}",
            mount.name, mount.status, mount.stdout
        ),
        Err(err) => println!("step: remote mount check not mounted: {err}"),
    }

    session.close()?;
    Ok(0)
}

fn agent_nix_bootstrap_transfer_generated_dispatch(
    repo: &Path,
    args: &AgentTransferGeneratedArgs,
) -> Result<u8> {
    let mut session =
        crate::install::remote::RemoteInstallSession::connect(repo, &args.remote, |message| {
            println!("bootstrap: {message}");
        })?;
    println!("bootstrapped agent: {}", session.agent_binary());

    let transferred = session.transfer_generated(repo, &args.remote_dir)?;
    for artifact in transferred {
        println!(
            "transferred: {} -> {} ({} bytes)",
            artifact.local_path.display(),
            artifact.remote_path,
            artifact.bytes_written
        );
    }
    session.close()?;
    Ok(0)
}

fn remote_install_plan_dispatch(
    source_dir: &str,
    allow_ssh: bool,
    overwrite_existing_storage: bool,
    network_route_cleanup: bool,
) -> Result<u8> {
    let mut state = crate::install::state::InstallState::draft();
    state.allow_ssh = allow_ssh;
    state.overwrite_existing_storage = overwrite_existing_storage;
    state.network_route_cleanup = network_route_cleanup;
    let steps = crate::install::plan::plan_remote_install_steps(&state, source_dir)?;
    println!(
        "remote install plan: source_dir={source_dir} ssh={} overwrite_existing_storage={} network_route_cleanup={}",
        if state.allow_ssh { "enabled" } else { "disabled" },
        if state.overwrite_existing_storage {
            "enabled"
        } else {
            "disabled"
        },
        if state.network_route_cleanup {
            "enabled"
        } else {
            "disabled"
        }
    );
    for (index, step) in steps.iter().enumerate() {
        let marker = if step.destructive {
            "DESTRUCTIVE"
        } else {
            "safe"
        };
        println!(
            "{:02}. [{}] {} :: {}",
            index + 1,
            marker,
            step.name,
            step.command_line()
        );
    }
    Ok(0)
}

fn remote_install_exec_dispatch(repo: &Path, args: &RemoteInstallExecArgs) -> Result<u8> {
    let mut state = crate::install::state::InstallState::draft();
    state.allow_ssh = args.allow_ssh;
    state.overwrite_existing_storage = args.overwrite_existing_storage;
    state.network_route_cleanup = !args.no_network_route_cleanup;
    state.skip_bin_ensure = args.skip_bin_ensure;
    if args.skip_dotfiles {
        state.dotfiles_repo = None;
    }
    state.user_password_hash =
        resolve_password_hash(args.password.as_deref(), args.password_hash_file.as_deref())?;
    apply_disk_selection(&mut state, crate::install::state::InstallScope::Remote, &args.remote, &args.disks)?;
    let policy = destructive_policy_for_target(
        args.allow_destructive,
        args.confirm_destructive_target.as_deref(),
        args.max_destructive_steps,
        &args.remote,
    )?;

    let secrets = if args.allow_destructive {
        crate::install::exec::prepare_remote_install_secrets(
            repo,
            &state,
            args.age_key_file.as_deref(),
        )?
    } else {
        None
    };

    let reporter = crate::report::Reporter::text();
    let mut session = match args.agent_binary.as_deref() {
        Some(agent_binary) => {
            reporter.note(format!("using existing remote agent: {agent_binary}"));
            crate::install::remote::RemoteInstallSession::connect_existing(&args.remote, agent_binary)?
        }
        None => {
            let bootstrap_reporter = reporter.clone();
            crate::install::remote::RemoteInstallSession::connect(repo, &args.remote, move |message| {
                bootstrap_reporter.note(format!("bootstrap: {message}"));
            })?
        }
    };
    session.set_reporter(reporter.clone());
    reporter.note(format!("bootstrapped agent: {}", session.agent_binary()));

    let execution = (|| {
        if args.transfer_source {
            crate::install::exec::prepare_generated(repo, &state)?;
            let transferred = session.transfer_flake_source(repo, &args.source_dir)?;
            for artifact in transferred {
                reporter.note(format!(
                    "transferred: {} -> {} ({} bytes)",
                    artifact.local_path.display(),
                    artifact.remote_path,
                    artifact.bytes_written
                ));
            }
        }

        let steps = match secrets.as_ref() {
            Some(_) => crate::install::plan::plan_remote_install_steps_with_secrets(
                &state,
                &args.source_dir,
                crate::install::exec::plan_secrets(&secrets),
            )?,
            None => crate::install::plan::plan_remote_install_steps(&state, &args.source_dir)?,
        };
        crate::install::executor::execute_remote_plan(&mut session, &steps, policy, &reporter)
    })();
    let close = session.close();
    let execution = match (execution, close) {
        (Ok(execution), Ok(())) => execution,
        (Err(err), _) => return Err(err),
        (Ok(_), Err(err)) => return Err(err),
    };

    Ok(if execution.refused.is_empty() { 0 } else { 1 })
}

fn local_install_exec_dispatch(repo: &Path, args: &LocalInstallExecArgs) -> Result<u8> {
    let mut state = crate::install::state::InstallState::draft();
    state.scope = crate::install::state::InstallScope::Local;
    state.mountpoint = args.mountpoint.clone();
    state.allow_ssh = args.allow_ssh;
    state.overwrite_existing_storage = args.overwrite_existing_storage;
    state.network_route_cleanup = !args.no_network_route_cleanup;
    state.skip_bin_ensure = args.skip_bin_ensure;
    if args.skip_dotfiles {
        state.dotfiles_repo = None;
    }
    state.user_password_hash =
        resolve_password_hash(args.password.as_deref(), args.password_hash_file.as_deref())?;
    apply_disk_selection(&mut state, crate::install::state::InstallScope::Local, "", &args.disks)?;

    let policy = destructive_policy_for_target(
        args.allow_destructive,
        args.confirm_destructive_target.as_deref(),
        args.max_destructive_steps,
        &args.mountpoint,
    )?;

    crate::install::exec::prepare_generated(repo, &state)?;

    // On a local install the flake source is this repository itself; it already
    // holds flake.nix plus the freshly written generated/ files.
    let source_dir = repo.to_string_lossy().to_string();

    let secrets = if args.allow_destructive {
        crate::install::exec::prepare_remote_install_secrets(
            repo,
            &state,
            args.age_key_file.as_deref(),
        )?
    } else {
        None
    };

    let steps = match secrets.as_ref() {
        Some(_) => crate::install::plan::plan_remote_install_steps_with_secrets(
            &state,
            &source_dir,
            crate::install::exec::plan_secrets(&secrets),
        )?,
        None => crate::install::plan::plan_remote_install_steps(&state, &source_dir)?,
    };

    let reporter = crate::report::Reporter::text();
    let mut ops = crate::install::local::LiveLocalOps {
        reporter: reporter.clone(),
    };
    let execution =
        crate::install::local::execute_local_plan(&mut ops, &steps, policy, &reporter)?;

    Ok(if execution.refused.is_empty() { 0 } else { 1 })
}

/// The LIS -> NixOS applier: consume a distro-neutral LIS document and emit
/// this repo's generated nix (disko.nix, host.nix, user.nix). Never touches
/// disks -- applying the generated config is a separate, confirmed step.
fn lis_apply_dispatch(repo: &Path, file: &Path) -> Result<u8> {
    let doc = crate::install::lis::read(file)?;
    let issues = lis::validate(&doc);
    if !issues.is_empty() {
        return Err(format!(
            "{} is not valid LIS: {}",
            file.display(),
            issues
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    let state = crate::install::lis::state_from(&doc);
    crate::install::exec::prepare_generated(repo, &state)?;
    println!(
        "applied {} -> host/generated/ (hostname={}, users={}, pools={})",
        file.display(),
        state.hostname,
        state.users.len(),
        state.volume_groups.len(),
    );
    Ok(0)
}

fn prepare_generated_dispatch(repo: &Path, allow_ssh: bool) -> Result<u8> {
    let mut state = crate::install::state::InstallState::draft();
    state.allow_ssh = allow_ssh;
    crate::install::exec::prepare_generated(repo, &state)?;
    println!(
        "generated installer config: ok ssh={}",
        if state.allow_ssh {
            "enabled"
        } else {
            "disabled"
        }
    );
    Ok(0)
}

fn destructive_policy_for_target(
    allow_destructive: bool,
    confirmed_target: Option<&str>,
    max_destructive_steps: Option<usize>,
    expected_target: &str,
) -> Result<crate::install::executor::RemoteExecutionPolicy> {
    if !allow_destructive {
        if confirmed_target.is_some() || max_destructive_steps.is_some() {
            return Err(
                "--confirm-destructive-target/--max-destructive-steps require --allow-destructive"
                    .to_string(),
            );
        }
        return Ok(crate::install::executor::RemoteExecutionPolicy::safe());
    }

    match confirmed_target {
        Some(target) if target == expected_target => {}
        Some(target) => {
            return Err(format!(
                "destructive confirmation target mismatch: got {target}, expected {expected_target}",
            ));
        }
        None => {
            return Err(format!(
                "destructive execution requires --confirm-destructive-target {expected_target}",
            ));
        }
    }

    let max_destructive_steps = max_destructive_steps
        .ok_or_else(|| "destructive execution requires --max-destructive-steps".to_string())?;
    if max_destructive_steps == 0 {
        return Err("--max-destructive-steps must be greater than zero".to_string());
    }

    Ok(crate::install::executor::RemoteExecutionPolicy::allow_destructive_steps(max_destructive_steps))
}

fn local_agent_binary(override_path: Option<&Path>) -> Result<PathBuf> {
    match override_path {
        Some(path) => Ok(path.to_path_buf()),
        None => std::env::current_exe()
            .map_err(|err| format!("failed to resolve current executable: {err}")),
    }
}

fn disk_prep_preview_dispatch(disk: &str) -> Result<u8> {
    println!("{}", crate::install::disk::remote_prepare_preview(disk)?);
    Ok(0)
}

fn preflight_dispatch(repo: &Path) -> Result<u8> {
    let state = crate::install::state::InstallState::draft();
    let report =
        crate::install::preflight::run(repo, &state, &|message| println!("{message}"));
    for check in &report.checks {
        let marker = match check.status {
            crate::install::preflight::PreflightStatus::Pass => "ok",
            crate::install::preflight::PreflightStatus::Fail => "fail",
        };
        println!("{marker}: {} - {}", check.name, check.detail);
    }
    Ok(if report.pass() { 0 } else { 1 })
}

fn secrets_check_dispatch(repo: &Path) -> Result<u8> {
    let check = crate::install::secrets::check(repo);
    if check.ok {
        println!("ok: secrets - {}", check.detail);
        Ok(0)
    } else {
        println!("fail: secrets - {}", check.detail);
        Ok(1)
    }
}

fn ssh_check_dispatch(remote: &str) -> Result<u8> {
    let check = crate::install::ssh::check_key_auth(remote);
    if check.ok {
        println!("ok: ssh - {}", check.detail);
        Ok(0)
    } else {
        println!("fail: ssh - {}", check.detail);
        Ok(1)
    }
}

fn sops_rule_dispatch(repo: &Path, file: &Path) -> Result<u8> {
    let config = crate::sops::config::SopsConfig::load(repo)?;
    let matched = config.match_file(repo, file)?;
    println!("sops rule: {}", matched.path_regex);
    println!("age recipients:");
    for recipient in matched.recipients {
        println!("  {recipient}");
    }
    Ok(0)
}

fn sops_info_dispatch(
    file: &Path,
    show_stanzas: bool,
    match_yubikey: bool,
    unwrap_check: bool,
    unwrap_file_key: bool,
    unwrap_data_key: bool,
    check_values: bool,
) -> Result<u8> {
    let metadata = crate::sops::metadata::SopsMetadata::load(file)?;
    let show_stanzas =
        show_stanzas || unwrap_check || unwrap_file_key || unwrap_data_key || check_values;
    let unwrap_check = unwrap_check || unwrap_file_key || unwrap_data_key || check_values;
    let match_yubikey =
        match_yubikey || unwrap_check || unwrap_file_key || unwrap_data_key || check_values;
    let yubikey_recipients = match match_yubikey {
        true => Some(yubikey_probe::recipients()?),
        false => None,
    };
    println!("sops file: {}", file.display());
    println!("age recipients:");
    for recipient in metadata.recipients() {
        println!("  {recipient}");
    }
    if show_stanzas {
        println!("age stanzas:");
        for entry in metadata.entries() {
            println!("  recipient: {}", entry.recipient);
            let mut connected = false;
            if let Some(report) = yubikey_recipients.as_ref() {
                if let Some(info) = report.find_recipient(&entry.recipient) {
                    connected = true;
                    println!(
                        "    connected=true yubikey_serial={} slot={}",
                        info.serial, info.slot
                    );
                } else {
                    println!("    connected=false");
                }
            }
            for stanza in &entry.stanzas {
                let backend = if stanza.is_yubikey() {
                    "yubikey"
                } else {
                    "software"
                };
                println!(
                    "    {} args={} body={} backend={}",
                    stanza.stanza_type,
                    stanza.args.len(),
                    stanza.body_len,
                    backend
                );
                if unwrap_check && stanza.is_yubikey() {
                    let check = stanza.unwrap_check();
                    let ok = connected && check.ok;
                    let reason = if connected {
                        check.reason
                    } else {
                        "matching YubiKey is not connected".to_string()
                    };
                    println!("      unwrap_check={} reason={}", ok, reason);
                }
            }
            if unwrap_file_key
                && connected
                && entry.stanzas.iter().any(|stanza| stanza.is_yubikey())
            {
                let Some(report) = yubikey_recipients.as_ref() else {
                    continue;
                };
                let Some(info) = report.find_recipient(&entry.recipient) else {
                    continue;
                };
                let unwrapped = crate::sops::unwrap::unwrap_entry(entry, info)?;
                println!("    file_key_sha256_128={}", unwrapped.fingerprint);
            }
        }
    }
    if unwrap_data_key || check_values {
        let Some(report) = yubikey_recipients.as_ref() else {
            return Err("YubiKey recipient report was not loaded".to_string());
        };
        let data_key = crate::sops::data_key::decrypt_first(&metadata, report)?;
        if unwrap_data_key {
            println!(
                "data_key: ok bytes={} sha256_128={}",
                data_key.len(),
                data_key.fingerprint()
            );
        }
        if check_values {
            let report = crate::sops::values::check_file(file, &data_key)?;
            println!(
                "values: ok decrypted={}/{} mac_decrypted={} mac_matches={}",
                report.decrypted_values,
                report.encrypted_values,
                report.mac_decrypted,
                report.mac_matches
            );
        }
    }
    Ok(0)
}

fn yubikey_dispatch(command: YubikeyCommand) -> Result<u8> {
    match command {
        YubikeyCommand::Status => {
            let report = yubikey_probe::status()?;
            if report.has_reader() {
                println!("YubiKey readers:");
                for reader in report.readers {
                    if let Some(yubikey) = reader.yubikey {
                        println!(
                            "  {}: YubiKey serial {} version {}",
                            reader.name, yubikey.serial, yubikey.version
                        );
                    } else {
                        println!("  {}: no YubiKey opened", reader.name);
                    }
                }
            } else {
                println!("YubiKey readers: none");
            }
            Ok(0)
        }
        YubikeyCommand::Recipients => {
            let report = yubikey_probe::recipients()?;
            if report.recipients.is_empty() {
                println!("YubiKey recipients: none");
                return Ok(1);
            }

            println!("YubiKey recipients:");
            for recipient in report.recipients {
                println!("  serial {} slot {}", recipient.serial, recipient.slot);
                println!("    age1tag: {}", recipient.tag_recipient);
                println!("    age1yubikey: {}", recipient.yubikey_recipient);
            }
            Ok(0)
        }
    }
}

fn storage_dispatch(command: StorageCommand) -> Result<u8> {
    let repo = repo::find()?;
    match command {
        StorageCommand::Plan => storage_cli::plan(&repo),
        StorageCommand::Apply(args) => {
            if args.dry_run {
                return storage_cli::apply(&repo, true);
            }
            let remote = args.remote.clone().ok_or_else(|| {
                "storage apply requires --remote <user@host> (or --dry-run to preview)".to_string()
            })?;
            storage_apply_exec_dispatch(&repo, &args, &remote)
        }
    }
}

fn storage_apply_exec_dispatch(repo: &Path, args: &StorageApplyArgs, remote: &str) -> Result<u8> {
    let mut state = crate::install::state::InstallState::draft();
    state.scope = crate::install::state::InstallScope::Remote;
    state.remote = remote.to_string();
    state.overwrite_existing_storage = args.overwrite_existing_storage;
    state.network_route_cleanup = !args.no_network_route_cleanup;
    state.filesystem = match args.filesystem.as_str() {
        "ext4" => crate::install::state::Filesystem::Ext4,
        _ => crate::install::state::Filesystem::Btrfs,
    };
    state.encrypt = args.encrypt;
    apply_disk_selection(&mut state, crate::install::state::InstallScope::Remote, remote, &args.disks)?;

    let policy = destructive_policy_for_target(
        args.allow_destructive,
        args.confirm_destructive_target.as_deref(),
        args.max_destructive_steps,
        remote,
    )?;

    // Render generated/disko.nix from the (possibly disk-overridden) state so the
    // transferred source lays out exactly the disks we planned.
    crate::install::exec::prepare_generated(repo, &state)?;

    let reporter = crate::report::Reporter::text();
    let mut session = match args.agent_binary.as_deref() {
        Some(agent_binary) => {
            reporter.note(format!("using existing remote agent: {agent_binary}"));
            crate::install::remote::RemoteInstallSession::connect_existing(remote, agent_binary)?
        }
        None => {
            let bootstrap_reporter = reporter.clone();
            crate::install::remote::RemoteInstallSession::connect(repo, remote, move |message| {
                bootstrap_reporter.note(format!("bootstrap: {message}"));
            })?
        }
    };
    session.set_reporter(reporter.clone());
    reporter.note(format!("bootstrapped agent: {}", session.agent_binary()));

    let execution = (|| {
        if args.transfer_source {
            let transferred = session.transfer_flake_source(repo, &args.source_dir)?;
            for artifact in transferred {
                reporter.note(format!(
                    "transferred: {} -> {} ({} bytes)",
                    artifact.local_path.display(),
                    artifact.remote_path,
                    artifact.bytes_written
                ));
            }
        }

        let steps = crate::install::plan::plan_remote_storage_steps(&state, &args.source_dir)?;
        crate::install::executor::execute_remote_plan(&mut session, &steps, policy, &reporter)
    })();
    let close = session.close();
    let execution = match (execution, close) {
        (Ok(execution), Ok(())) => execution,
        (Err(err), _) => return Err(err),
        (Ok(_), Err(err)) => return Err(err),
    };

    Ok(if execution.refused.is_empty() { 0 } else { 1 })
}

/// Replace the draft install disks with a caller-specified selection, resolving
/// real sizes/models from a live scan of the target so capacity validation and
/// the rendered Disko layout match the actual hardware.
/// Resolve the primary user's password hash from a plaintext password (hashed
/// with `mkpasswd -m yescrypt`) or a file holding a pre-computed hash.
fn resolve_password_hash(
    password: Option<&str>,
    password_hash_file: Option<&Path>,
) -> Result<Option<String>> {
    if let Some(path) = password_hash_file {
        let hash = std::fs::read_to_string(path)
            .map_err(|err| format!("failed to read password hash file {}: {err}", path.display()))?
            .trim()
            .to_string();
        if hash.is_empty() {
            return Err(format!("password hash file is empty: {}", path.display()));
        }
        return Ok(Some(hash));
    }

    let Some(password) = password else {
        return Ok(None);
    };
    crate::install::secrets::hash_password(password).map(Some)
}

fn apply_disk_selection(
    state: &mut crate::install::state::InstallState,
    scope: crate::install::state::InstallScope,
    remote: &str,
    disks: &[String],
) -> Result<()> {
    if disks.is_empty() {
        return Ok(());
    }

    let discovered = crate::install::disk::discover(scope, remote)?;
    let chosen = disks
        .iter()
        .map(|path| {
            discovered
                .iter()
                .find(|disk| &disk.path == path)
                .map(|disk| crate::install::state::DiskChoice {
                    path: disk.path.clone(),
                    size_gib: disk.size_gib,
                    model: disk.model.clone(),
                })
                .ok_or_else(|| format!("requested disk not found on target: {path}"))
        })
        .collect::<Result<Vec<_>>>()?;

    state.discovered_disks = chosen.clone();
    state.disks = chosen;
    state.disk_roles.clear();
    state.normalize_disk_roles();
    state.normalize_storage_assignments();
    Ok(())
}

#[cfg(test)]
mod main_tests {
    use super::destructive_policy_for_target;

    #[test]
    fn safe_policy_allows_no_destructive_steps() {
        let policy = destructive_policy_for_target(false, None, None, "local").unwrap();

        assert_eq!(policy.destructive_steps_allowed, 0);
    }

    #[test]
    fn destructive_policy_requires_matching_target_confirmation() {
        let err = destructive_policy_for_target(true, Some("nixos@old"), Some(1), "nixos@new")
            .unwrap_err();

        assert!(err.contains("target mismatch"));
    }

    #[test]
    fn destructive_policy_requires_step_limit() {
        let err = destructive_policy_for_target(true, Some("nixos@host"), None, "nixos@host")
            .unwrap_err();

        assert!(err.contains("--max-destructive-steps"));
    }

    #[test]
    fn destructive_policy_accepts_target_and_step_limit() {
        let policy =
            destructive_policy_for_target(true, Some("nixos@host"), Some(1), "nixos@host").unwrap();

        assert_eq!(policy.destructive_steps_allowed, 1);
    }
}
