pub mod bootstrap;
pub mod client;

use std::env;
use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
#[cfg(unix)]
use std::os::unix::fs::symlink;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use futures_util::TryStreamExt;
use nix::unistd::{getgid, getuid};
use rtnetlink::packet_route::{
    address::{AddressAttribute, AddressMessage},
    link::{LinkAttribute, LinkMessage},
    route::{RouteAddress, RouteAttribute, RouteHeader, RouteMessage},
    AddressFamily,
};
use rtnetlink::RouteMessageBuilder;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::install::disk::{DiskInfo, DiskPrepareResult};
use crate::install::state::InstallScope;
use crate::Result;

const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_LEN: usize = 2 * 1024 * 1024;

/// Wire protocol version. Bump whenever the request/response enums change
/// shape (postcard is positional, so a stale agent binary would otherwise
/// misdecode frames). The client checks this on connect and refuses stale
/// agents with a clear error instead of garbled decode failures.
pub const PROTOCOL_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentRequest {
    Ping,
    DiskScan,
    DiskPrepare {
        disk: String,
    },
    RunCommand {
        program: String,
        args: Vec<String>,
        stdin: Vec<u8>,
    },
    RunCommandEnv {
        program: String,
        args: Vec<String>,
        stdin: Vec<u8>,
        env: Vec<(String, String)>,
    },
    ToolsCheck {
        required: Vec<String>,
        require_passwordless_sudo: bool,
    },
    WriteFile {
        path: String,
        bytes: Vec<u8>,
        mode: Option<u32>,
        create_parent: bool,
    },
    SudoWriteFile {
        path: String,
        bytes: Vec<u8>,
        mode: u32,
        create_parent: bool,
    },
    DiskoApply {
        disko_file: String,
    },
    ConfigCopy {
        source_dir: String,
        role: String,
        install_user: String,
    },
    DotfilesRun {
        dotfiles_repo: String,
        install_user: String,
        github_token: Vec<u8>,
    },
    NetworkRouteCleanup,
    StorageOverwrite {
        vg_name: String,
    },
    ScheduleReboot {
        delay_secs: u64,
    },
    /// Full target introspection: hardware, firmware, disks, LVM, mounts.
    Facts,
    /// Wire protocol handshake; the client refuses mismatched agents.
    ProtocolVersion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentResponse {
    Pong,
    DiskScan { disks: Vec<DiskInfo> },
    DiskPrepare { result: DiskPrepareResult },
    Command { result: CommandResult },
    ToolsCheck { result: ToolsCheckResult },
    WriteFile { result: FileWriteResult },
    RebootScheduled { delay_secs: u64 },
    Error { message: String },
    CommandProgress { stdout: Vec<u8>, stderr: Vec<u8> },
    Facts { facts: crate::facts::TargetFacts },
    ProtocolVersion { version: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandResult {
    pub status: u32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolsCheckResult {
    pub user: Option<String>,
    pub found: Vec<ToolPath>,
    pub missing: Vec<String>,
    pub sudo_ok: Option<bool>,
    pub sudo_stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolPath {
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileWriteResult {
    pub path: String,
    pub bytes_written: u64,
}

pub fn run_stdio() -> Result<u8> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    run(stdin.lock(), stdout.lock())
}

pub fn run<R: Read, W: Write>(mut reader: R, mut writer: W) -> Result<u8> {
    loop {
        let request = match read_frame::<_, AgentRequest>(&mut reader) {
            Ok(Some(request)) => request,
            Ok(None) => break,
            Err(err) => {
                write_frame(
                    &mut writer,
                    &AgentResponse::Error {
                        message: err.clone(),
                    },
                )?;
                return Err(err);
            }
        };

        if let AgentRequest::RunCommand {
            program,
            args,
            stdin,
        } = request
        {
            run_command_streaming(&mut writer, &program, &args, &stdin, &[])?;
            continue;
        }

        if let AgentRequest::RunCommandEnv {
            program,
            args,
            stdin,
            env,
        } = request
        {
            run_command_streaming(&mut writer, &program, &args, &stdin, &env)?;
            continue;
        }

        if let AgentRequest::DotfilesRun {
            dotfiles_repo,
            install_user,
            github_token,
        } = request
        {
            dotfiles_run_streaming(&mut writer, &dotfiles_repo, &install_user, &github_token)?;
            continue;
        }

        let response = handle_request(request);
        write_frame(&mut writer, &response)?;
        writer
            .flush()
            .map_err(|err| format!("failed to flush agent response: {err}"))?;
    }
    Ok(0)
}

fn handle_request(request: AgentRequest) -> AgentResponse {
    match request {
        AgentRequest::Ping => AgentResponse::Pong,
        AgentRequest::DiskScan => match crate::install::disk::discover(InstallScope::Local, "") {
            Ok(disks) => AgentResponse::DiskScan { disks },
            Err(err) => AgentResponse::Error { message: err },
        },
        AgentRequest::DiskPrepare { disk } => match crate::install::disk::local_prepare(&disk) {
            Ok(result) => AgentResponse::DiskPrepare { result },
            Err(err) => AgentResponse::Error { message: err },
        },
        AgentRequest::RunCommand {
            program,
            args,
            stdin,
        } => match run_command(&program, &args, &stdin) {
            Ok(result) => AgentResponse::Command { result },
            Err(err) => AgentResponse::Error { message: err },
        },
        AgentRequest::RunCommandEnv {
            program,
            args,
            stdin,
            env,
        } => match run_command_with_env(&program, &args, &stdin, &env) {
            Ok(result) => AgentResponse::Command { result },
            Err(err) => AgentResponse::Error { message: err },
        },
        AgentRequest::ToolsCheck {
            required,
            require_passwordless_sudo,
        } => match tools_check(&required, require_passwordless_sudo) {
            Ok(result) => AgentResponse::ToolsCheck { result },
            Err(err) => AgentResponse::Error { message: err },
        },
        AgentRequest::WriteFile {
            path,
            bytes,
            mode,
            create_parent,
        } => match write_file(&path, &bytes, mode, create_parent) {
            Ok(result) => AgentResponse::WriteFile { result },
            Err(err) => AgentResponse::Error { message: err },
        },
        AgentRequest::SudoWriteFile {
            path,
            bytes,
            mode,
            create_parent,
        } => match sudo_write_file(&path, &bytes, mode, create_parent) {
            Ok(result) => AgentResponse::WriteFile { result },
            Err(err) => AgentResponse::Error { message: err },
        },
        AgentRequest::DiskoApply { disko_file } => match disko_apply(&disko_file) {
            Ok(result) => AgentResponse::Command { result },
            Err(err) => AgentResponse::Error { message: err },
        },
        AgentRequest::ConfigCopy {
            source_dir,
            role,
            install_user,
        } => match config_copy(&source_dir, &role, &install_user) {
            Ok(result) => AgentResponse::Command { result },
            Err(err) => AgentResponse::Error { message: err },
        },
        AgentRequest::DotfilesRun {
            dotfiles_repo,
            install_user,
            github_token,
        } => match dotfiles_run(&dotfiles_repo, &install_user, &github_token) {
            Ok(result) => AgentResponse::Command { result },
            Err(err) => AgentResponse::Error { message: err },
        },
        AgentRequest::NetworkRouteCleanup => match network_route_cleanup() {
            Ok(result) => AgentResponse::Command { result },
            Err(err) => AgentResponse::Error { message: err },
        },
        AgentRequest::StorageOverwrite { vg_name } => match storage_overwrite(&vg_name) {
            Ok(result) => AgentResponse::Command { result },
            Err(err) => AgentResponse::Error { message: err },
        },
        AgentRequest::ScheduleReboot { delay_secs } => match schedule_reboot(delay_secs) {
            Ok(()) => AgentResponse::RebootScheduled { delay_secs },
            Err(err) => AgentResponse::Error { message: err },
        },
        AgentRequest::Facts => AgentResponse::Facts {
            facts: crate::facts::collect(),
        },
        AgentRequest::ProtocolVersion => AgentResponse::ProtocolVersion {
            version: PROTOCOL_VERSION,
        },
    }
}

fn run_command(program: &str, args: &[String], stdin: &[u8]) -> Result<CommandResult> {
    run_command_with_env(program, args, stdin, &[])
}

fn run_command_with_env(
    program: &str,
    args: &[String],
    stdin: &[u8],
    env_vars: &[(String, String)],
) -> Result<CommandResult> {
    if program.trim().is_empty() {
        return Err("agent command program is empty".to_string());
    }
    if program.contains('\0') || args.iter().any(|arg| arg.contains('\0')) {
        return Err("agent command contains invalid NUL byte".to_string());
    }
    validate_env_vars(env_vars)?;

    let mut command = Command::new(program);
    command.args(args);
    for (key, value) in env_vars {
        command.env(key, value);
    }

    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn agent command {program}: {err}"))?;

    if !stdin.is_empty() {
        let child_stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "failed to open agent command stdin".to_string())?;
        child_stdin
            .write_all(stdin)
            .map_err(|err| format!("failed to write agent command stdin: {err}"))?;
    }
    drop(child.stdin.take());

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait for agent command {program}: {err}"))?;
    Ok(CommandResult {
        status: output.status.code().unwrap_or(1) as u32,
        stdout: truncate_command_output(output.stdout, "stdout"),
        stderr: truncate_command_output(output.stderr, "stderr"),
    })
}

fn run_command_streaming<W: Write>(
    writer: &mut W,
    program: &str,
    args: &[String],
    stdin: &[u8],
    env_vars: &[(String, String)],
) -> Result<()> {
    match run_command_streaming_inner(writer, program, args, stdin, env_vars) {
        Ok(result) => {
            write_frame(writer, &AgentResponse::Command { result })?;
            writer
                .flush()
                .map_err(|err| format!("failed to flush agent command response: {err}"))
        }
        Err(err) => {
            write_frame(
                writer,
                &AgentResponse::Error {
                    message: err.clone(),
                },
            )?;
            writer.flush().map_err(|flush_err| {
                format!("failed to flush agent error response: {flush_err}")
            })?;
            Err(err)
        }
    }
}

fn run_command_streaming_inner<W: Write>(
    writer: &mut W,
    program: &str,
    args: &[String],
    stdin: &[u8],
    env_vars: &[(String, String)],
) -> Result<CommandResult> {
    if program.trim().is_empty() {
        return Err("agent command program is empty".to_string());
    }
    if program.contains('\0') || args.iter().any(|arg| arg.contains('\0')) {
        return Err("agent command contains invalid NUL byte".to_string());
    }
    validate_env_vars(env_vars)?;

    let mut command = Command::new(program);
    command.args(args);
    for (key, value) in env_vars {
        command.env(key, value);
    }

    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn agent command {program}: {err}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to open agent command stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to open agent command stderr".to_string())?;

    let (tx, rx) = mpsc::channel();
    spawn_command_reader(stdout, CommandStream::Stdout, tx.clone());
    spawn_command_reader(stderr, CommandStream::Stderr, tx);

    if !stdin.is_empty() {
        let child_stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "failed to open agent command stdin".to_string())?;
        child_stdin
            .write_all(stdin)
            .map_err(|err| format!("failed to write agent command stdin: {err}"))?;
    }
    drop(child.stdin.take());

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut readers_done = 0usize;
    let mut exit_status = None;

    while exit_status.is_none() || readers_done < 2 {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(CommandEvent::Chunk(stream, bytes)) => {
                match stream {
                    CommandStream::Stdout => {
                        stdout.extend_from_slice(&bytes);
                        write_frame(
                            writer,
                            &AgentResponse::CommandProgress {
                                stdout: bytes,
                                stderr: Vec::new(),
                            },
                        )?;
                    }
                    CommandStream::Stderr => {
                        stderr.extend_from_slice(&bytes);
                        write_frame(
                            writer,
                            &AgentResponse::CommandProgress {
                                stdout: Vec::new(),
                                stderr: bytes,
                            },
                        )?;
                    }
                }
                writer
                    .flush()
                    .map_err(|err| format!("failed to flush agent progress response: {err}"))?;
            }
            Ok(CommandEvent::ReaderDone) => readers_done += 1,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        if exit_status.is_none() {
            if let Some(status) = child
                .try_wait()
                .map_err(|err| format!("failed to poll agent command {program}: {err}"))?
            {
                exit_status = Some(status.code().unwrap_or(1) as u32);
            }
        }
    }

    let status = match exit_status {
        Some(status) => status,
        None => child
            .wait()
            .map_err(|err| format!("failed to wait for agent command {program}: {err}"))?
            .code()
            .unwrap_or(1) as u32,
    };

    Ok(CommandResult {
        status,
        stdout: truncate_command_output(stdout, "stdout"),
        stderr: truncate_command_output(stderr, "stderr"),
    })
}

fn validate_env_vars(env_vars: &[(String, String)]) -> Result<()> {
    for (key, value) in env_vars {
        if key.is_empty() || key.contains('=') || key.contains('\0') {
            return Err(format!("invalid environment variable name: {key:?}"));
        }
        if value.contains('\0') {
            return Err(format!(
                "environment variable {key} contains invalid NUL byte"
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum CommandStream {
    Stdout,
    Stderr,
}

enum CommandEvent {
    Chunk(CommandStream, Vec<u8>),
    ReaderDone,
}

fn spawn_command_reader<R>(mut reader: R, stream: CommandStream, tx: mpsc::Sender<CommandEvent>)
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buffer = [0u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if tx
                        .send(CommandEvent::Chunk(stream, buffer[..n].to_vec()))
                        .is_err()
                    {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = tx.send(CommandEvent::ReaderDone);
    });
}

fn truncate_command_output(mut bytes: Vec<u8>, stream_name: &str) -> Vec<u8> {
    if bytes.len() <= MAX_COMMAND_OUTPUT_LEN {
        return bytes;
    }

    let omitted = bytes.len() - MAX_COMMAND_OUTPUT_LEN;
    let mut truncated =
        format!("[nox: truncated {omitted} bytes from {stream_name}; showing tail]\n")
            .into_bytes();
    let tail = bytes.split_off(omitted);
    truncated.extend(tail);
    truncated
}

fn tools_check(required: &[String], require_passwordless_sudo: bool) -> Result<ToolsCheckResult> {
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for name in required {
        validate_tool_name(name)?;
        match find_in_path(name) {
            Some(path) => found.push(ToolPath {
                name: name.clone(),
                path: path.display().to_string(),
            }),
            None => missing.push(name.clone()),
        }
    }

    let user = run_command("id", &["-un".to_string()], &[])
        .ok()
        .filter(|result| result.status == 0)
        .map(|result| String::from_utf8_lossy(&result.stdout).trim().to_string())
        .filter(|value| !value.is_empty());

    let (sudo_ok, sudo_stderr) = if require_passwordless_sudo {
        match run_command("sudo", &["-n".to_string(), "true".to_string()], &[]) {
            Ok(result) => (
                Some(result.status == 0),
                String::from_utf8_lossy(&result.stderr).trim().to_string(),
            ),
            Err(err) => (Some(false), err),
        }
    } else {
        (None, String::new())
    };

    Ok(ToolsCheckResult {
        user,
        found,
        missing,
        sudo_ok,
        sudo_stderr,
    })
}

fn validate_tool_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err("tool name is empty".to_string());
    }
    if name.contains('/') || name.contains('\0') {
        return Err(format!("invalid tool name: {name}"));
    }
    Ok(())
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn write_file(
    path: &str,
    bytes: &[u8],
    mode: Option<u32>,
    create_parent: bool,
) -> Result<FileWriteResult> {
    let path = validate_write_path(path)?;
    if create_parent {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
        }
    }

    fs::write(&path, bytes).map_err(|err| format!("failed to write {}: {err}", path.display()))?;

    #[cfg(unix)]
    if let Some(mode) = mode {
        if mode > 0o7777 {
            return Err(format!("invalid file mode: {mode:o}"));
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .map_err(|err| format!("failed to chmod {}: {err}", path.display()))?;
    }

    Ok(FileWriteResult {
        path: path.display().to_string(),
        bytes_written: bytes.len() as u64,
    })
}

pub(crate) fn sudo_write_file(
    path: &str,
    bytes: &[u8],
    mode: u32,
    create_parent: bool,
) -> Result<FileWriteResult> {
    let path = validate_write_path(path)?;
    if mode > 0o7777 {
        return Err(format!("invalid file mode: {mode:o}"));
    }

    let temp_path = env::temp_dir().join(format!(
        "nox-sudo-write-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    fs::write(&temp_path, bytes)
        .map_err(|err| format!("failed to write temp file {}: {err}", temp_path.display()))?;
    #[cfg(unix)]
    fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("failed to chmod temp file {}: {err}", temp_path.display()))?;

    let result = (|| {
        if create_parent {
            if let Some(parent) = path.parent() {
                run_status(
                    "sudo",
                    &[
                        "--non-interactive",
                        "install",
                        "-d",
                        "-m",
                        "0755",
                        &parent.display().to_string(),
                    ],
                )?;
            }
        }

        run_status(
            "sudo",
            &[
                "--non-interactive",
                "install",
                "-m",
                &format!("{mode:o}"),
                &temp_path.display().to_string(),
                &path.display().to_string(),
            ],
        )
    })();

    let _ = fs::remove_file(&temp_path);
    result?;

    Ok(FileWriteResult {
        path: path.display().to_string(),
        bytes_written: bytes.len() as u64,
    })
}

pub(crate) fn disko_apply(disko_file: &str) -> Result<CommandResult> {
    let path = validate_write_path(disko_file)?;
    if !command_exists("disko") {
        return Err(
            "disko executable is missing from the nox agent PATH; rebuild the agent closure"
                .to_string(),
        );
    }

    run_command(
        "sudo",
        &[
            "--non-interactive".to_string(),
            "disko".to_string(),
            "--mode".to_string(),
            "disko".to_string(),
            path.display().to_string(),
        ],
        &[],
    )
}

pub(crate) fn network_route_cleanup() -> Result<CommandResult> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| format!("failed to build netlink runtime: {err}"))?;
    runtime.block_on(network_route_cleanup_async())
}

async fn network_route_cleanup_async() -> Result<CommandResult> {
    let (client_ip, server_ip) = ssh_connection_ips();
    let (connection, handle, _) =
        rtnetlink::new_connection().map_err(|err| format!("failed to open netlink: {err}"))?;
    tokio::spawn(connection);

    let links = collect_links(&handle).await?;
    let preferred_ifindex = if let Some(server_ip) = server_ip {
        interface_for_local_ip(&handle, server_ip).await?
    } else {
        None
    }
    .or_else(|| None);

    let preferred_ifindex = match preferred_ifindex {
        Some(index) => Some(index),
        None => match client_ip {
            Some(IpAddr::V4(client_ip)) => interface_for_route_to(&handle, client_ip).await?,
            Some(IpAddr::V6(_)) | None => None,
        },
    };

    let Some(preferred_ifindex) = preferred_ifindex else {
        let mut stdout =
            "network route cleanup skipped: could not infer SSH interface\n".to_string();
        stdout.push_str(&describe_default_routes(&handle, &links).await?);
        return Ok(CommandResult {
            status: 0,
            stdout: stdout.into_bytes(),
            stderr: Vec::new(),
        });
    };

    let preferred_dev = links
        .iter()
        .find_map(|(index, name)| (*index == preferred_ifindex).then(|| name.clone()))
        .unwrap_or_else(|| preferred_ifindex.to_string());

    let mut defaults = default_routes(&handle).await?;
    let mut deleted = 0usize;
    let mut stderr = Vec::new();
    for route in defaults.clone() {
        let Some(oif) = route_oif(&route) else {
            continue;
        };
        if oif == preferred_ifindex {
            continue;
        }

        match handle.route().del(route.clone()).execute().await {
            Ok(()) => deleted += 1,
            Err(err) => {
                let dev = links
                    .iter()
                    .find_map(|(index, name)| (*index == oif).then(|| name.as_str()))
                    .unwrap_or("");
                if dev.is_empty() {
                    return Err(format!(
                        "failed to delete competing default route for ifindex {oif}: {err}"
                    ));
                }
                fallback_delete_default_route(dev, route_gateway_v4(&route))?;
                deleted += 1;
                stderr.extend_from_slice(
                    format!("netlink route delete failed, used sudo ip fallback: {err}\n")
                        .as_bytes(),
                );
            }
        }
    }

    defaults = default_routes(&handle).await?;
    let mut stdout = format!(
        "preferred default route interface: {preferred_dev}\nremoved competing default routes: {deleted}\n"
    );
    stdout.push_str(&format_default_routes(&defaults, &links));
    Ok(CommandResult {
        status: 0,
        stdout: stdout.into_bytes(),
        stderr,
    })
}

fn ssh_connection_ips() -> (Option<IpAddr>, Option<IpAddr>) {
    let Ok(value) = env::var("SSH_CONNECTION") else {
        return (None, None);
    };
    let fields = value.split_whitespace().collect::<Vec<_>>();
    let client_ip = fields.first().and_then(|value| value.parse().ok());
    let server_ip = fields.get(2).and_then(|value| value.parse().ok());
    (client_ip, server_ip)
}

async fn collect_links(handle: &rtnetlink::Handle) -> Result<Vec<(u32, String)>> {
    let mut stream = handle.link().get().execute();
    let mut links = Vec::new();
    while let Some(message) = stream
        .try_next()
        .await
        .map_err(|err| format!("failed to list links: {err}"))?
    {
        if let Some(name) = link_name(&message) {
            links.push((message.header.index, name));
        }
    }
    Ok(links)
}

async fn interface_for_local_ip(handle: &rtnetlink::Handle, ip: IpAddr) -> Result<Option<u32>> {
    let mut stream = handle.address().get().execute();
    while let Some(message) = stream
        .try_next()
        .await
        .map_err(|err| format!("failed to list interface addresses: {err}"))?
    {
        if address_has_ip(&message, ip) {
            return Ok(Some(message.header.index));
        }
    }
    Ok(None)
}

async fn interface_for_route_to(handle: &rtnetlink::Handle, ip: Ipv4Addr) -> Result<Option<u32>> {
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(ip, 32)
        .build();
    let mut stream = handle.route().get(route).execute();
    while let Some(message) = stream
        .try_next()
        .await
        .map_err(|err| format!("failed to get route to SSH client: {err}"))?
    {
        if let Some(oif) = route_oif(&message) {
            return Ok(Some(oif));
        }
    }
    Ok(None)
}

async fn default_routes(handle: &rtnetlink::Handle) -> Result<Vec<RouteMessage>> {
    let route = RouteMessageBuilder::<Ipv4Addr>::new().build();
    let mut stream = handle.route().get(route).execute();
    let mut routes = Vec::new();
    while let Some(message) = stream
        .try_next()
        .await
        .map_err(|err| format!("failed to list default routes: {err}"))?
    {
        if is_default_ipv4_route(&message) {
            routes.push(message);
        }
    }
    Ok(routes)
}

async fn describe_default_routes(
    handle: &rtnetlink::Handle,
    links: &[(u32, String)],
) -> Result<String> {
    let routes = default_routes(handle).await?;
    Ok(format_default_routes(&routes, links))
}

fn link_name(message: &LinkMessage) -> Option<String> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::IfName(name) => Some(name.clone()),
            _ => None,
        })
}

fn address_has_ip(message: &AddressMessage, ip: IpAddr) -> bool {
    message.attributes.iter().any(|attribute| match attribute {
        AddressAttribute::Address(value) | AddressAttribute::Local(value) => *value == ip,
        _ => false,
    })
}

fn is_default_ipv4_route(route: &RouteMessage) -> bool {
    route.header.address_family == AddressFamily::Inet
        && route.header.destination_prefix_length == 0
        && route.header.table == RouteHeader::RT_TABLE_MAIN
        && !route
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, RouteAttribute::Destination(_)))
}

fn route_oif(route: &RouteMessage) -> Option<u32> {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Oif(index) => Some(*index),
            _ => None,
        })
}

fn route_gateway_v4(route: &RouteMessage) -> Option<Ipv4Addr> {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Gateway(RouteAddress::Inet(gateway)) => Some(*gateway),
            _ => None,
        })
}

fn format_default_routes(routes: &[RouteMessage], links: &[(u32, String)]) -> String {
    if routes.is_empty() {
        return "default routes: none\n".to_string();
    }

    let mut output = String::from("default routes:\n");
    for route in routes {
        let dev = route_oif(route)
            .and_then(|oif| {
                links
                    .iter()
                    .find_map(|(index, name)| (*index == oif).then(|| name.as_str()))
            })
            .unwrap_or("unknown");
        match route_gateway_v4(route) {
            Some(gateway) => output.push_str(&format!("  default via {gateway} dev {dev}\n")),
            None => output.push_str(&format!("  default dev {dev}\n")),
        }
    }
    output
}

fn fallback_delete_default_route(dev: &str, gateway: Option<Ipv4Addr>) -> Result<()> {
    let mut args = vec!["--non-interactive", "ip", "route", "del", "default"];
    let gateway_string;
    if let Some(gateway) = gateway {
        gateway_string = gateway.to_string();
        args.push("via");
        args.push(&gateway_string);
    }
    args.push("dev");
    args.push(dev);
    run_status("sudo", &args)
}

pub(crate) fn storage_overwrite(vg_name: &str) -> Result<CommandResult> {
    validate_volume_group_name(vg_name)?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    append_ignored_command(
        &mut stdout,
        &mut stderr,
        "unmount /mnt",
        "sudo",
        &["--non-interactive", "umount", "-R", "/mnt"],
    );
    append_ignored_command(
        &mut stdout,
        &mut stderr,
        "disable swap",
        "sudo",
        &["--non-interactive", "swapoff", "--all"],
    );

    if command_exists("vgchange") {
        append_ignored_command(
            &mut stdout,
            &mut stderr,
            "deactivate volume group",
            "sudo",
            &["--non-interactive", "vgchange", "-an", vg_name],
        );
    }

    if command_exists("vgs") && command_exists("vgremove") {
        let vgs = run_command(
            "sudo",
            &[
                "--non-interactive".to_string(),
                "vgs".to_string(),
                "--noheadings".to_string(),
                "-o".to_string(),
                "vg_name".to_string(),
                vg_name.to_string(),
            ],
            &[],
        )?;
        if vgs.status == 0 {
            let removed = run_command(
                "sudo",
                &[
                    "--non-interactive".to_string(),
                    "vgremove".to_string(),
                    "-ff".to_string(),
                    "-y".to_string(),
                    vg_name.to_string(),
                ],
                &[],
            )?;
            stdout.extend_from_slice(&removed.stdout);
            stderr.extend_from_slice(&removed.stderr);
            if removed.status != 0 {
                return Ok(CommandResult {
                    status: removed.status,
                    stdout,
                    stderr,
                });
            }
            stdout.extend_from_slice(
                format!("removed existing volume group: {vg_name}\n").as_bytes(),
            );
        } else {
            stdout.extend_from_slice(
                format!("no existing volume group found: {vg_name}\n").as_bytes(),
            );
        }
    } else {
        stdout.extend_from_slice(b"lvm tools not available; skipping volume group removal\n");
    }

    if command_exists("udevadm") {
        append_ignored_command(
            &mut stdout,
            &mut stderr,
            "settle udev",
            "sudo",
            &["--non-interactive", "udevadm", "settle"],
        );
    }

    Ok(CommandResult {
        status: 0,
        stdout,
        stderr,
    })
}

fn append_ignored_command(
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    label: &str,
    program: &str,
    args: &[&str],
) {
    let args = args
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    match run_command(program, &args, &[]) {
        Ok(result) => {
            if result.status != 0 {
                stdout.extend_from_slice(
                    format!("{label}: ignored exit status {}\n", result.status).as_bytes(),
                );
            }
            stdout.extend_from_slice(&result.stdout);
            stderr.extend_from_slice(&result.stderr);
        }
        Err(err) => {
            stdout.extend_from_slice(format!("{label}: skipped: {err}\n").as_bytes());
        }
    }
}

fn validate_volume_group_name(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err("volume group name is empty".to_string());
    }
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.')
    {
        Ok(())
    } else {
        Err(format!("invalid volume group name: {value}"))
    }
}

fn command_exists(name: &str) -> bool {
    find_in_path(name).is_some()
}

pub(crate) fn config_copy(source_dir: &str, role: &str, install_user: &str) -> Result<CommandResult> {
    let source_dir = validate_existing_dir(source_dir, "config-copy source dir")?;
    validate_role(role)?;
    validate_install_user(install_user)?;

    let dest = PathBuf::from("/mnt/etc/nixos");
    let mnt_etc = PathBuf::from("/mnt/etc");
    if !mnt_etc.is_dir() {
        return Err("installed system is not mounted at /mnt".to_string());
    }

    let uid = getuid().as_raw().to_string();
    let gid = getgid().as_raw().to_string();
    run_status(
        "sudo",
        &["--non-interactive", "rm", "-rf", "/mnt/etc/nixos"],
    )?;
    run_status(
        "sudo",
        &[
            "--non-interactive",
            "install",
            "-d",
            "-m",
            "0755",
            "-o",
            &uid,
            "-g",
            &gid,
            "/mnt/etc/nixos",
        ],
    )?;

    let mut copied = 0usize;
    let mut skipped = 0usize;
    for entry in WalkDir::new(&source_dir).follow_links(false) {
        let entry = entry.map_err(|err| format!("failed to walk source config: {err}"))?;
        let src = entry.path();
        let rel = src
            .strip_prefix(&source_dir)
            .map_err(|err| format!("failed to calculate relative path: {err}"))?;
        if rel.as_os_str().is_empty() {
            continue;
        }
        if should_skip_config_path(rel) {
            skipped += 1;
            continue;
        }

        let target = dest.join(rel);
        let metadata = fs::symlink_metadata(src)
            .map_err(|err| format!("failed to stat {}: {err}", src.display()))?;
        if metadata.is_dir() {
            fs::create_dir_all(&target)
                .map_err(|err| format!("failed to create {}: {err}", target.display()))?;
            copied += 1;
            continue;
        }

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
        }

        if metadata.file_type().is_symlink() {
            let link_target = fs::read_link(src)
                .map_err(|err| format!("failed to read symlink {}: {err}", src.display()))?;
            #[cfg(unix)]
            symlink(&link_target, &target)
                .map_err(|err| format!("failed to symlink {}: {err}", target.display()))?;
            #[cfg(not(unix))]
            return Err("config-copy symlink support requires unix".to_string());
        } else if metadata.is_file() {
            let mut bytes =
                fs::read(src).map_err(|err| format!("failed to read {}: {err}", src.display()))?;
            if rel == Path::new(".git/config") {
                let text = String::from_utf8_lossy(&bytes).replace(
                    "git@github.com:bresilla/nixos.git",
                    "https://github.com/bresilla/nixos.git",
                );
                bytes = text.into_bytes();
            }
            fs::write(&target, bytes)
                .map_err(|err| format!("failed to write {}: {err}", target.display()))?;
            #[cfg(unix)]
            fs::set_permissions(
                &target,
                fs::Permissions::from_mode(metadata.permissions().mode()),
            )
            .map_err(|err| format!("failed to chmod {}: {err}", target.display()))?;
        }
        copied += 1;
    }

    fs::write(dest.join("host/.nixos-role"), format!("{role}\n"))
        .map_err(|err| format!("failed to write .nixos-role: {err}"))?;

    let specific_dir = dest.join("host/specific");
    fs::create_dir_all(&specific_dir)
        .map_err(|err| format!("failed to create {}: {err}", specific_dir.display()))?;
    let specific_config = specific_dir.join("configuration.nix");
    if !specific_config.exists() {
        fs::write(&specific_config, DEFAULT_SPECIFIC_CONFIG)
            .map_err(|err| format!("failed to write {}: {err}", specific_config.display()))?;
    }

    set_config_tree_modes(&dest)?;

    let corner_gid = group_id_from_file(Path::new("/mnt/etc/group"), "corner")?;
    run_status(
        "sudo",
        &[
            "--non-interactive",
            "chown",
            "-R",
            &format!("0:{corner_gid}"),
            "/mnt/etc/nixos",
        ],
    )?;

    ensure_user_gitconfig(install_user)?;

    Ok(CommandResult {
        status: 0,
        stdout: format!(
            "copied config repo to /mnt/etc/nixos\ncopied entries: {copied}\nskipped entries: {skipped}\nrole: {role}"
        )
        .into_bytes(),
        stderr: Vec::new(),
    })
}

const DEFAULT_SPECIFIC_CONFIG: &str = r#"{ ... }:

{
  # Host-specific local overrides go here.
}
"#;

fn validate_existing_dir(path: &str, label: &str) -> Result<PathBuf> {
    let path = validate_write_path(path)?;
    if !path.is_dir() {
        return Err(format!("{label} missing: {}", path.display()));
    }
    Ok(path)
}

fn validate_role(role: &str) -> Result<()> {
    match role {
        "laptop" | "server" => Ok(()),
        _ => Err(format!("role must be laptop or server: {role}")),
    }
}

fn validate_install_user(value: &str) -> Result<()> {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err("install user is empty".to_string());
    };
    if !(first.is_ascii_lowercase() || first == '_') {
        return Err(format!("invalid install user: {value}"));
    }
    if chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-') {
        Ok(())
    } else {
        Err(format!("invalid install user: {value}"))
    }
}

fn should_skip_config_path(path: &Path) -> bool {
    path.starts_with("specific") || path == Path::new("secrets/key.txt")
}

fn set_config_tree_modes(dest: &Path) -> Result<()> {
    for entry in WalkDir::new(dest).follow_links(false) {
        let entry = entry.map_err(|err| format!("failed to walk copied config: {err}"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(path)
            .map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        #[cfg(unix)]
        {
            let mode = if metadata.is_dir() {
                0o2775
            } else {
                let executable = metadata.permissions().mode() & 0o111 != 0;
                if executable {
                    0o775
                } else {
                    0o664
                }
            };
            fs::set_permissions(path, fs::Permissions::from_mode(mode))
                .map_err(|err| format!("failed to chmod {}: {err}", path.display()))?;
        }
    }
    Ok(())
}

fn group_id_from_file(path: &Path, group: &str) -> Result<u32> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    for line in content.lines() {
        let mut fields = line.split(':');
        let Some(name) = fields.next() else { continue };
        let _password = fields.next();
        let Some(gid) = fields.next() else { continue };
        if name == group {
            return gid
                .parse::<u32>()
                .map_err(|err| format!("invalid gid for group {group}: {err}"));
        }
    }
    Err(format!(
        "could not find target group in {}: {group}",
        path.display()
    ))
}

fn user_ids_from_file(path: &Path, user: &str) -> Result<Option<(u32, u32)>> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    for line in content.lines() {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() >= 4 && fields[0] == user {
            let uid = fields[2]
                .parse::<u32>()
                .map_err(|err| format!("invalid uid for user {user}: {err}"))?;
            let gid = fields[3]
                .parse::<u32>()
                .map_err(|err| format!("invalid gid for user {user}: {err}"))?;
            return Ok(Some((uid, gid)));
        }
    }
    Ok(None)
}

fn ensure_user_gitconfig(install_user: &str) -> Result<()> {
    let home = PathBuf::from("/mnt/home").join(install_user);
    if !home.is_dir() {
        return Ok(());
    }
    let gitconfig = home.join(".gitconfig");
    let safe_block = "[safe]\n\tdirectory = /etc/nixos\n";
    let mut content = fs::read_to_string(&gitconfig).unwrap_or_default();
    if !content
        .lines()
        .any(|line| line.trim() == "directory = /etc/nixos")
    {
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(safe_block);
        fs::write(&gitconfig, content)
            .map_err(|err| format!("failed to write {}: {err}", gitconfig.display()))?;
    }

    if let Some((uid, gid)) = user_ids_from_file(Path::new("/mnt/etc/passwd"), install_user)? {
        run_status(
            "sudo",
            &[
                "--non-interactive",
                "chown",
                &format!("{uid}:{gid}"),
                &gitconfig.display().to_string(),
            ],
        )?;
    }
    Ok(())
}

fn dotfiles_run(
    _dotfiles_repo: &str,
    _install_user: &str,
    _github_token: &[u8],
) -> Result<CommandResult> {
    Err("dotfiles-run requires the streaming agent path".to_string())
}

pub(crate) fn dotfiles_run_streaming<W: Write>(
    writer: &mut W,
    dotfiles_repo: &str,
    install_user: &str,
    github_token: &[u8],
) -> Result<()> {
    match dotfiles_run_streaming_inner(writer, dotfiles_repo, install_user, github_token) {
        Ok(result) => {
            write_frame(writer, &AgentResponse::Command { result })?;
            writer
                .flush()
                .map_err(|err| format!("failed to flush dotfiles-run response: {err}"))
        }
        Err(err) => {
            write_frame(
                writer,
                &AgentResponse::Error {
                    message: err.clone(),
                },
            )?;
            writer
                .flush()
                .map_err(|flush_err| format!("failed to flush dotfiles-run error: {flush_err}"))?;
            Err(err)
        }
    }
}

fn dotfiles_run_streaming_inner<W: Write>(
    writer: &mut W,
    dotfiles_repo: &str,
    install_user: &str,
    github_token: &[u8],
) -> Result<CommandResult> {
    validate_dotfiles_repo(dotfiles_repo)?;
    validate_install_user(install_user)?;
    validate_installed_mount()?;

    let github_token = String::from_utf8(github_token.to_vec())
        .map_err(|err| format!("GitHub token is not valid UTF-8: {err}"))?;

    let temp_dir = env::temp_dir().join(format!(
        "nox-dotfiles-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    fs::create_dir(&temp_dir)
        .map_err(|err| format!("failed to create {}: {err}", temp_dir.display()))?;

    let result = (|| {
        emit_stdout_progress(writer, &format!("Cloning dotfiles repo: {dotfiles_repo}\n"))?;
        let checkout = temp_dir.join("dotfiles");
        let clone_result = run_command_streaming_inner(
            writer,
            "git",
            &[
                "clone".to_string(),
                "--recursive".to_string(),
                dotfiles_repo.to_string(),
                checkout.display().to_string(),
            ],
            &[],
            &[],
        )?;
        if clone_result.status != 0 {
            return Err(format!(
                "dotfiles git clone failed with exit code {}",
                clone_result.status
            ));
        }

        let run_me = checkout.join("run_me.sh");
        if !run_me.is_file() {
            return Err("dotfiles checkout missing run_me.sh".to_string());
        }
        #[cfg(unix)]
        fs::set_permissions(&run_me, fs::Permissions::from_mode(0o755))
            .map_err(|err| format!("failed to chmod {}: {err}", run_me.display()))?;

        let home_dir = PathBuf::from("/mnt/home").join(install_user);
        if !home_dir.is_dir() {
            return Err(format!(
                "installed user home is missing: {}",
                home_dir.display()
            ));
        }
        let dot_dir = home_dir.join(".dot");
        let agent_uid = getuid().as_raw().to_string();
        let agent_gid = getgid().as_raw().to_string();

        emit_stdout_progress(
            writer,
            &format!("Copying dotfiles into {}\n", dot_dir.display()),
        )?;
        run_status(
            "sudo",
            &[
                "--non-interactive",
                "rm",
                "-rf",
                &dot_dir.display().to_string(),
            ],
        )?;
        run_status(
            "sudo",
            &[
                "--non-interactive",
                "install",
                "-d",
                "-m",
                "0755",
                "-o",
                &agent_uid,
                "-g",
                &agent_gid,
                &dot_dir.display().to_string(),
            ],
        )?;
        copy_tree_contents(&checkout, &dot_dir)?;

        let sudo_shim = prepare_chroot_sudo_shim(&agent_uid, &agent_gid)?;
        let sudo_shim_dir = sudo_shim
            .parent()
            .ok_or_else(|| "sudo shim path has no parent".to_string())?;
        let token_env = github_token_env_args(&github_token);
        let path_env = format!(
            "PATH={}:{}",
            sudo_shim_dir.display(),
            "/nix/var/nix/profiles/system/sw/bin:/usr/local/bin:/bin:/usr/bin"
        );
        let chroot_run = format!(
            "cd /home/{}/.dot && exec /nix/var/nix/profiles/system/sw/bin/bash ./run_me.sh",
            install_user
        );
        let mut args = vec![
            "--non-interactive".to_string(),
            "chroot".to_string(),
            "/mnt".to_string(),
            "/nix/var/nix/profiles/system/sw/bin/env".to_string(),
            path_env,
            format!("HOME=/home/{install_user}"),
            format!("USER={install_user}"),
            format!("LOGNAME={install_user}"),
        ];
        args.extend(token_env);
        args.extend([
            "/nix/var/nix/profiles/system/sw/bin/bash".to_string(),
            "-lc".to_string(),
            chroot_run,
        ]);

        emit_stdout_progress(
            writer,
            "Running dotfiles ./run_me.sh inside installed system chroot\n",
        )?;
        let run_result = run_command_streaming_inner(writer, "sudo", &args, &[], &[])?;
        let ownership_result = fix_installed_user_ownership(install_user);
        if let Err(err) = ownership_result {
            return Err(format!("dotfiles ownership repair failed: {err}"));
        }
        if run_result.status != 0 {
            return Err(format!(
                "dotfiles run_me.sh failed with exit code {}",
                run_result.status
            ));
        }

        Ok(CommandResult {
            status: 0,
            stdout: b"dotfiles: ok\n".to_vec(),
            stderr: Vec::new(),
        })
    })();

    let _ = fs::remove_dir_all(&temp_dir);
    result
}

fn validate_dotfiles_repo(value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err("dotfiles repo is empty".to_string());
    }
    if value.contains('\0') || value.contains(char::is_whitespace) || value.starts_with('-') {
        return Err(format!("invalid dotfiles repo: {value}"));
    }
    Ok(())
}

fn validate_installed_mount() -> Result<()> {
    if Path::new("/mnt/nix/var/nix/profiles").is_dir() {
        Ok(())
    } else {
        Err("installed system is not mounted at /mnt".to_string())
    }
}

fn copy_tree_contents(source: &Path, dest: &Path) -> Result<()> {
    for entry in WalkDir::new(source).follow_links(false) {
        let entry = entry.map_err(|err| format!("failed to walk dotfiles checkout: {err}"))?;
        let src = entry.path();
        let rel = src
            .strip_prefix(source)
            .map_err(|err| format!("failed to calculate dotfiles relative path: {err}"))?;
        if rel.as_os_str().is_empty() {
            continue;
        }

        let target = dest.join(rel);
        let metadata = fs::symlink_metadata(src)
            .map_err(|err| format!("failed to stat {}: {err}", src.display()))?;
        if metadata.is_dir() {
            fs::create_dir_all(&target)
                .map_err(|err| format!("failed to create {}: {err}", target.display()))?;
            #[cfg(unix)]
            fs::set_permissions(
                &target,
                fs::Permissions::from_mode(metadata.permissions().mode()),
            )
            .map_err(|err| format!("failed to chmod {}: {err}", target.display()))?;
            continue;
        }

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
        }

        if metadata.file_type().is_symlink() {
            let link_target = fs::read_link(src)
                .map_err(|err| format!("failed to read symlink {}: {err}", src.display()))?;
            #[cfg(unix)]
            symlink(&link_target, &target)
                .map_err(|err| format!("failed to symlink {}: {err}", target.display()))?;
            #[cfg(not(unix))]
            return Err("dotfiles symlink support requires unix".to_string());
        } else if metadata.is_file() {
            fs::copy(src, &target)
                .map_err(|err| format!("failed to copy {}: {err}", src.display()))?;
            #[cfg(unix)]
            fs::set_permissions(
                &target,
                fs::Permissions::from_mode(metadata.permissions().mode()),
            )
            .map_err(|err| format!("failed to chmod {}: {err}", target.display()))?;
        }
    }
    Ok(())
}

fn prepare_chroot_sudo_shim(agent_uid: &str, agent_gid: &str) -> Result<PathBuf> {
    run_status(
        "sudo",
        &[
            "--non-interactive",
            "install",
            "-d",
            "-m",
            "1777",
            "/mnt/tmp",
        ],
    )?;
    let shim_dir = Path::new("/mnt/tmp/nixos-install-sudo-shim");
    run_status(
        "sudo",
        &[
            "--non-interactive",
            "install",
            "-d",
            "-m",
            "0755",
            "-o",
            agent_uid,
            "-g",
            agent_gid,
            &shim_dir.display().to_string(),
        ],
    )?;
    let shim = shim_dir.join("sudo");
    fs::write(&shim, SUDO_SHIM)
        .map_err(|err| format!("failed to write sudo shim {}: {err}", shim.display()))?;
    #[cfg(unix)]
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755))
        .map_err(|err| format!("failed to chmod sudo shim {}: {err}", shim.display()))?;
    Ok(shim)
}

const SUDO_SHIM: &str = r#"#!/usr/bin/env bash
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -n | --non-interactive | -E | -H) shift ;;
    --) shift; break ;;
    -*) shift ;;
    *) break ;;
  esac
done
exec "$@"
"#;

fn github_token_env_args(token: &str) -> Vec<String> {
    if token.is_empty() {
        Vec::new()
    } else {
        vec![
            format!("GITHUB_TOKEN={token}"),
            format!("GITHUB_AUTH_TOKEN={token}"),
        ]
    }
}

fn fix_installed_user_ownership(install_user: &str) -> Result<()> {
    let Some((uid, gid)) = user_ids_from_file(Path::new("/mnt/etc/passwd"), install_user)? else {
        return Err(format!(
            "installed user is missing from /mnt/etc/passwd: {install_user}"
        ));
    };
    let owner = format!("{uid}:{gid}");
    let home = PathBuf::from("/mnt/home").join(install_user);
    let paths = [
        home.join(".dot"),
        home.join(".local"),
        home.join(".config"),
        home.join(".zshenv"),
        home.join(".profile"),
        home.join(".winitrc"),
    ];

    for path in paths {
        if fs::symlink_metadata(&path).is_ok() {
            run_status(
                "sudo",
                &[
                    "--non-interactive",
                    "chown",
                    "-R",
                    "-h",
                    &owner,
                    &path.display().to_string(),
                ],
            )?;
        }
    }
    Ok(())
}

fn emit_stdout_progress<W: Write>(writer: &mut W, message: &str) -> Result<()> {
    write_frame(
        writer,
        &AgentResponse::CommandProgress {
            stdout: message.as_bytes().to_vec(),
            stderr: Vec::new(),
        },
    )?;
    writer
        .flush()
        .map_err(|err| format!("failed to flush progress response: {err}"))
}

pub(crate) fn schedule_reboot(delay_secs: u64) -> Result<()> {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(delay_secs));
        let _ = Command::new("sync").status();
        let status = Command::new("sudo")
            .arg("--non-interactive")
            .arg("systemctl")
            .arg("reboot")
            .arg("--force")
            .status();
        if !matches!(status, Ok(status) if status.success()) {
            let _ = Command::new("sudo")
                .arg("--non-interactive")
                .arg("reboot")
                .arg("-f")
                .status();
        }
    });
    Ok(())
}

fn run_status(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| format!("failed to run {program}: {err}"))?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    if detail.is_empty() {
        Err(format!("{program} exited with {}", output.status))
    } else {
        Err(format!("{program} exited with {}: {detail}", output.status))
    }
}

fn unique_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn validate_write_path(path: &str) -> Result<PathBuf> {
    if path.is_empty() {
        return Err("write path is empty".to_string());
    }
    if path.contains('\0') {
        return Err("write path contains invalid NUL byte".to_string());
    }
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(format!("write path must be absolute: {}", path.display()));
    }
    Ok(path)
}

pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<()> {
    let payload =
        postcard::to_stdvec(value).map_err(|err| format!("failed to encode agent frame: {err}"))?;
    if payload.len() > MAX_FRAME_LEN {
        return Err(format!("agent frame too large: {} bytes", payload.len()));
    }
    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .map_err(|err| format!("failed to write agent frame length: {err}"))?;
    writer
        .write_all(&payload)
        .map_err(|err| format!("failed to write agent frame payload: {err}"))
}

pub fn read_frame<R: Read, T: for<'de> Deserialize<'de>>(reader: &mut R) -> Result<Option<T>> {
    let mut length = [0u8; 4];
    match reader.read_exact(&mut length) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(format!("failed to read agent frame length: {err}")),
    }

    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_LEN {
        return Err(format!("agent frame too large: {length} bytes"));
    }

    let mut payload = vec![0u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(|err| format!("failed to read agent frame payload: {err}"))?;
    postcard::from_bytes(&payload)
        .map(Some)
        .map_err(|err| format!("failed to decode agent frame payload ({length} bytes): {err}"))
}

#[cfg(test)]
mod tests {
    use super::{read_frame, run, write_frame, AgentRequest, AgentResponse};

    #[test]
    fn frame_round_trip() {
        let request = AgentRequest::DiskPrepare {
            disk: "/dev/nvme0n1".to_string(),
        };
        let mut bytes = Vec::new();

        write_frame(&mut bytes, &request).unwrap();
        let decoded = read_frame::<_, AgentRequest>(&mut bytes.as_slice())
            .unwrap()
            .unwrap();

        assert_eq!(decoded, request);
    }

    #[test]
    fn ping_returns_pong() {
        let mut input = Vec::new();
        write_frame(&mut input, &AgentRequest::Ping).unwrap();
        let mut output = Vec::new();

        run(input.as_slice(), &mut output).unwrap();
        let response = read_frame::<_, AgentResponse>(&mut output.as_slice())
            .unwrap()
            .unwrap();

        assert_eq!(response, AgentResponse::Pong);
    }

    #[test]
    fn command_runs_without_shell() {
        let mut input = Vec::new();
        write_frame(
            &mut input,
            &AgentRequest::RunCommand {
                program: "printf".to_string(),
                args: vec!["hello".to_string()],
                stdin: Vec::new(),
            },
        )
        .unwrap();
        let mut output = Vec::new();

        run(input.as_slice(), &mut output).unwrap();
        let mut output = output.as_slice();
        let progress = read_frame::<_, AgentResponse>(&mut output)
            .unwrap()
            .unwrap();
        let response = read_frame::<_, AgentResponse>(&mut output)
            .unwrap()
            .unwrap();

        assert_eq!(
            progress,
            AgentResponse::CommandProgress {
                stdout: b"hello".to_vec(),
                stderr: Vec::new(),
            }
        );

        assert_eq!(
            response,
            AgentResponse::Command {
                result: super::CommandResult {
                    status: 0,
                    stdout: b"hello".to_vec(),
                    stderr: Vec::new(),
                }
            }
        );
    }

    #[test]
    fn command_output_is_truncated_to_fit_agent_frame() {
        let oversized = vec![b'x'; super::MAX_COMMAND_OUTPUT_LEN + 10];
        let truncated = super::truncate_command_output(oversized, "stdout");

        assert!(truncated.len() > super::MAX_COMMAND_OUTPUT_LEN);
        assert!(truncated.len() < super::MAX_COMMAND_OUTPUT_LEN + 128);
        assert!(String::from_utf8_lossy(&truncated).starts_with("[nox: truncated 10 bytes"));
    }

    #[test]
    fn tools_check_reports_missing_tool() {
        let mut input = Vec::new();
        write_frame(
            &mut input,
            &AgentRequest::ToolsCheck {
                required: vec!["definitely-not-a-real-nx-tool".to_string()],
                require_passwordless_sudo: false,
            },
        )
        .unwrap();
        let mut output = Vec::new();

        run(input.as_slice(), &mut output).unwrap();
        let response = read_frame::<_, AgentResponse>(&mut output.as_slice())
            .unwrap()
            .unwrap();

        match response {
            AgentResponse::ToolsCheck { result } => {
                assert_eq!(result.missing, vec!["definitely-not-a-real-nx-tool"]);
                assert!(result.found.is_empty());
                assert_eq!(result.sudo_ok, None);
            }
            response => panic!("unexpected response: {response:?}"),
        }
    }

    #[test]
    fn write_file_creates_parent_and_writes_bytes() {
        let dir = std::env::temp_dir().join(format!("nox-agent-write-{}", std::process::id()));
        let file = dir.join("nested/file.txt");
        let mut input = Vec::new();
        write_frame(
            &mut input,
            &AgentRequest::WriteFile {
                path: file.display().to_string(),
                bytes: b"content".to_vec(),
                mode: Some(0o600),
                create_parent: true,
            },
        )
        .unwrap();
        let mut output = Vec::new();

        run(input.as_slice(), &mut output).unwrap();
        let response = read_frame::<_, AgentResponse>(&mut output.as_slice())
            .unwrap()
            .unwrap();

        assert_eq!(std::fs::read(&file).unwrap(), b"content");
        match response {
            AgentResponse::WriteFile { result } => {
                assert_eq!(result.path, file.display().to_string());
                assert_eq!(result.bytes_written, 7);
            }
            response => panic!("unexpected response: {response:?}"),
        }

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn write_file_rejects_relative_path() {
        let mut input = Vec::new();
        write_frame(
            &mut input,
            &AgentRequest::WriteFile {
                path: "relative.txt".to_string(),
                bytes: Vec::new(),
                mode: None,
                create_parent: false,
            },
        )
        .unwrap();
        let mut output = Vec::new();

        run(input.as_slice(), &mut output).unwrap();
        let response = read_frame::<_, AgentResponse>(&mut output.as_slice())
            .unwrap()
            .unwrap();

        match response {
            AgentResponse::Error { message } => {
                assert!(message.contains("write path must be absolute"));
            }
            response => panic!("unexpected response: {response:?}"),
        }
    }

    #[test]
    fn eof_without_frame_exits_cleanly() {
        let mut output = Vec::new();

        let code = run([].as_slice(), &mut output).unwrap();

        assert_eq!(code, 0);
        assert!(output.is_empty());
    }
}
