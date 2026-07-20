use russh::client;
use russh::keys::{
    check_known_hosts_path, known_hosts::learn_known_hosts_path, load_secret_key,
    Error as KeyError, PrivateKeyWithHashAlg,
};
use russh::ChannelMsg;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshCheck {
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCommandOutput {
    pub status: u32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub struct InteractiveCommand {
    runtime: tokio::runtime::Runtime,
    session: client::Handle<KnownHostsVerifier>,
    channel: russh::Channel<client::Msg>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_status: Option<u32>,
}

pub fn check_key_auth(target: &str) -> SshCheck {
    if target.trim().is_empty() {
        return fail("remote target is empty");
    }

    let target = match SshTarget::parse(target) {
        Ok(target) => target,
        Err(err) => return fail(err),
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => return fail(format!("failed to start async runtime: {err}")),
    };

    match runtime.block_on(check_key_auth_async(&target)) {
        Ok(detail) => SshCheck { ok: true, detail },
        Err(err) => fail(err),
    }
}

pub fn run_command(target: &str, command: &str) -> Result<RemoteCommandOutput, String> {
    run_command_with_stdin(target, command, &[])
}

pub fn run_command_with_stdin(
    target: &str,
    command: &str,
    stdin: &[u8],
) -> Result<RemoteCommandOutput, String> {
    if target.trim().is_empty() {
        return Err("remote target is empty".to_string());
    }
    if command.trim().is_empty() {
        return Err("remote command is empty".to_string());
    }

    let target = SshTarget::parse(target)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| format!("failed to start async runtime: {err}"))?;

    runtime.block_on(run_command_async(&target, command, stdin))
}

pub fn open_interactive_command(target: &str, command: &str) -> Result<InteractiveCommand, String> {
    if target.trim().is_empty() {
        return Err("remote target is empty".to_string());
    }
    if command.trim().is_empty() {
        return Err("remote command is empty".to_string());
    }

    let target = SshTarget::parse(target)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| format!("failed to start async runtime: {err}"))?;

    let (session, channel) = runtime.block_on(open_interactive_command_async(&target, command))?;
    Ok(InteractiveCommand {
        runtime,
        session,
        channel,
        stdout: Vec::new(),
        stderr: Vec::new(),
        exit_status: None,
    })
}

impl InteractiveCommand {
    pub fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        let bytes = bytes.to_vec();
        self.runtime
            .block_on(send_channel_data(&self.channel, bytes))
            .map_err(|err| format!("failed to send remote command stdin: {err}"))
    }

    pub fn read_exact_stdout(&mut self, len: usize) -> Result<Vec<u8>, String> {
        while self.stdout.len() < len {
            self.poll_channel_once()?;
        }
        Ok(self.stdout.drain(..len).collect())
    }

    pub fn close(mut self) -> Result<RemoteCommandOutput, String> {
        let _ = self.runtime.block_on(close_channel_stdin(&self.channel));
        while self.exit_status.is_none() {
            match self.poll_channel_once() {
                Ok(()) => {}
                Err(err) if err.contains("closed before") => break,
                Err(err) => return Err(err),
            }
        }
        let _ = self.runtime.block_on(disconnect_session(&self.session));
        Ok(RemoteCommandOutput {
            status: self.exit_status.unwrap_or(0),
            stdout: self.stdout,
            stderr: self.stderr,
        })
    }

    fn poll_channel_once(&mut self) -> Result<(), String> {
        let msg = self
            .runtime
            .block_on(wait_channel_message(&mut self.channel));
        match msg {
            Some(ChannelMsg::Data { data }) => {
                self.stdout.extend_from_slice(&data);
                Ok(())
            }
            Some(ChannelMsg::ExtendedData { data, .. }) => {
                self.stderr.extend_from_slice(&data);
                Ok(())
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                self.exit_status = Some(exit_status);
                Ok(())
            }
            Some(ChannelMsg::Eof | ChannelMsg::Close) | None => {
                Err("remote command closed before enough stdout was received".to_string())
            }
            Some(_) => Ok(()),
        }
    }
}

async fn check_key_auth_async(target: &SshTarget) -> Result<String, String> {
    let (session, key_path, installed) = authenticated_session(target).await?;
    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;

    if installed {
        Ok(format!(
            "installed public key, then russh key auth works for {} with {}",
            target.display(),
            key_path.display()
        ))
    } else {
        Ok(format!(
            "russh key auth works for {} with {}",
            target.display(),
            key_path.display()
        ))
    }
}

async fn run_command_async(
    target: &SshTarget,
    command: &str,
    stdin: &[u8],
) -> Result<RemoteCommandOutput, String> {
    let (mut session, _, _) = authenticated_session(target).await?;
    let output = run_remote_command(&mut session, command, stdin).await;
    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;
    output
}

async fn open_interactive_command_async(
    target: &SshTarget,
    command: &str,
) -> Result<
    (
        client::Handle<KnownHostsVerifier>,
        russh::Channel<client::Msg>,
    ),
    String,
> {
    let (session, _, _) = authenticated_session(target).await?;
    let channel = open_remote_command_channel(&session, command).await?;
    Ok((session, channel))
}

async fn authenticated_session(
    target: &SshTarget,
) -> Result<(client::Handle<KnownHostsVerifier>, PathBuf, bool), String> {
    let keys = private_key_candidates();
    if keys.is_empty() {
        return Err(
            "no SSH private key found; set NIXOS_INSTALL_SSH_KEY or create ~/.ssh/id_ed25519"
                .to_string(),
        );
    }

    let mut errors = Vec::new();
    let mut rejected_key = None;
    for key_path in keys {
        match authenticate_with_key(target, &key_path).await {
            Ok(session) => return Ok((session, key_path, false)),
            Err(SshAuthError::Rejected) => {
                if rejected_key.is_none() {
                    rejected_key = Some(key_path.clone());
                }
                errors.push(format!(
                    "{}: server rejected public key",
                    key_path.display()
                ));
            }
            Err(SshAuthError::Other(err)) => errors.push(format!("{}: {err}", key_path.display())),
        }
    }

    if let Some(key_path) = rejected_key {
        install_public_key_with_password(target, &key_path).await?;
        let session = authenticate_with_key(target, &key_path)
            .await
            .map_err(|err| format!("key install completed, but retry failed: {err}"))?;
        return Ok((session, key_path, true));
    }

    Err(format!(
        "russh key auth failed for {}; {}",
        target.display(),
        errors.join("; ")
    ))
}

#[derive(Debug)]
enum SshAuthError {
    Rejected,
    Other(String),
}

impl std::fmt::Display for SshAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected => write!(f, "server rejected public key"),
            Self::Other(err) => f.write_str(err),
        }
    }
}

async fn authenticate_with_key(
    target: &SshTarget,
    key_path: &Path,
) -> Result<client::Handle<KnownHostsVerifier>, SshAuthError> {
    let key = load_secret_key(key_path, None)
        .map_err(|err| SshAuthError::Other(format!("failed to load private key: {err}")))?;
    let mut session = connect(target).await.map_err(SshAuthError::Other)?;

    let hash = session
        .best_supported_rsa_hash()
        .await
        .map_err(|err| SshAuthError::Other(format!("failed to negotiate RSA hash: {err}")))?
        .flatten();
    let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
    let authenticated = session
        .authenticate_publickey(&target.user, key)
        .await
        .map_err(|err| SshAuthError::Other(format!("public key auth failed: {err}")))?;

    if !authenticated.success() {
        let _ = session
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        return Err(SshAuthError::Rejected);
    }

    Ok(session)
}

async fn install_public_key_with_password(
    target: &SshTarget,
    key_path: &Path,
) -> Result<(), String> {
    let public_key_path = public_key_path(key_path);
    let public_key = fs::read_to_string(&public_key_path)
        .map_err(|err| format!("failed to read {}: {err}", public_key_path.display()))?;
    let public_key = public_key.trim();
    if public_key.is_empty() {
        return Err(format!("{} is empty", public_key_path.display()));
    }

    let password = password_for_target(target)?;
    let mut session = connect(target).await?;
    let authenticated = session
        .authenticate_password(&target.user, password)
        .await
        .map_err(|err| format!("password auth failed: {err}"))?;
    if !authenticated.success() {
        return Err("server rejected password".to_string());
    }

    let command = authorized_keys_command(public_key);
    let output = run_remote_command(&mut session, &command, &[]).await?;
    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;
    if output.status == 0 {
        Ok(())
    } else if output.stderr.is_empty() {
        Err(format!(
            "remote authorized_keys install exited with {}",
            output.status
        ))
    } else {
        Err(format!(
            "remote authorized_keys install exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

async fn connect(target: &SshTarget) -> Result<client::Handle<KnownHostsVerifier>, String> {
    let config = client::Config {
        inactivity_timeout: None,
        ..Default::default()
    };
    client::connect(
        Arc::new(config),
        (target.host.as_str(), target.port),
        KnownHostsVerifier {
            host: target.host.clone(),
            port: target.port,
            path: known_hosts_file(),
        },
    )
    .await
    .map_err(|err| format!("connect failed: {err}"))
}

async fn run_remote_command(
    session: &mut client::Handle<KnownHostsVerifier>,
    command: &str,
    stdin: &[u8],
) -> Result<RemoteCommandOutput, String> {
    let mut channel = open_remote_command_channel(session, command).await?;
    if !stdin.is_empty() {
        channel
            .data_bytes(stdin.to_vec())
            .await
            .map_err(|err| format!("failed to send remote command stdin: {err}"))?;
    }
    channel
        .eof()
        .await
        .map_err(|err| format!("failed to close remote command stdin: {err}"))?;

    let mut exit_status = None;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::ExitStatus {
                exit_status: status,
            } => exit_status = Some(status),
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => {
                stderr.extend_from_slice(&data);
            }
            _ => {}
        }
    }

    match exit_status {
        Some(status) => Ok(RemoteCommandOutput {
            status,
            stdout,
            stderr,
        }),
        None => Err("remote command did not return an exit status".to_string()),
    }
}

async fn open_remote_command_channel(
    session: &client::Handle<KnownHostsVerifier>,
    command: &str,
) -> Result<russh::Channel<client::Msg>, String> {
    let channel = session
        .channel_open_session()
        .await
        .map_err(|err| format!("failed to open ssh session: {err}"))?;
    channel
        .exec(true, command)
        .await
        .map_err(|err| format!("failed to execute remote command: {err}"))?;
    Ok(channel)
}

async fn send_channel_data(
    channel: &russh::Channel<client::Msg>,
    bytes: Vec<u8>,
) -> Result<(), russh::Error> {
    channel.data_bytes(bytes).await
}

async fn close_channel_stdin(channel: &russh::Channel<client::Msg>) -> Result<(), russh::Error> {
    channel.eof().await
}

async fn wait_channel_message(channel: &mut russh::Channel<client::Msg>) -> Option<ChannelMsg> {
    channel.wait().await
}

async fn disconnect_session(
    session: &client::Handle<KnownHostsVerifier>,
) -> Result<(), russh::Error> {
    session
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
}

fn password_for_target(target: &SshTarget) -> Result<String, String> {
    if let Ok(password) = env::var("NIXOS_INSTALL_SSH_PASSWORD") {
        return Ok(password);
    }
    rpassword::prompt_password(format!("Password for {}: ", target.display()))
        .map_err(|err| format!("failed to read password: {err}"))
}

fn public_key_path(key_path: &Path) -> PathBuf {
    let mut path = key_path.as_os_str().to_os_string();
    path.push(".pub");
    PathBuf::from(path)
}

fn authorized_keys_command(public_key: &str) -> String {
    let key = shell_single_quote(public_key);
    format!(
        "umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys && if ! grep -qxF -- {key} ~/.ssh/authorized_keys; then printf '%s\\n' {key} >> ~/.ssh/authorized_keys; fi"
    )
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[derive(Clone, Debug)]
struct KnownHostsVerifier {
    host: String,
    port: u16,
    path: PathBuf,
}

impl client::Handler for KnownHostsVerifier {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        match check_known_hosts_path(&self.host, self.port, server_public_key, &self.path) {
            Ok(true) => Ok(true),
            Ok(false) => {
                learn_known_hosts_path(&self.host, self.port, server_public_key, &self.path)?;
                Ok(true)
            }
            Err(KeyError::KeyChanged { line }) => {
                remove_known_host_line(&self.path, line)?;
                learn_known_hosts_path(&self.host, self.port, server_public_key, &self.path)?;
                Ok(true)
            }
            Err(err) => Err(err.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SshTarget {
    user: String,
    host: String,
    port: u16,
}

impl SshTarget {
    fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        let (user, host_port) = raw
            .split_once('@')
            .ok_or_else(|| "remote target must be user@host or user@host:port".to_string())?;
        if user.is_empty() || host_port.is_empty() {
            return Err("remote target must include both user and host".to_string());
        }

        let (host, port) = if host_port.starts_with('[') {
            parse_bracket_host(host_port)?
        } else if let Some((host, port)) = host_port.rsplit_once(':') {
            if host.contains(':') {
                (host_port.to_string(), 22)
            } else {
                (host.to_string(), parse_port(port)?)
            }
        } else {
            (host_port.to_string(), 22)
        };

        if host.is_empty() {
            return Err("remote target host is empty".to_string());
        }

        Ok(Self {
            user: user.to_string(),
            host,
            port,
        })
    }

    fn display(&self) -> String {
        if self.port == 22 {
            format!("{}@{}", self.user, self.host)
        } else {
            format!("{}@{}:{}", self.user, self.host, self.port)
        }
    }
}

fn parse_bracket_host(host_port: &str) -> Result<(String, u16), String> {
    let end = host_port
        .find(']')
        .ok_or_else(|| "bracketed IPv6 target is missing ']'".to_string())?;
    let host = host_port[1..end].to_string();
    let rest = &host_port[end + 1..];
    let port = if rest.is_empty() {
        22
    } else if let Some(port) = rest.strip_prefix(':') {
        parse_port(port)?
    } else {
        return Err("bracketed IPv6 target must use user@[host] or user@[host]:port".to_string());
    };
    Ok((host, port))
}

fn parse_port(raw: &str) -> Result<u16, String> {
    raw.parse::<u16>()
        .map_err(|_| format!("invalid SSH port: {raw}"))
}

fn private_key_candidates() -> Vec<PathBuf> {
    if let Some(path) = env::var_os("NIXOS_INSTALL_SSH_KEY") {
        return vec![PathBuf::from(path)];
    }

    let Some(home) = env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    ["id_ed25519", "id_ecdsa", "id_rsa"]
        .into_iter()
        .map(|name| home.join(".ssh").join(name))
        .filter(|path| path.exists())
        .collect()
}

fn known_hosts_file() -> PathBuf {
    env::var_os("NIXOS_INSTALL_SSH_KNOWN_HOSTS")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".ssh/known_hosts")))
        .unwrap_or_else(|| PathBuf::from("/dev/null"))
}

fn remove_known_host_line(path: &Path, line_number: usize) -> Result<(), KeyError> {
    if line_number == 0 {
        return Ok(());
    }

    let contents = fs::read_to_string(path)?;
    let mut filtered = String::new();
    for (index, line) in contents.lines().enumerate() {
        if index + 1 != line_number {
            filtered.push_str(line);
            filtered.push('\n');
        }
    }
    fs::write(path, filtered)?;
    Ok(())
}

fn fail(detail: impl Into<String>) -> SshCheck {
    SshCheck {
        ok: false,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{authorized_keys_command, public_key_path, remove_known_host_line, SshTarget};
    use std::fs;
    use std::path::Path;

    #[test]
    fn parses_default_port_target() {
        assert_eq!(
            SshTarget::parse("nixos@10.10.10.7").unwrap(),
            SshTarget {
                user: "nixos".to_string(),
                host: "10.10.10.7".to_string(),
                port: 22
            }
        );
    }

    #[test]
    fn parses_custom_port_target() {
        assert_eq!(
            SshTarget::parse("nixos@example.test:2222").unwrap(),
            SshTarget {
                user: "nixos".to_string(),
                host: "example.test".to_string(),
                port: 2222
            }
        );
    }

    #[test]
    fn parses_bracketed_ipv6_target() {
        assert_eq!(
            SshTarget::parse("nixos@[fe80::1]:2222").unwrap(),
            SshTarget {
                user: "nixos".to_string(),
                host: "fe80::1".to_string(),
                port: 2222
            }
        );
    }

    #[test]
    fn rejects_missing_user() {
        assert!(SshTarget::parse("10.10.10.7").is_err());
    }

    #[test]
    fn removes_stale_known_host_line() {
        let path = std::env::temp_dir().join(format!("nox-known-hosts-{}", std::process::id()));
        fs::write(&path, "one\nstale\ntwo\n").unwrap();

        remove_known_host_line(&path, 2).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "one\ntwo\n");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn public_key_path_appends_pub() {
        assert_eq!(
            public_key_path(Path::new("/tmp/id.test")),
            Path::new("/tmp/id.test.pub")
        );
    }

    #[test]
    fn authorized_keys_command_quotes_key() {
        let command = authorized_keys_command("ssh-ed25519 AAAA comment'with quote");

        assert!(command.contains("mkdir -p ~/.ssh"));
        assert!(command.contains("'ssh-ed25519 AAAA comment'\\''with quote'"));
    }
}
