use std::path::Path;

use crate::agent::{AgentRequest, AgentResponse, CommandResult, ToolsCheckResult};
use crate::agent::client::AgentSession;
use crate::install::artifacts::TransferredArtifact;
use crate::install::disk::{DiskInfo, DiskPrepareResult};
use crate::Result;

pub struct RemoteInstallSession {
    agent_binary: String,
    agent: AgentSession,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteStepResult {
    pub name: String,
    pub status: u32,
    pub stdout: String,
    pub stderr: String,
}

impl RemoteInstallSession {
    pub fn connect(repo: &Path, remote: &str, mut progress: impl FnMut(&str)) -> Result<Self> {
        let bootstrapped = crate::agent::bootstrap::bootstrap_with_progress(repo, remote, |message| {
            progress(message);
        })?;
        let agent_binary = bootstrapped.binary.to_string_lossy().to_string();
        Self::connect_existing(remote, &agent_binary)
    }

    pub fn connect_existing(remote: &str, agent_binary: &str) -> Result<Self> {
        let agent = AgentSession::connect(remote, &agent_binary)?;
        Ok(Self {
            agent_binary: agent_binary.to_string(),
            agent,
        })
    }

    pub fn agent_binary(&self) -> &str {
        &self.agent_binary
    }

    /// Route live remote output through this reporter (e.g. into a TUI).
    pub fn set_reporter(&mut self, reporter: crate::report::Reporter) {
        self.agent.set_reporter(reporter);
    }

    pub fn ping(&mut self) -> Result<()> {
        self.agent.ping()
    }

    /// Full structured introspection of the target machine.
    pub fn facts(&mut self) -> Result<crate::facts::TargetFacts> {
        self.agent.facts()
    }

    pub fn tools_check(
        &mut self,
        required: &[String],
        require_passwordless_sudo: bool,
    ) -> Result<ToolsCheckResult> {
        self.agent.tools_check(required, require_passwordless_sudo)
    }

    pub fn disk_scan(&mut self) -> Result<Vec<DiskInfo>> {
        match self.agent.request(AgentRequest::DiskScan)? {
            AgentResponse::DiskScan { disks } => Ok(disks),
            AgentResponse::Error { message } => Err(message),
            response => Err(format!(
                "unexpected remote disk scan response: {response:?}"
            )),
        }
    }

    pub fn transfer_generated(
        &mut self,
        repo: &Path,
        remote_dir: &str,
    ) -> Result<Vec<TransferredArtifact>> {
        crate::install::artifacts::transfer_generated_with_writer(repo, remote_dir, |path, bytes| {
            self.agent.write_file(path, bytes, Some(0o644), true)
        })
    }

    pub fn transfer_flake_source(
        &mut self,
        repo: &Path,
        remote_dir: &str,
    ) -> Result<Vec<TransferredArtifact>> {
        crate::install::artifacts::transfer_flake_source_with_writer(repo, remote_dir, |path, bytes| {
            self.agent.write_file(path, bytes, Some(0o644), true)
        })
    }

    pub fn prepare_disk(&mut self, disk: &str) -> Result<DiskPrepareResult> {
        self.agent.prepare_disk(disk)
    }

    pub fn sudo_write_file(
        &mut self,
        path: &str,
        bytes: &[u8],
        mode: u32,
        create_parent: bool,
    ) -> Result<RemoteStepResult> {
        let result = self
            .agent
            .sudo_write_file(path, bytes, mode, create_parent)?;
        Ok(RemoteStepResult {
            name: "sudo file write".to_string(),
            status: 0,
            stdout: format!("wrote {} bytes to {}", result.bytes_written, result.path),
            stderr: String::new(),
        })
    }

    pub fn disko_apply(&mut self, disko_file: &str) -> Result<RemoteStepResult> {
        let result = self.agent.disko_apply(disko_file)?;
        Ok(step_result("apply disko layout", result))
    }

    pub fn config_copy(
        &mut self,
        source_dir: &str,
        role: &str,
        install_user: &str,
    ) -> Result<RemoteStepResult> {
        let result = self.agent.config_copy(source_dir, role, install_user)?;
        Ok(step_result("copy system config", result))
    }

    pub fn network_route_cleanup(&mut self) -> Result<RemoteStepResult> {
        let result = self.agent.network_route_cleanup()?;
        Ok(step_result("clean up competing default routes", result))
    }

    pub fn storage_overwrite(&mut self, vg_name: &str) -> Result<RemoteStepResult> {
        let result = self.agent.storage_overwrite(vg_name)?;
        Ok(step_result("remove existing volume group", result))
    }

    pub fn dotfiles_run(
        &mut self,
        dotfiles_repo: &str,
        install_user: &str,
        github_token: &[u8],
    ) -> Result<RemoteStepResult> {
        let result = self
            .agent
            .dotfiles_run(dotfiles_repo, install_user, github_token)?;
        Ok(step_result("run dotfiles", result))
    }

    pub fn schedule_reboot(&mut self, delay_secs: u64) -> Result<RemoteStepResult> {
        let delay_secs = self.agent.schedule_reboot(delay_secs)?;
        Ok(RemoteStepResult {
            name: "schedule reboot".to_string(),
            status: 0,
            stdout: format!("reboot scheduled in {delay_secs}s"),
            stderr: String::new(),
        })
    }

    pub fn run_step(
        &mut self,
        name: &str,
        program: &str,
        args: &[String],
        stdin: &[u8],
    ) -> Result<RemoteStepResult> {
        validate_step_name(name)?;
        let result = self.agent.run_command(program, args, stdin)?;
        Ok(step_result(name, result))
    }

    pub fn run_step_env(
        &mut self,
        name: &str,
        program: &str,
        args: &[String],
        stdin: &[u8],
        env: &[(String, String)],
    ) -> Result<RemoteStepResult> {
        validate_step_name(name)?;
        let result = self.agent.run_command_env(program, args, stdin, env)?;
        Ok(step_result(name, result))
    }

    pub fn run_checked_step(
        &mut self,
        name: &str,
        program: &str,
        args: &[String],
        stdin: &[u8],
    ) -> Result<RemoteStepResult> {
        let result = self.run_step(name, program, args, stdin)?;
        if result.status == 0 {
            Ok(result)
        } else if result.stderr.is_empty() {
            Err(format!(
                "remote step '{}' exited with {}",
                result.name, result.status
            ))
        } else {
            Err(format!(
                "remote step '{}' exited with {}: {}",
                result.name, result.status, result.stderr
            ))
        }
    }

    pub fn run_checked_step_env(
        &mut self,
        name: &str,
        program: &str,
        args: &[String],
        stdin: &[u8],
        env: &[(String, String)],
    ) -> Result<RemoteStepResult> {
        let result = self.run_step_env(name, program, args, stdin, env)?;
        if result.status == 0 {
            Ok(result)
        } else if result.stderr.is_empty() {
            Err(format!(
                "remote step '{}' exited with {}",
                result.name, result.status
            ))
        } else {
            Err(format!(
                "remote step '{}' exited with {}: {}",
                result.name, result.status, result.stderr
            ))
        }
    }

    pub fn remote_user_check(&mut self) -> Result<RemoteStepResult> {
        self.run_checked_step("remote user", "id", &["-un".to_string()], &[])
    }

    pub fn remote_nixos_version(&mut self) -> Result<RemoteStepResult> {
        self.run_checked_step("remote nixos version", "nixos-version", &Vec::new(), &[])
    }

    pub fn remote_mount_check(&mut self) -> Result<RemoteStepResult> {
        self.run_checked_step("remote mount check", "findmnt", &["/mnt".to_string()], &[])
    }

    pub fn close(self) -> Result<()> {
        let output = self.agent.close()?;
        if output.status == 0 {
            Ok(())
        } else if output.stderr.is_empty() {
            Err(format!("remote agent exited with {}", output.status))
        } else {
            Err(format!(
                "remote agent exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }
}

fn validate_step_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err("remote step name is empty".to_string());
    }
    Ok(())
}

fn step_result(name: &str, result: CommandResult) -> RemoteStepResult {
    RemoteStepResult {
        name: name.to_string(),
        status: result.status,
        stdout: String::from_utf8_lossy(&result.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&result.stderr).trim().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{step_result, validate_step_name};
    use crate::agent::CommandResult;

    #[test]
    fn step_result_trims_stdout_and_stderr() {
        let result = step_result(
            "remote user",
            CommandResult {
                status: 0,
                stdout: b"nixos\n".to_vec(),
                stderr: b" warning\n".to_vec(),
            },
        );

        assert_eq!(result.name, "remote user");
        assert_eq!(result.status, 0);
        assert_eq!(result.stdout, "nixos");
        assert_eq!(result.stderr, "warning");
    }

    #[test]
    fn rejects_empty_step_name() {
        assert!(validate_step_name("").is_err());
        assert!(validate_step_name("   ").is_err());
    }
}
