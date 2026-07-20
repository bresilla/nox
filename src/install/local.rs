//! Native local install execution.
//!
//! The install plan produced by [`crate::install::plan`] is backend-agnostic: each
//! step is a program plus arguments, where `nox-agent <subcommand>` marks a
//! typed operation. The remote installer interprets those steps over the SSH
//! agent; this module interprets the same steps in-process, calling the agent
//! operation functions directly, so a local install runs the identical plan
//! without SSH.
//!
//! Destructive steps flow through the same [`RemoteExecutionPolicy`] gate as the
//! remote path, so nothing runs unless the caller confirms.

use std::process::Command;

use crate::agent;
use crate::install::executor::{
    execute_plan_with_runner, RemoteExecutionPolicy, RemoteInstallExecution,
    RemoteInstallStepOutput,
};
use crate::install::plan::{RemoteInstallStep, StepOp};
use crate::report::{Reporter, Stream};
use crate::Result;

/// The typed operations a local install performs. Extracting them behind a trait
/// lets the orchestration be unit-tested with a recording fake instead of running
/// real disk and filesystem mutations.
pub(crate) trait LocalOps {
    fn network_route_cleanup(&mut self) -> Result<StepOutcome>;
    fn storage_overwrite(&mut self, vg_name: &str) -> Result<StepOutcome>;
    fn prepare_disk(&mut self, disk: &str) -> Result<StepOutcome>;
    fn disko_apply(&mut self, disko_file: &str) -> Result<StepOutcome>;
    fn write_secret_key(&mut self, path: &str, mode: u32, bytes: &[u8]) -> Result<StepOutcome>;
    fn config_copy(&mut self, source_dir: &str, role: &str, install_user: &str)
        -> Result<StepOutcome>;
    fn bin_ensure(&mut self, github_token: &[u8]) -> Result<StepOutcome>;
    fn dotfiles_run(
        &mut self,
        dotfiles_repo: &str,
        install_user: &str,
        github_token: &[u8],
    ) -> Result<StepOutcome>;
    fn schedule_reboot(&mut self, delay_secs: u64) -> Result<StepOutcome>;
    fn run_program(&mut self, program: &str, args: &[String], stdin: &[u8]) -> Result<StepOutcome>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StepOutcome {
    pub status: u32,
    pub stdout: String,
    pub stderr: String,
}

impl StepOutcome {
    fn ok(stdout: impl Into<String>) -> Self {
        Self {
            status: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }
}

pub(crate) fn execute_local_plan(
    ops: &mut dyn LocalOps,
    steps: &[RemoteInstallStep],
    policy: RemoteExecutionPolicy,
    reporter: &Reporter,
) -> Result<RemoteInstallExecution> {
    execute_plan_with_runner(steps, policy, reporter, |step| execute_local_step(ops, step))
}

fn execute_local_step(
    ops: &mut dyn LocalOps,
    step: &RemoteInstallStep,
) -> Result<RemoteInstallStepOutput> {
    let outcome = dispatch(ops, step)?;
    Ok(RemoteInstallStepOutput {
        name: step.name.to_string(),
        command: step.command_line(),
        status: outcome.status,
        stdout: outcome.stdout,
        stderr: outcome.stderr,
    })
}

/// Map the shared typed step operations onto the local backend. Validation
/// already happened in [`RemoteInstallStep::op`], identically to the remote path.
fn dispatch(ops: &mut dyn LocalOps, step: &RemoteInstallStep) -> Result<StepOutcome> {
    match step.op()? {
        StepOp::Program { program, args } => ops.run_program(program, args, &step.stdin),
        StepOp::NixosInstall { args } => {
            let mut full = vec![
                "TMPDIR=/tmp".to_string(),
                "sudo".to_string(),
                "--non-interactive".to_string(),
                "nixos-install".to_string(),
            ];
            full.extend(args.iter().cloned());
            ops.run_program("env", &full, &step.stdin)
        }
        StepOp::RouteCleanup => ops.network_route_cleanup(),
        StepOp::StorageOverwrite { vg_name } => ops.storage_overwrite(vg_name),
        StepOp::DiskPrepare { disk } => ops.prepare_disk(disk),
        StepOp::DiskoApply { disko_file } => ops.disko_apply(disko_file),
        StepOp::SecretWrite { path, mode } => ops.write_secret_key(path, mode, &step.stdin),
        StepOp::ConfigCopy {
            source_dir,
            role,
            install_user,
        } => ops.config_copy(source_dir, role, install_user),
        StepOp::BinEnsure => ops.bin_ensure(&step.stdin),
        StepOp::DotfilesRun {
            dotfiles_repo,
            install_user,
        } => ops.dotfiles_run(dotfiles_repo, install_user, &step.stdin),
        StepOp::Reboot => ops.schedule_reboot(3),
    }
}

/// Live implementation that performs the real local mutations by calling the
/// agent operation functions in-process and shelling out for plain programs.
/// Output of long-running programs streams through the reporter live.
pub(crate) struct LiveLocalOps {
    pub reporter: Reporter,
}

impl LocalOps for LiveLocalOps {
    fn network_route_cleanup(&mut self) -> Result<StepOutcome> {
        agent::network_route_cleanup().map(command_result_outcome)
    }

    fn storage_overwrite(&mut self, vg_name: &str) -> Result<StepOutcome> {
        agent::storage_overwrite(vg_name).map(command_result_outcome)
    }

    fn prepare_disk(&mut self, disk: &str) -> Result<StepOutcome> {
        let result = crate::install::disk::local_prepare(disk)?;
        Ok(StepOutcome {
            status: result.status,
            stdout: result.stdout,
            stderr: result.stderr,
        })
    }

    fn disko_apply(&mut self, disko_file: &str) -> Result<StepOutcome> {
        agent::disko_apply(disko_file).map(command_result_outcome)
    }

    fn write_secret_key(&mut self, path: &str, mode: u32, bytes: &[u8]) -> Result<StepOutcome> {
        let result = agent::sudo_write_file(path, bytes, mode, true)?;
        Ok(StepOutcome::ok(format!(
            "wrote {} bytes to {}",
            result.bytes_written, result.path
        )))
    }

    fn config_copy(
        &mut self,
        source_dir: &str,
        role: &str,
        install_user: &str,
    ) -> Result<StepOutcome> {
        agent::config_copy(source_dir, role, install_user).map(command_result_outcome)
    }

    fn bin_ensure(&mut self, github_token: &[u8]) -> Result<StepOutcome> {
        let token = String::from_utf8(github_token.to_vec())
            .map_err(|err| format!("GitHub token is not valid UTF-8: {err}"))?;
        let mut args = Vec::new();
        if !token.is_empty() {
            args.push(format!("GITHUB_TOKEN={token}"));
            args.push(format!("GITHUB_AUTH_TOKEN={token}"));
        }
        args.extend(
            [
                "chroot",
                "/mnt",
                "/nix/var/nix/profiles/system/sw/bin/env",
                "PATH=/nix/var/nix/profiles/system/sw/bin:/usr/local/bin:/bin:/usr/bin",
                "HOME=/root",
                "USER=root",
                "LOGNAME=root",
                "/nix/var/nix/profiles/system/sw/bin/bin",
                "ensure",
            ]
            .into_iter()
            .map(str::to_string),
        );
        let mut sudo_args = vec!["--non-interactive".to_string()];
        if !token.is_empty() {
            sudo_args.push("--preserve-env=GITHUB_TOKEN,GITHUB_AUTH_TOKEN".to_string());
        }
        sudo_args.extend(args);
        run_local_program(&self.reporter, "sudo", &sudo_args, &[])
    }

    fn dotfiles_run(
        &mut self,
        dotfiles_repo: &str,
        install_user: &str,
        github_token: &[u8],
    ) -> Result<StepOutcome> {
        let mut writer = ReporterWriter {
            reporter: self.reporter.clone(),
        };
        agent::dotfiles_run_streaming(&mut writer, dotfiles_repo, install_user, github_token)?;
        Ok(StepOutcome::ok("dotfiles run complete"))
    }

    fn schedule_reboot(&mut self, delay_secs: u64) -> Result<StepOutcome> {
        agent::schedule_reboot(delay_secs)?;
        Ok(StepOutcome::ok(format!("reboot scheduled in {delay_secs}s")))
    }

    fn run_program(&mut self, program: &str, args: &[String], stdin: &[u8]) -> Result<StepOutcome> {
        run_local_program(&self.reporter, program, args, stdin)
    }
}

/// Adapter delivering a `Write` stream (used by the chroot/dotfiles helpers)
/// into the reporter as live output chunks.
struct ReporterWriter {
    reporter: Reporter,
}

impl std::io::Write for ReporterWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.reporter.output(Stream::Stdout, buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run a local program, streaming its output through the reporter live (so long
/// steps like nixos-install show progress) while also capturing it for the step
/// result — mirroring what the remote agent does over the wire.
fn run_local_program(
    reporter: &Reporter,
    program: &str,
    args: &[String],
    stdin: &[u8],
) -> Result<StepOutcome> {
    use std::io::{Read, Write};
    use std::process::Stdio;

    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin.is_empty() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to run {program}: {err}"))?;

    if !stdin.is_empty() {
        child
            .stdin
            .take()
            .ok_or_else(|| "failed to open stdin for local program".to_string())?
            .write_all(stdin)
            .map_err(|err| format!("failed to write stdin to {program}: {err}"))?;
    }

    let stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| "failed to open stdout for local program".to_string())?;
    let stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| "failed to open stderr for local program".to_string())?;

    let stream_pipe = |mut pipe: Box<dyn Read + Send>, reporter: Reporter, stream: Stream| {
        std::thread::spawn(move || {
            let mut captured = Vec::new();
            let mut buffer = [0u8; 8192];
            loop {
                match pipe.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        reporter.output(stream, &buffer[..read]);
                        captured.extend_from_slice(&buffer[..read]);
                    }
                }
            }
            captured
        })
    };

    let stdout_thread = stream_pipe(Box::new(stdout_pipe), reporter.clone(), Stream::Stdout);
    let stderr_thread = stream_pipe(Box::new(stderr_pipe), reporter.clone(), Stream::Stderr);

    let status = child
        .wait()
        .map_err(|err| format!("failed to wait for {program}: {err}"))?;
    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();

    Ok(StepOutcome {
        status: status.code().unwrap_or(1) as u32,
        stdout: String::from_utf8_lossy(&stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&stderr).trim().to_string(),
    })
}

fn command_result_outcome(result: agent::CommandResult) -> StepOutcome {
    StepOutcome {
        status: result.status,
        stdout: String::from_utf8_lossy(&result.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&result.stderr).trim().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{execute_local_plan, LocalOps, StepOutcome};
    use crate::install::executor::RemoteExecutionPolicy;
    use crate::install::plan::{plan_remote_install_steps_with_secrets, RemoteInstallSecrets};
    use crate::install::state::InstallState;

    #[derive(Default)]
    struct FakeLocalOps {
        calls: Vec<String>,
    }

    impl FakeLocalOps {
        fn record(&mut self, call: impl Into<String>) -> Result<StepOutcome, String> {
            let call = call.into();
            self.calls.push(call.clone());
            Ok(StepOutcome::ok(call))
        }
    }

    impl LocalOps for FakeLocalOps {
        fn network_route_cleanup(&mut self) -> Result<StepOutcome, String> {
            self.record("network-route-cleanup")
        }
        fn storage_overwrite(&mut self, vg: &str) -> Result<StepOutcome, String> {
            self.record(format!("storage-overwrite {vg}"))
        }
        fn prepare_disk(&mut self, disk: &str) -> Result<StepOutcome, String> {
            self.record(format!("disk-prepare {disk}"))
        }
        fn disko_apply(&mut self, file: &str) -> Result<StepOutcome, String> {
            self.record(format!("disko-apply {file}"))
        }
        fn write_secret_key(
            &mut self,
            path: &str,
            mode: u32,
            bytes: &[u8],
        ) -> Result<StepOutcome, String> {
            self.record(format!("secret-write {path} {mode:o} {}", bytes.len()))
        }
        fn config_copy(
            &mut self,
            source_dir: &str,
            role: &str,
            install_user: &str,
        ) -> Result<StepOutcome, String> {
            self.record(format!("config-copy {source_dir} {role} {install_user}"))
        }
        fn bin_ensure(&mut self, token: &[u8]) -> Result<StepOutcome, String> {
            self.record(format!("bin-ensure token={}", token.len()))
        }
        fn dotfiles_run(
            &mut self,
            repo: &str,
            user: &str,
            token: &[u8],
        ) -> Result<StepOutcome, String> {
            self.record(format!("dotfiles-run {repo} {user} token={}", token.len()))
        }
        fn schedule_reboot(&mut self, delay: u64) -> Result<StepOutcome, String> {
            self.record(format!("reboot {delay}"))
        }
        fn run_program(
            &mut self,
            program: &str,
            args: &[String],
            _stdin: &[u8],
        ) -> Result<StepOutcome, String> {
            self.record(format!("program {program} {}", args.join(" ")))
        }
    }

    fn sample_steps() -> Vec<crate::install::plan::RemoteInstallStep> {
        plan_remote_install_steps_with_secrets(
            &InstallState::sample(),
            "/tmp/nx-source",
            RemoteInstallSecrets {
                shared_system_key: Some(b"AGE-SECRET-KEY"),
                github_token: Some(b"ghp_test"),
            },
        )
        .unwrap()
    }

    #[test]
    fn dispatches_every_agent_operation_in_process() {
        let steps = sample_steps();
        let mut ops = FakeLocalOps::default();

        let execution = execute_local_plan(
            &mut ops,
            &steps,
            RemoteExecutionPolicy::allow_destructive_steps(usize::MAX),
            &crate::report::Reporter::silent(),
        )
        .unwrap();

        assert_eq!(execution.completed.len(), steps.len());
        assert!(execution.refused.is_empty());
        // Typed agent operations are routed to the in-process backend, not shelled out.
        assert!(ops.calls.iter().any(|c| c == "network-route-cleanup"));
        assert!(ops.calls.iter().any(|c| c == "disk-prepare /dev/nvme0n1"));
        assert!(ops
            .calls
            .iter()
            .any(|c| c == "disko-apply /tmp/nx-source/host/generated/disko.nix"));
        assert!(ops
            .calls
            .iter()
            .any(|c| c == "secret-write /mnt/var/lib/sops-nix/key.txt 600 14"));
        assert!(ops
            .calls
            .iter()
            .any(|c| c == "config-copy /tmp/nx-source laptop bresilla"));
        assert!(ops.calls.iter().any(|c| c == "bin-ensure token=8"));
        assert!(ops.calls.iter().any(|c| c.starts_with("dotfiles-run")));
        assert!(ops.calls.iter().any(|c| c == "reboot 3"));
        // Plain programs (id, test, findmnt) go through run_program; nixos-install
        // is wrapped with env/TMPDIR/sudo exactly like the remote backend does.
        assert!(ops.calls.iter().any(|c| c.starts_with("program id")));
        assert!(ops
            .calls
            .iter()
            .any(|c| c.starts_with("program env TMPDIR=/tmp sudo") && c.contains("nixos-install")));
    }

    #[test]
    fn safe_policy_refuses_destructive_steps_locally() {
        let steps = sample_steps();
        let mut ops = FakeLocalOps::default();

        let execution =
            execute_local_plan(&mut ops, &steps, RemoteExecutionPolicy::safe(), &crate::report::Reporter::silent()).unwrap();

        assert!(!execution.refused.is_empty());
        // No destructive typed op runs under the safe policy.
        assert!(!ops.calls.iter().any(|c| c.starts_with("disk-prepare")));
        assert!(!ops.calls.iter().any(|c| c.starts_with("disko-apply")));
    }
}
