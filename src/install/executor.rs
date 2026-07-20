use std::time::Instant;

use crate::install::plan::{RemoteInstallStep, StepOp};
use crate::install::remote::{RemoteInstallSession, RemoteStepResult};
use crate::report::{Event, Reporter};
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteExecutionPolicy {
    pub destructive_steps_allowed: usize,
}

impl RemoteExecutionPolicy {
    pub fn safe() -> Self {
        Self {
            destructive_steps_allowed: 0,
        }
    }

    pub fn allow_destructive_steps(destructive_steps_allowed: usize) -> Self {
        Self {
            destructive_steps_allowed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteInstallExecution {
    pub completed: Vec<RemoteInstallStepOutput>,
    pub refused: Vec<RemoteInstallRefusal>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteInstallStepOutput {
    pub name: String,
    pub command: String,
    pub status: u32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteInstallRefusal {
    pub name: String,
    pub command: String,
}

pub fn execute_remote_plan(
    session: &mut RemoteInstallSession,
    steps: &[RemoteInstallStep],
    policy: RemoteExecutionPolicy,
    reporter: &Reporter,
) -> Result<RemoteInstallExecution> {
    execute_plan_with_runner(steps, policy, reporter, |step| {
        execute_remote_step(session, step)
    })
}

/// Map a typed step operation onto the remote agent session.
fn execute_remote_step(
    session: &mut RemoteInstallSession,
    step: &RemoteInstallStep,
) -> Result<RemoteInstallStepOutput> {
    let result = match step.op()? {
        StepOp::DiskPrepare { disk } => {
            let result = session.prepare_disk(disk)?;
            return Ok(RemoteInstallStepOutput {
                name: step.name.to_string(),
                command: step.command_line(),
                status: result.status,
                stdout: result.stdout,
                stderr: result.stderr,
            });
        }
        StepOp::RouteCleanup => session.network_route_cleanup()?,
        StepOp::StorageOverwrite { vg_name } => session.storage_overwrite(vg_name)?,
        StepOp::SecretWrite { path, mode } => {
            let mut result = session.sudo_write_file(path, &step.stdin, mode, true)?;
            result.name = step.name.to_string();
            result
        }
        StepOp::DiskoApply { disko_file } => {
            let mut result = session.disko_apply(disko_file)?;
            result.name = step.name.to_string();
            result
        }
        StepOp::ConfigCopy {
            source_dir,
            role,
            install_user,
        } => {
            let mut result = session.config_copy(source_dir, role, install_user)?;
            result.name = step.name.to_string();
            result
        }
        StepOp::NixosInstall { args } => {
            let mut full = vec![
                "TMPDIR=/tmp".to_string(),
                "sudo".to_string(),
                "--non-interactive".to_string(),
                "nixos-install".to_string(),
            ];
            full.extend(args.iter().cloned());
            session.run_checked_step(step.name, "env", &full, &step.stdin)?
        }
        StepOp::BinEnsure => run_remote_bin_ensure(session, step)?,
        StepOp::DotfilesRun {
            dotfiles_repo,
            install_user,
        } => {
            let mut result = session.dotfiles_run(dotfiles_repo, install_user, &step.stdin)?;
            result.name = step.name.to_string();
            result
        }
        StepOp::Reboot => {
            let mut result = session.schedule_reboot(3)?;
            result.name = step.name.to_string();
            result
        }
        StepOp::Program { program, args } => {
            session.run_checked_step(step.name, program, args, &step.stdin)?
        }
    };

    Ok(RemoteInstallStepOutput {
        name: result.name,
        command: step.command_line(),
        status: result.status,
        stdout: result.stdout,
        stderr: result.stderr,
    })
}

fn run_remote_bin_ensure(
    session: &mut RemoteInstallSession,
    step: &RemoteInstallStep,
) -> Result<RemoteStepResult> {
    let token = String::from_utf8(step.stdin.clone())
        .map_err(|err| format!("GitHub token is not valid UTF-8: {err}"))?;
    let mut env = Vec::new();
    if !token.is_empty() {
        env.push(("GITHUB_TOKEN".to_string(), token.clone()));
        env.push(("GITHUB_AUTH_TOKEN".to_string(), token));
    }

    let args = vec![
        "--non-interactive".to_string(),
        "--preserve-env=GITHUB_TOKEN,GITHUB_AUTH_TOKEN".to_string(),
        "chroot".to_string(),
        "/mnt".to_string(),
        "/nix/var/nix/profiles/system/sw/bin/env".to_string(),
        "PATH=/nix/var/nix/profiles/system/sw/bin:/usr/local/bin:/bin:/usr/bin".to_string(),
        "HOME=/root".to_string(),
        "USER=root".to_string(),
        "LOGNAME=root".to_string(),
        "/nix/var/nix/profiles/system/sw/bin/bin".to_string(),
        "ensure".to_string(),
    ];
    let mut result = session.run_checked_step_env(step.name, "sudo", &args, &[], &env)?;

    let bin_dir = session.run_step(
        "check system bin dir",
        "test",
        &["-d".to_string(), "/mnt/usr/local/bin".to_string()],
        &[],
    )?;
    if bin_dir.status == 0 {
        let chmod = session.run_checked_step(
            "fix system bin permissions",
            "sudo",
            &[
                "--non-interactive".to_string(),
                "find".to_string(),
                "/mnt/usr/local/bin".to_string(),
                "-maxdepth".to_string(),
                "1".to_string(),
                "-type".to_string(),
                "f".to_string(),
                "-exec".to_string(),
                "chmod".to_string(),
                "0755".to_string(),
                "{}".to_string(),
                "+".to_string(),
            ],
            &[],
        )?;
        append_step_output(&mut result.stdout, &chmod.stdout);
        append_step_output(&mut result.stderr, &chmod.stderr);
    }
    Ok(result)
}

/// Run a plan through any backend runner, enforcing the destructive-step policy
/// and reporting every lifecycle event. Used by both the remote and the local
/// install paths so gating and reporting behave identically.
pub(crate) fn execute_plan_with_runner(
    steps: &[RemoteInstallStep],
    policy: RemoteExecutionPolicy,
    reporter: &Reporter,
    mut runner: impl FnMut(&RemoteInstallStep) -> Result<RemoteInstallStepOutput>,
) -> Result<RemoteInstallExecution> {
    let mut completed = Vec::new();
    let mut destructive_steps_run = 0;
    let total = steps.len();

    for (index, step) in steps.iter().enumerate() {
        if step.destructive && destructive_steps_run >= policy.destructive_steps_allowed {
            let refused: Vec<RemoteInstallRefusal> = steps[index..]
                .iter()
                .filter(|step| step.destructive)
                .map(refusal_from_step)
                .collect();
            for refusal in &refused {
                reporter.emit(Event::StepRefused {
                    name: refusal.name.clone(),
                    command: refusal.command.clone(),
                });
            }
            return Ok(RemoteInstallExecution { completed, refused });
        }

        reporter.emit(Event::StepStarted {
            index,
            total,
            name: step.name.to_string(),
            command: step.command_line(),
            destructive: step.destructive,
        });
        let started = Instant::now();
        let output = runner(step)?;
        reporter.emit(Event::StepCompleted {
            index,
            name: output.name.clone(),
            status: output.status,
            stdout: output.stdout.clone(),
            stderr: output.stderr.clone(),
            millis: started.elapsed().as_millis(),
        });
        if output.status != 0 {
            return Err(step_failure(&output));
        }
        completed.push(output);
        if step.destructive {
            destructive_steps_run += 1;
        }
    }

    Ok(RemoteInstallExecution {
        completed,
        refused: Vec::new(),
    })
}

fn step_failure(output: &RemoteInstallStepOutput) -> String {
    let detail = if !output.stderr.is_empty() {
        output.stderr.as_str()
    } else if !output.stdout.is_empty() {
        output.stdout.as_str()
    } else {
        ""
    };
    if detail.is_empty() {
        format!("step '{}' exited with {}", output.name, output.status)
    } else {
        format!(
            "step '{}' exited with {}: {}",
            output.name, output.status, detail
        )
    }
}

fn append_step_output(target: &mut String, addition: &str) {
    if addition.is_empty() {
        return;
    }
    if !target.is_empty() {
        target.push('\n');
    }
    target.push_str(addition);
}

fn refusal_from_step(step: &RemoteInstallStep) -> RemoteInstallRefusal {
    RemoteInstallRefusal {
        name: step.name.to_string(),
        command: step.command_line(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        execute_plan_with_runner, RemoteExecutionPolicy, RemoteInstallStepOutput,
    };
    use crate::install::plan::plan_remote_install_steps;
    use crate::install::state::InstallState;
    use crate::report::{Event, Reporter};
    use std::sync::{Arc, Mutex};

    fn ok_runner(
        step: &crate::install::plan::RemoteInstallStep,
    ) -> Result<RemoteInstallStepOutput, String> {
        Ok(RemoteInstallStepOutput {
            name: step.name.to_string(),
            command: step.command_line(),
            status: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    }

    #[test]
    fn safe_mode_runs_safe_steps_then_refuses_destructive_tail() {
        let state = InstallState::sample();
        let steps = plan_remote_install_steps(&state, "/tmp/nx-source").unwrap();
        let execution = execute_plan_with_runner(
            &steps,
            RemoteExecutionPolicy::safe(),
            &Reporter::silent(),
            ok_runner,
        )
        .unwrap();

        assert_eq!(
            execution
                .completed
                .iter()
                .map(|step| step.name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "verify remote user",
                "clean up competing default routes",
                "verify flake source",
                "verify generated disko",
            ]
        );
        assert_eq!(
            execution
                .refused
                .iter()
                .map(|step| step.name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "prepare target disk",
                "apply disko layout",
                "install nixos",
                "copy system config",
                "run system bin ensure",
                "run dotfiles",
                "reboot target",
            ]
        );
    }

    #[test]
    fn confirmed_mode_runs_destructive_steps() {
        let state = InstallState::sample();
        let steps = plan_remote_install_steps(&state, "/tmp/nx-source").unwrap();
        let execution = execute_plan_with_runner(
            &steps,
            RemoteExecutionPolicy::allow_destructive_steps(usize::MAX),
            &Reporter::silent(),
            ok_runner,
        )
        .unwrap();

        assert_eq!(execution.completed.len(), steps.len());
        assert!(execution.refused.is_empty());
    }

    #[test]
    fn non_zero_step_status_stops_execution() {
        let state = InstallState::sample();
        let steps = plan_remote_install_steps(&state, "/tmp/nx-source").unwrap();
        let err = execute_plan_with_runner(
            &steps,
            RemoteExecutionPolicy::allow_destructive_steps(usize::MAX),
            &Reporter::silent(),
            |step| {
                let status = if step.name == "apply disko layout" {
                    1
                } else {
                    0
                };
                Ok(RemoteInstallStepOutput {
                    name: step.name.to_string(),
                    command: step.command_line(),
                    status,
                    stdout: String::new(),
                    stderr: "disko failed".to_string(),
                })
            },
        )
        .unwrap_err();

        assert!(err.contains("apply disko layout"));
        assert!(err.contains("disko failed"));
    }

    #[test]
    fn destructive_limit_stops_after_allowed_count() {
        let state = InstallState::sample();
        let steps = plan_remote_install_steps(&state, "/tmp/nx-source").unwrap();
        let execution = execute_plan_with_runner(
            &steps,
            RemoteExecutionPolicy::allow_destructive_steps(1),
            &Reporter::silent(),
            ok_runner,
        )
        .unwrap();

        assert_eq!(execution.completed.len(), 5);
        assert_eq!(execution.refused.len(), 6);
    }

    #[test]
    fn emits_lifecycle_events_in_order() {
        let state = InstallState::sample();
        let steps = plan_remote_install_steps(&state, "/tmp/nx-source").unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let reporter = Reporter::new(move |event| sink.lock().unwrap().push(event));

        execute_plan_with_runner(&steps, RemoteExecutionPolicy::safe(), &reporter, ok_runner)
            .unwrap();

        let events = seen.lock().unwrap();
        // 4 safe steps -> Started+Completed each, then refusals for the destructive tail.
        let mut iter = events.iter();
        for expected_index in 0..4usize {
            match iter.next().unwrap() {
                Event::StepStarted { index, total, .. } => {
                    assert_eq!(*index, expected_index);
                    assert_eq!(*total, steps.len());
                }
                event => panic!("expected StepStarted, got {event:?}"),
            }
            match iter.next().unwrap() {
                Event::StepCompleted { index, status, .. } => {
                    assert_eq!(*index, expected_index);
                    assert_eq!(*status, 0);
                }
                event => panic!("expected StepCompleted, got {event:?}"),
            }
        }
        assert!(matches!(iter.next().unwrap(), Event::StepRefused { .. }));
    }
}
