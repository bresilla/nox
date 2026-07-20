//! Live install progress screen.
//!
//! The install runs on a worker thread; its [`Reporter`](crate::report::Reporter)
//! is backed by an mpsc channel, so every step lifecycle event and every chunk
//! of streamed output (local pipe or remote SSH stream) arrives here and is
//! rendered live. This is what makes `nox install` a self-contained entry
//! point: the whole install happens inside the TUI, not by dropping to raw
//! stdout.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::install::state::InstallState;
use crate::report::{Event, Reporter, Stream};
use crate::Result;

const MAX_OUTPUT_LINES: usize = 400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepStatus {
    Pending,
    Running,
    Done,
    Failed,
    Refused,
}

#[derive(Debug, Clone)]
pub struct StepView {
    pub name: String,
    pub status: StepStatus,
    pub millis: Option<u128>,
}

/// Everything the progress screen renders. Updated purely by draining reporter
/// events, so the same struct drives both the live view and the tests.
#[derive(Debug, Clone, Default)]
pub struct ProgressState {
    pub phase: String,
    pub notes: Vec<String>,
    pub steps: Vec<StepView>,
    pub output: Vec<String>,
    pub running_index: Option<usize>,
    pub total: usize,
    pub finished: bool,
    pub failed: bool,
    pub summary: Option<String>,
}

impl ProgressState {
    pub fn completed_steps(&self) -> usize {
        self.steps
            .iter()
            .filter(|step| step.status == StepStatus::Done)
            .count()
    }

    /// Fraction of steps completed, for the progress gauge.
    pub fn ratio(&self) -> f64 {
        if self.total == 0 {
            return if self.finished { 1.0 } else { 0.0 };
        }
        (self.completed_steps() as f64 / self.total as f64).clamp(0.0, 1.0)
    }

    /// Apply one reporter event. Pure, so this is unit-tested directly.
    pub fn apply(&mut self, event: Event) {
        match event {
            Event::Phase { name } => self.phase = name,
            Event::Note { message } => {
                self.notes.push(message.clone());
                self.push_output(format!("• {message}"));
            }
            Event::StepStarted {
                index,
                total,
                name,
                command,
                destructive,
            } => {
                self.total = total;
                if self.steps.len() <= index {
                    self.steps.resize(
                        index + 1,
                        StepView {
                            name: name.clone(),
                            status: StepStatus::Pending,
                            millis: None,
                        },
                    );
                }
                self.steps[index] = StepView {
                    name: name.clone(),
                    status: StepStatus::Running,
                    millis: None,
                };
                self.running_index = Some(index);
                let marker = if destructive { " [destructive]" } else { "" };
                self.push_output(format!("$ {command}{marker}"));
            }
            Event::StepOutput { stream, chunk } => {
                let text = String::from_utf8_lossy(&chunk);
                let prefix = match stream {
                    Stream::Stdout => "",
                    Stream::Stderr => "! ",
                };
                for line in text.split('\n') {
                    if !line.is_empty() {
                        self.push_output(format!("{prefix}{}", line.trim_end_matches('\r')));
                    }
                }
            }
            Event::StepCompleted {
                index,
                name,
                status,
                millis,
                ..
            } => {
                if let Some(step) = self.steps.get_mut(index) {
                    step.name = name;
                    step.status = if status == 0 {
                        StepStatus::Done
                    } else {
                        StepStatus::Failed
                    };
                    step.millis = Some(millis);
                }
                if status != 0 {
                    self.failed = true;
                }
                self.running_index = None;
            }
            Event::StepRefused { name, command } => {
                self.steps.push(StepView {
                    name,
                    status: StepStatus::Refused,
                    millis: None,
                });
                self.push_output(format!("refused (destructive gate): {command}"));
            }
        }
    }

    fn push_output(&mut self, line: String) {
        self.output.push(line);
        if self.output.len() > MAX_OUTPUT_LINES {
            let overflow = self.output.len() - MAX_OUTPUT_LINES;
            self.output.drain(0..overflow);
        }
    }
}

/// A running install: a worker thread plus the channel its reporter feeds.
pub struct InstallRun {
    receiver: Receiver<Event>,
    handle: Option<JoinHandle<Result<u8>>>,
    pub state: ProgressState,
    pub started: Instant,
}

impl InstallRun {
    /// Spawn the install on a worker thread, wiring its reporter to an mpsc
    /// channel this handle drains.
    pub fn spawn(repo: PathBuf, state: InstallState) -> Self {
        let (sender, receiver) = mpsc::channel::<Event>();
        // The Reporter sink must be Fn + Send + Sync; mpsc::Sender is Send but
        // not Sync, so guard it with a Mutex.
        let sender = Mutex::new(sender);
        let reporter = Reporter::new(move |event| {
            if let Ok(sender) = sender.lock() {
                let _ = sender.send(event);
            }
        });

        let handle = std::thread::Builder::new()
            .name("nox-install".to_string())
            .spawn(move || {
                crate::install::exec::run_confirmed_with_reporter(&repo, &state, &reporter)
            })
            .expect("failed to spawn install thread");

        Self {
            receiver,
            handle: Some(handle),
            state: ProgressState::default(),
            started: Instant::now(),
        }
    }

    /// Drain all pending events into the progress state. Returns true if any
    /// event was applied (i.e. a redraw is warranted).
    pub fn pump(&mut self) -> bool {
        let mut changed = false;
        loop {
            match self.receiver.try_recv() {
                Ok(event) => {
                    self.state.apply(event);
                    changed = true;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    // Worker finished and dropped its reporter; collect the
                    // result exactly once.
                    if self.handle.is_some() {
                        self.finish();
                        changed = true;
                    }
                    break;
                }
            }
        }
        changed
    }

    fn finish(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        // Drain anything still queued before the channel closed.
        while let Ok(event) = self.receiver.try_recv() {
            self.state.apply(event);
        }
        self.state.finished = true;
        match handle.join() {
            Ok(Ok(0)) => {
                self.state.summary = Some("install complete".to_string());
            }
            Ok(Ok(_)) => {
                self.state.failed = true;
                self.state.summary =
                    Some("install stopped: destructive steps were refused".to_string());
            }
            Ok(Err(err)) => {
                self.state.failed = true;
                self.state.summary = Some(format!("install failed: {err}"));
            }
            Err(_) => {
                self.state.failed = true;
                self.state.summary = Some("install thread panicked".to_string());
            }
        }
    }

    pub fn is_finished(&self) -> bool {
        self.state.finished
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Event, Stream};

    fn started(index: usize, total: usize, name: &str) -> Event {
        Event::StepStarted {
            index,
            total,
            name: name.to_string(),
            command: format!("cmd-{name}"),
            destructive: false,
        }
    }

    fn completed(index: usize, name: &str, status: u32) -> Event {
        Event::StepCompleted {
            index,
            name: name.to_string(),
            status,
            stdout: String::new(),
            stderr: String::new(),
            millis: 12,
        }
    }

    #[test]
    fn tracks_step_lifecycle_and_ratio() {
        let mut state = ProgressState::default();
        state.apply(Event::Phase {
            name: "execute".to_string(),
        });
        state.apply(started(0, 2, "wipe"));
        assert_eq!(state.phase, "execute");
        assert_eq!(state.running_index, Some(0));
        assert_eq!(state.steps[0].status, StepStatus::Running);
        assert_eq!(state.ratio(), 0.0);

        state.apply(completed(0, "wipe", 0));
        assert_eq!(state.steps[0].status, StepStatus::Done);
        assert_eq!(state.running_index, None);
        assert_eq!(state.ratio(), 0.5);

        state.apply(started(1, 2, "install"));
        state.apply(completed(1, "install", 0));
        assert_eq!(state.ratio(), 1.0);
        assert!(!state.failed);
    }

    #[test]
    fn non_zero_status_marks_failure() {
        let mut state = ProgressState::default();
        state.apply(started(0, 1, "disko"));
        state.apply(completed(0, "disko", 1));
        assert!(state.failed);
        assert_eq!(state.steps[0].status, StepStatus::Failed);
    }

    #[test]
    fn output_streams_split_into_lines_and_cap() {
        let mut state = ProgressState::default();
        state.apply(started(0, 1, "install"));
        state.apply(Event::StepOutput {
            stream: Stream::Stdout,
            chunk: b"line one\nline two\n".to_vec(),
        });
        assert!(state.output.iter().any(|line| line == "line one"));
        assert!(state.output.iter().any(|line| line == "line two"));

        state.apply(Event::StepOutput {
            stream: Stream::Stderr,
            chunk: b"warning here\n".to_vec(),
        });
        assert!(state.output.iter().any(|line| line == "! warning here"));

        for n in 0..(MAX_OUTPUT_LINES + 50) {
            state.apply(Event::StepOutput {
                stream: Stream::Stdout,
                chunk: format!("l{n}\n").into_bytes(),
            });
        }
        assert!(state.output.len() <= MAX_OUTPUT_LINES);
    }

    #[test]
    fn refused_steps_are_recorded() {
        let mut state = ProgressState::default();
        state.apply(Event::StepRefused {
            name: "reboot".to_string(),
            command: "nox-agent reboot-target".to_string(),
        });
        assert_eq!(state.steps.last().unwrap().status, StepStatus::Refused);
    }

    #[test]
    fn notes_appear_in_output_and_list() {
        let mut state = ProgressState::default();
        state.apply(Event::Note {
            message: "bootstrap: ready".to_string(),
        });
        assert_eq!(state.notes, vec!["bootstrap: ready".to_string()]);
        assert!(state.output.iter().any(|line| line.contains("bootstrap: ready")));
    }
}
