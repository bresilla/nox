//! Structured install/progress events.
//!
//! Everything the installer wants to tell the user flows through a [`Reporter`]
//! instead of ad-hoc `println!`. The default text reporter reproduces the
//! classic CLI output; a TUI installs its own sink (e.g. an mpsc sender) and
//! renders the same events live. Both the SSH client (streamed remote output)
//! and the step executors (local and remote) emit through this one channel, so
//! the two sides report everything to whoever is watching.

use std::io::Write;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A coarse phase of the run: bootstrap, transfer, execute…
    Phase { name: String },
    /// Free-form progress note (bootstrap messages, transferred files…).
    Note { message: String },
    StepStarted {
        index: usize,
        total: usize,
        name: String,
        command: String,
        destructive: bool,
    },
    /// Live output chunk from the currently running step (remote stream or
    /// local pipe). Arrives between StepStarted and StepCompleted.
    StepOutput { stream: Stream, chunk: Vec<u8> },
    StepCompleted {
        index: usize,
        name: String,
        status: u32,
        stdout: String,
        stderr: String,
        millis: u128,
    },
    StepRefused { name: String, command: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// Cloneable handle delivering events to one sink. Cheap to clone and share
/// between the executor and the transport (both report into the same sink).
#[derive(Clone)]
pub struct Reporter {
    sink: Arc<dyn Fn(Event) + Send + Sync>,
}

impl Reporter {
    pub fn new(sink: impl Fn(Event) + Send + Sync + 'static) -> Self {
        Self {
            sink: Arc::new(sink),
        }
    }

    /// The classic CLI renderer: prints events as the installer always has.
    pub fn text() -> Self {
        Self::new(render_text_event)
    }

    /// Drops every event. Useful in tests and for headless runs.
    #[allow(dead_code)]
    pub fn silent() -> Self {
        Self::new(|_| {})
    }

    pub fn emit(&self, event: Event) {
        (self.sink)(event);
    }

    pub fn phase(&self, name: impl Into<String>) {
        self.emit(Event::Phase { name: name.into() });
    }

    pub fn note(&self, message: impl Into<String>) {
        self.emit(Event::Note {
            message: message.into(),
        });
    }

    pub fn output(&self, stream: Stream, chunk: &[u8]) {
        self.emit(Event::StepOutput {
            stream,
            chunk: chunk.to_vec(),
        });
    }
}

impl Default for Reporter {
    fn default() -> Self {
        Self::text()
    }
}

fn render_text_event(event: Event) {
    match event {
        Event::Phase { name } => println!("=== {name} ==="),
        Event::Note { message } => println!("{message}"),
        Event::StepStarted { name, command, .. } => {
            println!("running: {name} :: {command}");
        }
        Event::StepOutput { stream, chunk } => match stream {
            Stream::Stdout => {
                let _ = std::io::stdout().write_all(&chunk);
                let _ = std::io::stdout().flush();
            }
            Stream::Stderr => {
                let _ = std::io::stderr().write_all(&chunk);
                let _ = std::io::stderr().flush();
            }
        },
        Event::StepCompleted {
            name,
            status,
            stdout,
            stderr,
            ..
        } => {
            println!("completed: {name} status={status}");
            if !stdout.is_empty() {
                println!("  stdout: {stdout}");
            }
            if !stderr.is_empty() {
                println!("  stderr: {stderr}");
            }
        }
        Event::StepRefused { name, command } => {
            println!("refused destructive step: {name} :: {command}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Event, Reporter, Stream};
    use std::sync::{Arc, Mutex};

    #[test]
    fn reporter_delivers_events_to_sink() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let reporter = Reporter::new(move |event| sink.lock().unwrap().push(event));

        reporter.phase("execute");
        reporter.note("hello");
        reporter.output(Stream::Stdout, b"chunk");

        let events = seen.lock().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(
            events[0],
            Event::Phase {
                name: "execute".to_string()
            }
        );
        assert!(matches!(
            &events[2],
            Event::StepOutput { stream: Stream::Stdout, chunk } if chunk == b"chunk"
        ));
    }

    #[test]
    fn cloned_reporters_share_one_sink() {
        let seen = Arc::new(Mutex::new(0usize));
        let sink = Arc::clone(&seen);
        let reporter = Reporter::new(move |_| *sink.lock().unwrap() += 1);
        let clone = reporter.clone();

        reporter.note("a");
        clone.note("b");

        assert_eq!(*seen.lock().unwrap(), 2);
    }
}
