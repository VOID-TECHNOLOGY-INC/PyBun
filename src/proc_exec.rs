//! Shared process spawn/timeout/kill helper.
//!
//! `sandbox::execute_sandboxed` and `test_executor::run_with_timeout` used to
//! independently implement the same ~40 lines of process-management logic:
//! spawn a child, drain its stdout/stderr on background threads (so a chatty
//! process can't deadlock on a full pipe buffer), poll for exit, and kill the
//! child if it exceeds a wall-clock timeout. This module is the single
//! implementation both call sites delegate to (Issue #273).

use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Outcome of running a command to completion, possibly subject to a
/// wall-clock timeout.
pub enum ProcExecOutcome {
    /// The process exited on its own (or no timeout was configured).
    Completed {
        status: ExitStatus,
        /// `Some` only when `capture` was requested by the caller.
        stdout: Option<Vec<u8>>,
        stderr: Option<Vec<u8>>,
    },
    /// The process was killed because it exceeded the configured timeout.
    TimedOut,
}

/// Spawn `cmd`, optionally capturing stdout/stderr, and kill it if it runs
/// longer than `timeout_secs` (`None` or `Some(0)` means unlimited). Reader
/// threads drain the pipes concurrently so a chatty process can't deadlock on
/// a full pipe buffer while we poll for exit.
pub fn spawn_with_timeout(
    cmd: &mut Command,
    timeout_secs: Option<u64>,
    capture: bool,
) -> std::io::Result<ProcExecOutcome> {
    if capture {
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
    }

    let mut child = cmd.spawn()?;

    let stdout_handle = child.stdout.take().map(spawn_pipe_reader);
    let stderr_handle = child.stderr.take().map(spawn_pipe_reader);

    let timeout = timeout_secs
        .filter(|&secs| secs > 0)
        .map(Duration::from_secs);
    let poll_interval = Duration::from_millis(50);
    let start = Instant::now();

    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }

        if let Some(timeout) = timeout
            && start.elapsed() >= timeout
        {
            let _ = child.kill();
            let _ = child.wait();
            join_pipe_reader(stdout_handle);
            join_pipe_reader(stderr_handle);
            return Ok(ProcExecOutcome::TimedOut);
        }

        thread::sleep(poll_interval);
    };

    let stdout = join_pipe_reader(stdout_handle);
    let stderr = join_pipe_reader(stderr_handle);

    Ok(ProcExecOutcome::Completed {
        status,
        stdout,
        stderr,
    })
}

/// Spawn a thread that reads a child process pipe to completion.
pub fn spawn_pipe_reader<R>(mut reader: R) -> thread::JoinHandle<Vec<u8>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf);
        buf
    })
}

/// Join a pipe reader thread, discarding the handle. Returns `None` if there
/// was no pipe to read or the thread panicked.
pub fn join_pipe_reader(handle: Option<thread::JoinHandle<Vec<u8>>>) -> Option<Vec<u8>> {
    handle.and_then(|h| h.join().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completes_normally_before_timeout() {
        let mut cmd = Command::new("true");
        let outcome = spawn_with_timeout(&mut cmd, Some(5), false).expect("spawn should succeed");
        match outcome {
            ProcExecOutcome::Completed { status, .. } => {
                assert!(status.success());
            }
            ProcExecOutcome::TimedOut => panic!("expected process to complete, not time out"),
        }
    }

    #[test]
    fn captures_stdout_and_stderr_when_requested() {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("echo out; echo err 1>&2");
        let outcome = spawn_with_timeout(&mut cmd, None, true).expect("spawn should succeed");
        match outcome {
            ProcExecOutcome::Completed {
                status,
                stdout,
                stderr,
            } => {
                assert!(status.success());
                assert_eq!(stdout.unwrap(), b"out\n");
                assert_eq!(stderr.unwrap(), b"err\n");
            }
            ProcExecOutcome::TimedOut => panic!("expected process to complete, not time out"),
        }
    }

    #[test]
    fn does_not_capture_when_capture_is_false() {
        let mut cmd = Command::new("true");
        let outcome = spawn_with_timeout(&mut cmd, None, false).expect("spawn should succeed");
        match outcome {
            ProcExecOutcome::Completed { stdout, stderr, .. } => {
                assert!(stdout.is_none());
                assert!(stderr.is_none());
            }
            ProcExecOutcome::TimedOut => panic!("expected process to complete, not time out"),
        }
    }

    #[test]
    fn kills_process_that_exceeds_timeout() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let start = Instant::now();
        let outcome = spawn_with_timeout(&mut cmd, Some(1), false).expect("spawn should succeed");
        assert!(matches!(outcome, ProcExecOutcome::TimedOut));
        // Should return well before the process's own 30s duration.
        assert!(start.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn zero_timeout_means_unlimited() {
        let mut cmd = Command::new("true");
        let outcome = spawn_with_timeout(&mut cmd, Some(0), false).expect("spawn should succeed");
        match outcome {
            ProcExecOutcome::Completed { status, .. } => assert!(status.success()),
            ProcExecOutcome::TimedOut => panic!("timeout_secs=0 must mean unlimited"),
        }
    }

    #[test]
    fn no_timeout_runs_to_completion() {
        let mut cmd = Command::new("true");
        let outcome = spawn_with_timeout(&mut cmd, None, false).expect("spawn should succeed");
        match outcome {
            ProcExecOutcome::Completed { status, .. } => assert!(status.success()),
            ProcExecOutcome::TimedOut => panic!("no timeout must mean unlimited"),
        }
    }
}
