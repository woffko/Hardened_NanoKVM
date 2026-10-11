//! Stops HDMI capture after a configurable time without viewers and resumes it
//! when one connects. Rust counterpart of the idle handling in sipeed/NanoKVM
//! b587b9f.

use std::{collections::HashMap, fs, path::Path, sync::OnceLock, time::Duration};

use tokio::{
    sync::mpsc,
    time::{Instant, sleep_until},
};
use tracing::{debug, warn};

use crate::{AppError, Result, ffi::kvm};

pub const IDLE_TIMEOUT_FILE: &str = "/etc/kvm/hdmi_idle_timeout";
pub const MAX_IDLE_TIMEOUT_MINUTES: u32 = 7 * 24 * 60;

static CONTROLLER: OnceLock<mpsc::UnboundedSender<Command>> = OnceLock::new();

#[derive(Debug)]
enum Command {
    Viewers { source: &'static str, count: usize },
    CaptureEnabled,
    CaptureDisabled,
    TimeoutChanged,
}

#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// Nothing to schedule.
    Idle,
    /// Arm the idle timer.
    Arm(Duration),
    /// Capture was stopped for idle and a viewer is back.
    Resume,
}

/// Decides what the controller should do for the current demand. `stopped`
/// is whether capture is currently stopped because of idle.
fn plan(has_demand: bool, stopped: bool, disabled: bool, timeout_minutes: u32) -> Plan {
    if has_demand {
        if stopped && !disabled {
            return Plan::Resume;
        }
        return Plan::Idle;
    }
    if stopped || disabled || timeout_minutes == 0 {
        return Plan::Idle;
    }
    Plan::Arm(Duration::from_secs(u64::from(timeout_minutes) * 60))
}

/// Starts the controller. Must be called from within the tokio runtime.
pub fn start() {
    let (tx, rx) = mpsc::unbounded_channel();
    if CONTROLLER.set(tx).is_err() {
        return;
    }
    tokio::spawn(run(rx));
    send(Command::CaptureEnabled);
}

/// Reports the authoritative viewer count of one stream source.
pub fn report_viewers(source: &'static str, count: usize) {
    send(Command::Viewers { source, count });
}

/// HDMI was enabled by the user or at startup.
pub fn capture_enabled() {
    send(Command::CaptureEnabled);
}

/// HDMI was disabled by the user.
pub fn capture_disabled() {
    send(Command::CaptureDisabled);
}

pub fn idle_timeout_minutes() -> u32 {
    let Ok(raw) = fs::read_to_string(IDLE_TIMEOUT_FILE) else {
        return 0;
    };
    match raw.trim().parse::<u32>() {
        Ok(minutes) if minutes <= MAX_IDLE_TIMEOUT_MINUTES => minutes,
        _ => {
            warn!("invalid hdmi idle timeout; using default");
            0
        }
    }
}

pub fn set_idle_timeout(minutes: u32) -> Result<()> {
    if minutes > MAX_IDLE_TIMEOUT_MINUTES {
        return Err(AppError::BadRequest("invalid arguments".to_string()));
    }
    fs::write(IDLE_TIMEOUT_FILE, minutes.to_string())?;
    send(Command::TimeoutChanged);
    Ok(())
}

fn send(command: Command) {
    if let Some(tx) = CONTROLLER.get() {
        let _ = tx.send(command);
    }
}

fn hdmi_disabled() -> bool {
    Path::new(kvm::HDMI_DISABLE_FILE).exists()
}

async fn set_hdmi(enabled: bool) {
    match tokio::task::spawn_blocking(move || kvm::set_hdmi(enabled)).await {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => warn!(error = ?err, enabled, "failed to switch hdmi capture"),
        Err(err) => warn!(error = ?err, enabled, "hdmi capture task failed"),
    }
}

struct State {
    viewers: HashMap<&'static str, usize>,
    stopped_for_idle: bool,
    deadline: Option<Instant>,
}

impl State {
    fn has_demand(&self) -> bool {
        self.viewers.values().any(|count| *count > 0)
    }

    async fn reconcile(&mut self) {
        self.deadline = None;
        match plan(
            self.has_demand(),
            self.stopped_for_idle,
            hdmi_disabled(),
            idle_timeout_minutes(),
        ) {
            Plan::Idle => {}
            Plan::Arm(after) => self.deadline = Some(Instant::now() + after),
            Plan::Resume => {
                set_hdmi(true).await;
                self.stopped_for_idle = false;
                debug!("resumed hdmi capture after viewer connected");
            }
        }
    }

    async fn handle(&mut self, command: Command) {
        match command {
            Command::Viewers { source, count } => {
                self.viewers.insert(source, count);
            }
            Command::CaptureEnabled => self.stopped_for_idle = false,
            Command::CaptureDisabled => {
                self.stopped_for_idle = false;
                self.deadline = None;
                return;
            }
            Command::TimeoutChanged => {}
        }
        self.reconcile().await;
    }

    async fn expire(&mut self) {
        self.deadline = None;
        if self.has_demand() || hdmi_disabled() {
            return;
        }
        set_hdmi(false).await;
        self.stopped_for_idle = true;
        debug!("disabled hdmi capture after idle timeout");
    }
}

async fn run(mut rx: mpsc::UnboundedReceiver<Command>) {
    let mut state = State {
        viewers: HashMap::new(),
        stopped_for_idle: false,
        deadline: None,
    };

    loop {
        let timer = async {
            match state.deadline {
                Some(deadline) => sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            command = rx.recv() => match command {
                Some(command) => state.handle(command).await,
                None => return,
            },
            () = timer => state.expire().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    #[test]
    fn arms_timer_only_without_demand() {
        assert_eq!(plan(false, false, false, 60), Plan::Arm(HOUR));
        assert_eq!(plan(true, false, false, 60), Plan::Idle);
    }

    #[test]
    fn zero_timeout_never_arms() {
        assert_eq!(plan(false, false, false, 0), Plan::Idle);
    }

    #[test]
    fn disabled_or_stopped_never_arms() {
        assert_eq!(plan(false, false, true, 60), Plan::Idle);
        assert_eq!(plan(false, true, false, 60), Plan::Idle);
    }

    #[test]
    fn viewer_resumes_capture_stopped_for_idle() {
        assert_eq!(plan(true, true, false, 60), Plan::Resume);
    }

    #[test]
    fn viewer_does_not_resume_user_disabled_hdmi() {
        assert_eq!(plan(true, true, true, 60), Plan::Idle);
    }

    #[test]
    fn rejects_out_of_range_timeout() {
        assert!(set_idle_timeout(MAX_IDLE_TIMEOUT_MINUTES + 1).is_err());
    }
}
