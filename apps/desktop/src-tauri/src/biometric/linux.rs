//! Fingerprint unlock through fprintd (`net.reactivated.Fprint`) on the
//! system bus, using our own small D-Bus client (`dbus.rs`).
//!
//! fprintd draws no prompt of its own, so the app shows "touch the sensor"
//! while [`verify`] runs, and [`cancel`] stops it. Without fprintd, a reader
//! or an enrolled finger, the kind is `None` and the feature stays hidden.
//! fprintd's polkit rule lets the active local session verify without a
//! password, as the login screen does.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::dbus::{Connection, DbusError, Value, BUS_NAME};
use super::{BiometryKind, PresenceError};

const SERVICE: &str = "net.reactivated.Fprint";
const MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
const MANAGER: &str = "net.reactivated.Fprint.Manager";
const DEVICE: &str = "net.reactivated.Fprint.Device";

/// Scans allowed before the check fails, like the fprintd PAM module.
const ATTEMPTS: u32 = 3;
/// How long one attempt waits for a finger.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
/// How often a waiting verify looks at the cancel flag.
const POLL: Duration = Duration::from_millis(250);

static CANCEL: AtomicBool = AtomicBool::new(false);

/// The calling user's id, for the bus's EXTERNAL authentication.
fn current_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    // /proc/self belongs to the process's effective user.
    std::fs::metadata("/proc/self").ok().map(|m| m.uid())
}

/// Connects and resolves fprintd's unique name. Every call goes to that
/// name, so `Connection::call` accepts replies only from fprintd itself, and
/// only its signals are believed (see `wait_for_scan`).
fn connect() -> Result<(Connection, String), DbusError> {
    let uid = current_uid().ok_or(DbusError::Protocol("no /proc/self"))?;
    let mut bus = Connection::system(uid)?;
    // fprintd is started on demand by the bus; a call to its well-known name
    // starts it (the reply itself is not trusted or needed).
    let _ = bus.call(SERVICE, "/", "org.freedesktop.DBus.Peer", "Ping", &[]);
    let fprintd = bus.name_owner(SERVICE)?;
    Ok((bus, fprintd))
}

/// The default reader's object path.
fn default_device(bus: &mut Connection, fprintd: &str) -> Result<String, DbusError> {
    let reply = bus.call(fprintd, MANAGER_PATH, MANAGER, "GetDefaultDevice", &[])?;
    reply
        .first()
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(DbusError::Protocol("GetDefaultDevice returned no path"))
}

/// Whether the current user ("" in fprintd) has an enrolled finger.
fn has_enrolled_finger(bus: &mut Connection, fprintd: &str, device: &str) -> Result<bool, DbusError> {
    let reply = bus.call(fprintd, device, DEVICE, "ListEnrolledFingers", &[""])?;
    Ok(matches!(reply.first(), Some(Value::Array(fingers)) if !fingers.is_empty()))
}

pub fn kind() -> BiometryKind {
    let found = connect().and_then(|(mut bus, fprintd)| {
        let device = default_device(&mut bus, &fprintd)?;
        has_enrolled_finger(&mut bus, &fprintd, &device)
    });
    match found {
        Ok(true) => BiometryKind::Fingerprint,
        _ => BiometryKind::None,
    }
}

/// Stops a running [`verify`], which then returns `Cancelled`.
pub fn cancel() {
    CANCEL.store(true, Ordering::SeqCst);
}

fn map_remote(name: &str) -> PresenceError {
    match name.rsplit('.').next().unwrap_or_default() {
        "NoEnrolledPrints" | "NoSuchDevice" => PresenceError::Unavailable,
        "AlreadyInUse" => PresenceError::Busy,
        "PermissionDenied" => {
            PresenceError::Other("The system did not allow fingerprint checks for this session.".into())
        }
        _ => PresenceError::Other("The fingerprint reader reported an error.".into()),
    }
}

fn map_error(err: DbusError) -> PresenceError {
    match err {
        DbusError::Remote(name, _) => map_remote(&name),
        DbusError::Io(_) => PresenceError::Unavailable,
        DbusError::TimedOut => PresenceError::Other("The fingerprint reader did not answer.".into()),
        DbusError::Protocol(_) => PresenceError::Other("The fingerprint service sent an unexpected reply.".into()),
    }
}

/// How one scan ended.
enum Scan {
    Match,
    NoMatch,
}

/// Waits for the end of one verify attempt on `device`. Only a VerifyStatus
/// that fprintd itself sent counts: the AddMatch `sender=` filter applies to
/// broadcasts only, and any local process may address a signal to us.
fn wait_for_scan(bus: &mut Connection, fprintd: &str, device: &str) -> Result<Scan, PresenceError> {
    let deadline = Instant::now() + ATTEMPT_TIMEOUT;
    loop {
        if CANCEL.load(Ordering::SeqCst) {
            return Err(PresenceError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(PresenceError::Other("No finger was detected. Try again.".into()));
        }
        let signal = match bus.next_signal(POLL) {
            Ok(signal) => signal,
            Err(DbusError::TimedOut) => continue,
            Err(err) => return Err(map_error(err)),
        };
        if !signal.is_signal(DEVICE, "VerifyStatus")
            || signal.path.as_deref() != Some(device)
            || !bus.is_from(&signal, fprintd)
        {
            continue;
        }
        let result = signal.body.first().and_then(Value::as_str).unwrap_or_default();
        let done = matches!(signal.body.get(1), Some(Value::Bool(true)));
        match result {
            "verify-match" => return Ok(Scan::Match),
            "verify-no-match" => return Ok(Scan::NoMatch),
            "verify-disconnected" => return Err(PresenceError::Unavailable),
            "verify-unknown-error" => {
                return Err(PresenceError::Other("The fingerprint reader reported an error.".into()))
            }
            // retry-scan, swipe-too-short, finger-not-centered, remove-and-retry:
            // the reader keeps waiting unless it says it is done.
            _ if done => return Ok(Scan::NoMatch),
            _ => {}
        }
    }
}

fn verify_claimed(bus: &mut Connection, fprintd: &str, device: &str) -> Result<(), PresenceError> {
    for _ in 0..ATTEMPTS {
        bus.call(fprintd, device, DEVICE, "VerifyStart", &["any"]).map_err(map_error)?;
        let scan = wait_for_scan(bus, fprintd, device);
        let _ = bus.call(fprintd, device, DEVICE, "VerifyStop", &[]);
        match scan? {
            Scan::Match => return Ok(()),
            Scan::NoMatch => continue,
        }
    }
    Err(PresenceError::Failed)
}

pub fn verify(_reason: &str) -> Result<(), PresenceError> {
    CANCEL.store(false, Ordering::SeqCst);
    let (mut bus, fprintd) = connect().map_err(map_error)?;
    let device = default_device(&mut bus, &fprintd).map_err(map_error)?;

    let rule = format!(
        "type='signal',sender='{fprintd}',interface='{DEVICE}',member='VerifyStatus',path='{device}'"
    );
    bus.call(BUS_NAME, "/org/freedesktop/DBus", BUS_NAME, "AddMatch", &[&rule]).map_err(map_error)?;

    bus.call(&fprintd, &device, DEVICE, "Claim", &[""]).map_err(map_error)?;
    let result = verify_claimed(&mut bus, &fprintd, &device);
    let _ = bus.call(&fprintd, &device, DEVICE, "Release", &[]);
    result
}
