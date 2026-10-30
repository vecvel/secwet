//! Minimal D-Bus client: just enough of the wire protocol to talk to fprintd
//! on the system bus (method calls with string arguments, replies and signals
//! carrying strings, object paths, booleans and string arrays).
//!
//! Protocol reference: the D-Bus Specification, "Message Protocol" and
//! "Authentication Protocol". Messages are sent little-endian; replies in
//! either byte order are read.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const SYSTEM_BUS_DEFAULT: &str = "/var/run/dbus/system_bus_socket";

const METHOD_CALL: u8 = 1;
const METHOD_RETURN: u8 = 2;
const ERROR: u8 = 3;
const SIGNAL: u8 = 4;

const FIELD_PATH: u8 = 1;
const FIELD_INTERFACE: u8 = 2;
const FIELD_MEMBER: u8 = 3;
const FIELD_ERROR_NAME: u8 = 4;
const FIELD_REPLY_SERIAL: u8 = 5;
const FIELD_DESTINATION: u8 = 6;
const FIELD_SENDER: u8 = 7;
const FIELD_SIGNATURE: u8 = 8;

/// The bus daemon's own name; it is the sender of its replies and signals.
pub const BUS_NAME: &str = "org.freedesktop.DBus";

/// Messages larger than this are refused (the spec allows 128 MiB; fprintd
/// sends a few hundred bytes).
const MAX_MESSAGE: usize = 1 << 20;

/// A body value of the few types this client reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Bool(bool),
    U32(u32),
    Array(Vec<Value>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// An incoming message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    pub kind: u8,
    pub serial: u32,
    pub reply_serial: Option<u32>,
    pub path: Option<String>,
    pub interface: Option<String>,
    pub member: Option<String>,
    pub error_name: Option<String>,
    /// Unique name of the sending connection, stamped by the bus daemon (a
    /// peer cannot forge it).
    pub sender: Option<String>,
    pub destination: Option<String>,
    pub body: Vec<Value>,
}

impl Message {
    pub fn is_signal(&self, interface: &str, member: &str) -> bool {
        self.kind == SIGNAL
            && self.interface.as_deref() == Some(interface)
            && self.member.as_deref() == Some(member)
    }
}

#[derive(Debug)]
pub enum DbusError {
    Io(io::Error),
    /// The peer answered with a D-Bus error (name, message).
    Remote(String, String),
    Protocol(&'static str),
    TimedOut,
}

impl std::fmt::Display for DbusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbusError::Io(err) => write!(f, "system bus I/O error: {err}"),
            DbusError::Remote(name, message) if message.is_empty() => write!(f, "{name}"),
            DbusError::Remote(name, message) => write!(f, "{name}: {message}"),
            DbusError::Protocol(what) => write!(f, "D-Bus protocol error: {what}"),
            DbusError::TimedOut => write!(f, "the system bus did not answer in time"),
        }
    }
}

impl std::error::Error for DbusError {}

impl From<io::Error> for DbusError {
    fn from(err: io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => DbusError::TimedOut,
            _ => DbusError::Io(err),
        }
    }
}

pub type Result<T> = std::result::Result<T, DbusError>;

// ---------------------------------------------------------------------------
// Marshalling
// ---------------------------------------------------------------------------

/// Little-endian writer; offsets are from the message start, which the
/// alignment rules are relative to.
#[derive(Default)]
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn align(&mut self, n: usize) {
        while !self.buf.len().is_multiple_of(n) {
            self.buf.push(0);
        }
    }

    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn u32(&mut self, v: u32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn string(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
    }

    fn signature(&mut self, s: &str) {
        self.buf.push(s.len() as u8);
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
    }

    fn field(&mut self, code: u8, sig: &str, write: impl FnOnce(&mut Self)) {
        self.align(8);
        self.u8(code);
        self.signature(sig);
        write(self);
    }
}

/// Encodes a method call whose arguments are all strings.
pub fn encode_call(
    serial: u32,
    destination: &str,
    path: &str,
    interface: &str,
    member: &str,
    args: &[&str],
) -> Vec<u8> {
    let mut body = Writer::default();
    for arg in args {
        body.string(arg);
    }

    let mut w = Writer::default();
    w.u8(b'l');
    w.u8(METHOD_CALL);
    w.u8(0);
    w.u8(1);
    w.u32(body.buf.len() as u32);
    w.u32(serial);
    let len_at = w.buf.len();
    w.u32(0);
    let fields_start = {
        w.align(8);
        w.buf.len()
    };
    w.field(FIELD_PATH, "o", |w| w.string(path));
    w.field(FIELD_DESTINATION, "s", |w| w.string(destination));
    w.field(FIELD_INTERFACE, "s", |w| w.string(interface));
    w.field(FIELD_MEMBER, "s", |w| w.string(member));
    if !args.is_empty() {
        let sig = "s".repeat(args.len());
        w.field(FIELD_SIGNATURE, "g", |w| w.signature(&sig));
    }
    let fields_len = (w.buf.len() - fields_start) as u32;
    w.buf[len_at..len_at + 4].copy_from_slice(&fields_len.to_le_bytes());
    w.align(8);
    w.buf.extend_from_slice(&body.buf);
    w.buf
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    big_endian: bool,
}

impl<'a> Reader<'a> {
    fn align(&mut self, n: usize) -> Result<()> {
        let pad = (n - self.pos % n) % n;
        if self.pos + pad > self.buf.len() {
            return Err(DbusError::Protocol("truncated message"));
        }
        self.pos += pad;
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.buf.len())
            .ok_or(DbusError::Protocol("truncated message"))?;
        let bytes = &self.buf[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        self.align(4)?;
        let b: [u8; 4] = self.take(4)?.try_into().map_err(|_| DbusError::Protocol("bad u32"))?;
        Ok(if self.big_endian { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) })
    }

    fn string(&mut self) -> Result<String> {
        let len = self.u32()? as usize;
        let bytes = self.take(len)?.to_vec();
        self.take(1)?;
        String::from_utf8(bytes).map_err(|_| DbusError::Protocol("invalid UTF-8"))
    }

    fn signature(&mut self) -> Result<String> {
        let len = self.u8()? as usize;
        let bytes = self.take(len)?.to_vec();
        self.take(1)?;
        String::from_utf8(bytes).map_err(|_| DbusError::Protocol("invalid signature"))
    }

    /// Reads one complete type from the front of `sig`, returning the value
    /// and the rest of the signature.
    fn value<'s>(&mut self, sig: &'s str) -> Result<(Value, &'s str)> {
        let (code, rest) = sig.split_at(1);
        match code {
            "s" | "o" => Ok((Value::Str(self.string()?), rest)),
            "g" => Ok((Value::Str(self.signature()?), rest)),
            "b" => Ok((Value::Bool(self.u32()? != 0), rest)),
            "u" => Ok((Value::U32(self.u32()?), rest)),
            "a" => {
                let len = self.u32()? as usize;
                let elem = single_type(rest)?;
                self.align(type_alignment(elem))?;
                let end = self
                    .pos
                    .checked_add(len)
                    .filter(|end| *end <= self.buf.len())
                    .ok_or(DbusError::Protocol("truncated array"))?;
                let mut items = Vec::new();
                while self.pos < end {
                    let (item, _) = self.value(elem)?;
                    items.push(item);
                }
                Ok((Value::Array(items), &rest[elem.len()..]))
            }
            _ => Err(DbusError::Protocol("unsupported type")),
        }
    }
}

/// The first complete type in `sig` (only basic types and arrays of them).
fn single_type(sig: &str) -> Result<&str> {
    sig.bytes()
        .position(|c| c != b'a')
        .map(|i| &sig[..=i])
        .ok_or(DbusError::Protocol("bad signature"))
}

fn type_alignment(sig: &str) -> usize {
    match sig.as_bytes().first() {
        Some(b'g') | Some(b'y') | Some(b'v') => 1,
        Some(b'x') | Some(b't') | Some(b'd') | Some(b'(') | Some(b'{') => 8,
        _ => 4,
    }
}

/// Total length of a message from its 16-byte fixed header.
fn message_len(head: &[u8; 16]) -> Result<usize> {
    let big_endian = match head[0] {
        b'l' => false,
        b'B' => true,
        _ => return Err(DbusError::Protocol("bad byte order")),
    };
    let read = |b: &[u8]| {
        let b: [u8; 4] = b.try_into().unwrap_or_default();
        if big_endian { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }
    };
    let body = read(&head[4..8]) as usize;
    let fields = read(&head[12..16]) as usize;
    let header = (16 + fields).div_ceil(8) * 8;
    let total = header.saturating_add(body);
    if total > MAX_MESSAGE {
        return Err(DbusError::Protocol("message too large"));
    }
    Ok(total)
}

/// Decodes one complete message.
pub fn decode(buf: &[u8]) -> Result<Message> {
    let big_endian = match buf.first() {
        Some(b'l') => false,
        Some(b'B') => true,
        _ => return Err(DbusError::Protocol("bad byte order")),
    };
    let mut r = Reader { buf, pos: 1, big_endian };
    let kind = r.u8()?;
    let _flags = r.u8()?;
    let _version = r.u8()?;
    let body_len = r.u32()? as usize;
    let serial = r.u32()?;
    let fields_len = r.u32()? as usize;
    let fields_end = r.pos + fields_len;

    let mut msg = Message { kind, serial, ..Message::default() };
    let mut body_sig = String::new();
    while r.pos < fields_end {
        r.align(8)?;
        let code = r.u8()?;
        let sig = r.signature()?;
        let (value, _) = r.value(single_type(&sig)?)?;
        match (code, value) {
            (FIELD_PATH, Value::Str(s)) => msg.path = Some(s),
            (FIELD_INTERFACE, Value::Str(s)) => msg.interface = Some(s),
            (FIELD_MEMBER, Value::Str(s)) => msg.member = Some(s),
            (FIELD_ERROR_NAME, Value::Str(s)) => msg.error_name = Some(s),
            (FIELD_SENDER, Value::Str(s)) => msg.sender = Some(s),
            (FIELD_DESTINATION, Value::Str(s)) => msg.destination = Some(s),
            (FIELD_REPLY_SERIAL, Value::U32(n)) => msg.reply_serial = Some(n),
            (FIELD_SIGNATURE, Value::Str(s)) => body_sig = s,
            _ => {}
        }
    }
    r.align(8)?;
    let body_start = r.pos;
    if body_start + body_len > buf.len() {
        return Err(DbusError::Protocol("truncated body"));
    }
    let mut body = Reader { buf: &buf[..body_start + body_len], pos: body_start, big_endian };
    let mut sig = body_sig.as_str();
    while !sig.is_empty() {
        let (value, rest) = body.value(sig)?;
        msg.body.push(value);
        sig = rest;
    }
    Ok(msg)
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// The `path=` of the first `unix:` entry in a D-Bus server address.
fn unix_path(address: &str) -> Option<String> {
    address.split(';').find_map(|entry| {
        let params = entry.strip_prefix("unix:")?;
        params.split(',').find_map(|p| p.strip_prefix("path=").map(str::to_owned))
    })
}

/// Socket path of the system bus (`DBUS_SYSTEM_BUS_ADDRESS` or the default).
fn system_bus_path() -> String {
    std::env::var("DBUS_SYSTEM_BUS_ADDRESS")
        .ok()
        .and_then(|addr| unix_path(&addr))
        .unwrap_or_else(|| SYSTEM_BUS_DEFAULT.to_owned())
}

pub struct Connection {
    stream: BufReader<UnixStream>,
    serial: u32,
    /// Signals that arrived while waiting for a reply.
    pending: Vec<Message>,
    /// This connection's unique name, from `Hello`.
    unique_name: String,
}

impl Connection {
    /// Connects to the system bus as user `uid` (SASL EXTERNAL).
    pub fn system(uid: u32) -> Result<Self> {
        let stream = UnixStream::connect(system_bus_path())?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut stream = BufReader::new(stream);

        let uid_hex: String = uid.to_string().bytes().map(|b| format!("{b:02x}")).collect();
        stream.get_mut().write_all(format!("\0AUTH EXTERNAL {uid_hex}\r\n").as_bytes())?;
        let mut line = String::new();
        stream.read_line(&mut line)?;
        if !line.starts_with("OK ") {
            return Err(DbusError::Protocol("system bus refused authentication"));
        }
        stream.get_mut().write_all(b"BEGIN\r\n")?;

        let mut conn = Connection { stream, serial: 0, pending: Vec::new(), unique_name: String::new() };
        let reply = conn.call(BUS_NAME, "/org/freedesktop/DBus", BUS_NAME, "Hello", &[])?;
        conn.unique_name = reply
            .first()
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(DbusError::Protocol("Hello returned no name"))?;
        Ok(conn)
    }

    /// The unique name (":1.42") that currently owns well-known `name`.
    /// Calls sent to it are answered by that connection alone, and its
    /// signals carry it as their sender.
    pub fn name_owner(&mut self, name: &str) -> Result<String> {
        let reply = self.call(BUS_NAME, "/org/freedesktop/DBus", BUS_NAME, "GetNameOwner", &[name])?;
        reply
            .first()
            .and_then(Value::as_str)
            .filter(|owner| owner.starts_with(':'))
            .map(str::to_owned)
            .ok_or(DbusError::Protocol("GetNameOwner returned no unique name"))
    }

    /// Whether `msg` was sent by `sender` (a unique name) and addressed to
    /// this connection or broadcast. Any local peer can send this
    /// connection a signal, so a signal counts only when this holds.
    pub fn is_from(&self, msg: &Message, sender: &str) -> bool {
        msg.sender.as_deref() == Some(sender)
            && msg.destination.as_deref().is_none_or(|d| d == self.unique_name)
    }

    fn read_message(&mut self, deadline: Instant) -> Result<Message> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(DbusError::TimedOut);
        }
        self.stream.get_ref().set_read_timeout(Some(remaining))?;
        let mut head = [0u8; 16];
        self.stream.read_exact(&mut head[..1])?;
        // A message has started: give the rest its own time, so a short poll
        // never stops in the middle of one and loses the stream position.
        self.stream.get_ref().set_read_timeout(Some(Duration::from_secs(5)))?;
        self.stream.read_exact(&mut head[1..])?;
        let total = message_len(&head)?;
        let mut buf = head.to_vec();
        buf.resize(total, 0);
        self.stream.read_exact(&mut buf[16..])?;
        decode(&buf)
    }

    /// Calls a method with string arguments and waits for its reply. When
    /// `destination` is the bus or a unique name, only a reply from that very
    /// connection counts: another peer could otherwise answer first with a
    /// matching reply serial. Name a well-known service through
    /// [`Self::name_owner`] to get the same check.
    pub fn call(
        &mut self,
        destination: &str,
        path: &str,
        interface: &str,
        member: &str,
        args: &[&str],
    ) -> Result<Vec<Value>> {
        self.serial += 1;
        let serial = self.serial;
        let bytes = encode_call(serial, destination, path, interface, member, args);
        self.stream.get_mut().write_all(&bytes)?;

        let checked = destination == BUS_NAME || destination.starts_with(':');
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let msg = self.read_message(deadline)?;
            let from_peer = !checked || msg.sender.as_deref() == Some(destination);
            match msg.kind {
                METHOD_RETURN | ERROR if msg.reply_serial == Some(serial) && !from_peer => {}
                METHOD_RETURN if msg.reply_serial == Some(serial) => return Ok(msg.body),
                ERROR if msg.reply_serial == Some(serial) => {
                    let text = msg.body.first().and_then(Value::as_str).unwrap_or("").to_owned();
                    return Err(DbusError::Remote(msg.error_name.unwrap_or_default(), text));
                }
                SIGNAL => self.pending.push(msg),
                _ => {}
            }
        }
    }

    /// Waits up to `timeout` for the next signal.
    pub fn next_signal(&mut self, timeout: Duration) -> Result<Message> {
        if !self.pending.is_empty() {
            return Ok(self.pending.remove(0));
        }
        let deadline = Instant::now() + timeout;
        loop {
            let msg = self.read_message(deadline)?;
            if msg.kind == SIGNAL {
                return Ok(msg);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a little-endian message the way a bus daemon would.
    fn encode_reply(kind: u8, reply_serial: u32, sig: &str, body: impl FnOnce(&mut Writer)) -> Vec<u8> {
        let mut b = Writer::default();
        body(&mut b);
        let mut w = Writer::default();
        w.u8(b'l');
        w.u8(kind);
        w.u8(0);
        w.u8(1);
        w.u32(b.buf.len() as u32);
        w.u32(77);
        let len_at = w.buf.len();
        w.u32(0);
        w.align(8);
        let start = w.buf.len();
        w.field(FIELD_REPLY_SERIAL, "u", |w| w.u32(reply_serial));
        w.field(FIELD_SENDER, "s", |w| w.string(":1.7"));
        w.field(FIELD_DESTINATION, "s", |w| w.string(":1.42"));
        if kind == ERROR {
            w.field(FIELD_ERROR_NAME, "s", |w| w.string("net.reactivated.Fprint.Error.NoEnrolledPrints"));
        }
        w.field(FIELD_SIGNATURE, "g", |w| w.signature(sig));
        let n = (w.buf.len() - start) as u32;
        w.buf[len_at..len_at + 4].copy_from_slice(&n.to_le_bytes());
        w.align(8);
        w.buf.extend_from_slice(&b.buf);
        w.buf
    }

    #[test]
    fn call_round_trips_through_decode() {
        let bytes = encode_call(
            3,
            "net.reactivated.Fprint",
            "/net/reactivated/Fprint/Device/0",
            "net.reactivated.Fprint.Device",
            "VerifyStart",
            &["any"],
        );
        assert_eq!(bytes.len() % 8, 0, "body starts aligned and \"any\" pads to 8");
        let head: [u8; 16] = bytes[..16].try_into().unwrap();
        assert_eq!(message_len(&head).unwrap(), bytes.len());

        let msg = decode(&bytes).unwrap();
        assert_eq!(msg.kind, METHOD_CALL);
        assert_eq!(msg.serial, 3);
        assert_eq!(msg.path.as_deref(), Some("/net/reactivated/Fprint/Device/0"));
        assert_eq!(msg.interface.as_deref(), Some("net.reactivated.Fprint.Device"));
        assert_eq!(msg.member.as_deref(), Some("VerifyStart"));
        assert_eq!(msg.body, vec![Value::Str("any".into())]);
    }

    #[test]
    fn decodes_string_array_reply() {
        let bytes = encode_reply(METHOD_RETURN, 5, "as", |b| {
            let len_at = b.buf.len();
            b.u32(0);
            let start = b.buf.len();
            b.string("right-index-finger");
            b.string("left-thumb");
            let n = (b.buf.len() - start) as u32;
            b.buf[len_at..len_at + 4].copy_from_slice(&n.to_le_bytes());
        });
        let msg = decode(&bytes).unwrap();
        assert_eq!(msg.reply_serial, Some(5));
        assert_eq!(
            msg.body,
            vec![Value::Array(vec![
                Value::Str("right-index-finger".into()),
                Value::Str("left-thumb".into()),
            ])]
        );
    }

    #[test]
    fn decodes_signal_and_error_bodies() {
        let mut bytes = encode_reply(SIGNAL, 0, "sb", |b| {
            b.string("verify-match");
            b.u32(1);
        });
        let msg = decode(&bytes).unwrap();
        assert_eq!(msg.body, vec![Value::Str("verify-match".into()), Value::Bool(true)]);
        // The sender the bus stamped is what a VerifyStatus is checked against.
        assert_eq!(msg.sender.as_deref(), Some(":1.7"));
        assert_eq!(msg.destination.as_deref(), Some(":1.42"));

        bytes = encode_reply(ERROR, 9, "s", |b| b.string("No enrolled prints"));
        let msg = decode(&bytes).unwrap();
        assert_eq!(msg.error_name.as_deref(), Some("net.reactivated.Fprint.Error.NoEnrolledPrints"));
        assert_eq!(msg.body, vec![Value::Str("No enrolled prints".into())]);
    }

    #[test]
    fn rejects_truncated_and_oversized_messages() {
        let bytes = encode_call(1, "a.b", "/", "a.b", "C", &["x"]);
        assert!(decode(&bytes[..bytes.len() - 3]).is_err());

        let mut head: [u8; 16] = bytes[..16].try_into().unwrap();
        head[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(message_len(&head).is_err());
    }

    #[test]
    fn reads_system_bus_address() {
        assert_eq!(
            unix_path("tcp:host=x;unix:guid=1,path=/run/dbus/system_bus_socket").as_deref(),
            Some("/run/dbus/system_bus_socket")
        );
        assert_eq!(unix_path("unix:abstract=/tmp/x"), None);
    }
}
