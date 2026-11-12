// SPDX-License-Identifier: AGPL-3.0-only
//! Web host for the CtrlAltNotes backend. Deliberately tiny and dependency-free (std only):
//! a localhost-only HTTP/1.1 server that exposes exactly
//!   * `GET  /` and the four static UI files (embedded in the binary), and
//!   * `POST /api/<command>` with a JSON body, forwarded to `Service::dispatch`.
//!
//! Hardening (each item has a test in `tests/http.rs`):
//!   * binds 127.0.0.1 only (never reachable from the network);
//!   * every /api call needs `Authorization: Bearer <256-bit launch token>`, compared in
//!     constant time. The token is handed to the browser in the URL *fragment*, which browsers
//!     never send to servers or put in Referer headers;
//!   * Host is pinned (DNS-rebinding defence) and a present Origin must be ours (CSRF);
//!   * JSON-only bodies, hard limits on header size, body size, connections and time;
//!   * request smuggling surface removed: Transfer-Encoding and duplicate/odd Content-Length
//!     are rejected, one request per connection (`Connection: close`);
//!   * strict CSP (no inline script/style, nothing remote), no caching, no sniffing;
//!   * no API accepts a file-system path: paths only ever come from launch flags.
#![forbid(unsafe_code)]

use ctrlaltnotes_core::crypto::random_bytes;
use ctrlaltnotes_service::{to_json, ApiError, Service, ServiceConfig, SyncTarget};
use serde_json::{Map, Value};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const MAX_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_BODY_BYTES: usize = 6 * 1024 * 1024;
pub const MAX_CONNECTIONS: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// A whole request (head + body) must arrive within this, however slowly it is dripped in.
static REQUEST_DEADLINE_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(20_000);

/// Tests shorten the overall request deadline; the apps never call this.
#[doc(hidden)]
pub fn set_request_deadline_ms(ms: u64) {
    REQUEST_DEADLINE_MS.store(ms, Ordering::SeqCst);
}

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const STATIC_FILES: [(&str, &[u8], &str); 12] = [
    (
        "/",
        include_bytes!("../../../ui/index.html"),
        "text/html; charset=utf-8",
    ),
    (
        "/app.css",
        include_bytes!("../../../ui/app.css"),
        "text/css; charset=utf-8",
    ),
    (
        "/theme.js",
        include_bytes!("../../../ui/theme.js"),
        "text/javascript; charset=utf-8",
    ),
    (
        "/md.js",
        include_bytes!("../../../ui/md.js"),
        "text/javascript; charset=utf-8",
    ),
    (
        "/api.js",
        include_bytes!("../../../ui/api.js"),
        "text/javascript; charset=utf-8",
    ),
    (
        "/quick.js",
        include_bytes!("../../../ui/quick.js"),
        "text/javascript; charset=utf-8",
    ),
    (
        "/app.js",
        include_bytes!("../../../ui/app.js"),
        "text/javascript; charset=utf-8",
    ),
    (
        "/icon.svg",
        include_bytes!("../../../ui/icon.svg"),
        "image/svg+xml",
    ),
    (
        "/logo.svg",
        include_bytes!("../../../ui/logo.svg"),
        "image/svg+xml",
    ),
    (
        "/logo-dark.svg",
        include_bytes!("../../../ui/logo-dark.svg"),
        "image/svg+xml",
    ),
    (
        "/favicon.ico",
        include_bytes!("../../../ui/favicon.ico"),
        "image/x-icon",
    ),
    (
        "/favicon.png",
        include_bytes!("../../../ui/favicon.png"),
        "image/png",
    ),
];

pub struct WebConfig {
    pub vault_dir: std::path::PathBuf,
    pub sync: Option<SyncTarget>,
    /// 0 = pick a random free port.
    pub port: u16,
    pub idle_lock: Duration,
    pub kdf: Option<ctrlaltnotes_core::KdfParams>,
}

pub struct Running {
    pub port: u16,
    pub token: String,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    service: Arc<Service>,
}

impl Running {
    /// URL to open in the browser. The token lives in the fragment (never sent over the wire).
    pub fn url(&self) -> String {
        format!("http://localhost:{}/#{}", self.port, self.token)
    }

    /// Block until the server stops (it normally runs until the process is killed).
    pub fn wait(mut self) {
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }

    pub fn service(&self) -> &Arc<Service> {
        &self.service
    }

    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, self.port)));
        let _ = TcpStream::connect_timeout(
            &SocketAddr::from((Ipv6Addr::LOCALHOST, self.port)),
            Duration::from_millis(200),
        );
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        self.service.lock_now();
    }
}

pub fn start(cfg: WebConfig) -> std::io::Result<Running> {
    // preferences live next to the vault folder, e.g. `.../vault` -> `.../vault-settings.json`
    let settings = cfg.vault_dir.file_name().map(|n| {
        cfg.vault_dir
            .with_file_name(format!("{}-settings.json", n.to_string_lossy()))
    });
    // app-wide preferences (theme) the same way: `.../vault` -> `.../vault-app.json`
    let app_state = cfg.vault_dir.file_name().map(|n| {
        cfg.vault_dir
            .with_file_name(format!("{}-app.json", n.to_string_lossy()))
    });
    let mut sc = ServiceConfig::new(cfg.vault_dir);
    sc.settings_path = settings;
    sc.app_state_path = app_state;
    sc.sync_override = cfg.sync;
    sc.idle_lock = cfg.idle_lock;
    sc.kdf = cfg.kdf;
    let service = Service::new(sc);

    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, cfg.port)))?;
    let port = listener.local_addr()?.port();
    let token = hex_token();
    let stop = Arc::new(AtomicBool::new(false));
    let active = Arc::new(AtomicUsize::new(0));

    let ctx = Arc::new(Ctx {
        service: service.clone(),
        token: token.clone(),
        port,
    });
    // `localhost` may resolve to ::1 as well: hold that address too (best effort), otherwise
    // another local process could squat on [::1]:PORT and receive the launch token.
    if let Ok(l6) = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))) {
        let (c, st, ac) = (ctx.clone(), stop.clone(), active.clone());
        std::thread::spawn(move || accept_loop(l6, st, ac, c));
    }
    let (c, st, ac) = (ctx, stop.clone(), active);
    let handle = std::thread::spawn(move || accept_loop(listener, st, ac, c));
    Ok(Running {
        port,
        token,
        stop,
        handle: Some(handle),
        service,
    })
}

fn accept_loop(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    ctx: Arc<Ctx>,
) {
    for conn in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let Ok(stream) = conn else { continue };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            drop(stream); // shed load instead of queueing
            continue;
        }
        let ctx = ctx.clone();
        let active = active.clone();
        std::thread::spawn(move || {
            let _ = handle_conn(stream, &ctx);
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// Write a private (0600) one-shot page that redirects to `url`, so the launch token never
/// appears in the argument list of the browser-opener process (visible to other local users
/// via `ps`). The caller deletes it shortly after the browser has read it.
pub fn write_launch_page(url: &str) -> std::io::Result<std::path::PathBuf> {
    use std::fs::OpenOptions;
    let name: String = random_bytes::<12>()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect();
    let path = std::env::temp_dir().join(format!("ctrlaltnotes-open-{name}.html"));
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(&path)?;
    // the URL is generated by us (http://localhost:PORT/#hex), so no escaping is needed
    let html = format!(
        "<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=\"0;url={url}\"><title>CtrlAltNotes</title><a href=\"{url}\">Open CtrlAltNotes</a>"
    );
    f.write_all(html.as_bytes())?;
    Ok(path)
}

fn hex_token() -> String {
    let b = random_bytes::<32>();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Ctx {
    service: Arc<Service>,
    token: String,
    port: u16,
}

struct Request {
    method: String,
    path: String,
    host: Option<String>,
    origin: Option<String>,
    authorization: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

enum ReqError {
    Bad,
    TooLarge,
    Io,
}

fn handle_conn(mut s: TcpStream, ctx: &Ctx) -> std::io::Result<()> {
    s.set_read_timeout(Some(IO_TIMEOUT))?;
    s.set_write_timeout(Some(IO_TIMEOUT))?;
    s.set_nodelay(true).ok();
    let req = match read_request(&mut s) {
        Ok(r) => r,
        Err(ReqError::TooLarge) => return respond(&mut s, 413, "text/plain", b"too large"),
        Err(ReqError::Bad) => return respond_json(&mut s, 400, "bad request"),
        Err(ReqError::Io) => return Ok(()),
    };
    route(&mut s, ctx, req)
}

fn route(s: &mut TcpStream, ctx: &Ctx, req: Request) -> std::io::Result<()> {
    if !host_ok(&req, ctx.port) {
        return respond_json(s, 403, "forbidden");
    }
    let path = req.path.split('?').next().unwrap_or("");
    if req.method == "GET" {
        if let Some((_, body, ctype)) = STATIC_FILES.iter().find(|(p, _, _)| *p == path) {
            return respond(s, 200, ctype, body);
        }
        return respond_json(s, 404, "not found");
    }
    let Some(cmd) = path.strip_prefix("/api/") else {
        return respond_json(s, 404, "not found");
    };
    if req.method != "POST" {
        return respond_json(s, 405, "method not allowed");
    }
    let expected = format!("Bearer {}", ctx.token);
    match &req.authorization {
        Some(a) if ct_eq(a.as_bytes(), expected.as_bytes()) => {}
        _ => return respond_json(s, 401, "unauthorized"),
    }
    if !cmd_ok(cmd) {
        return respond_json(s, 404, "not found");
    }
    let ct = req.content_type.as_deref().unwrap_or("");
    if ct.split(';').next().unwrap_or("").trim() != "application/json" {
        return respond_json(s, 415, "invalid input");
    }
    let args: Value = if req.body.is_empty() {
        Value::Object(Map::new())
    } else {
        match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(_) => return respond_json(s, 400, "invalid input"),
        }
    };
    if !args.is_object() {
        return respond_json(s, 400, "invalid input");
    }
    // The web host never supplies a host path: file-system choices are launch flags only.
    match ctx.service.dispatch(cmd, &args, None) {
        Ok(v) => respond(s, 200, "application/json", to_json(&v).as_bytes()),
        Err(e) => {
            let code = match e {
                ApiError::Locked => 423,
                ApiError::Throttled(_) => 429,
                ApiError::NotFound => 404,
                ApiError::Internal => 500,
                ApiError::Bad(_) | ApiError::Cancelled => 400,
            };
            respond_json(s, code, &e.wire())
        }
    }
}

fn cmd_ok(c: &str) -> bool {
    !c.is_empty() && c.len() <= 32 && c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

fn host_ok(r: &Request, port: u16) -> bool {
    let a = format!("127.0.0.1:{port}");
    let b = format!("localhost:{port}");
    match r.host.as_deref() {
        Some(h) if h == a || h == b => {}
        _ => return false,
    }
    match r.origin.as_deref() {
        None => true,
        Some(o) => o == format!("http://{a}") || o == format!("http://{b}"),
    }
}

/// Constant-time byte comparison (length leaks, which is fine: the token length is public).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

fn find_subslice(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn read_request(s: &mut TcpStream) -> Result<Request, ReqError> {
    let deadline =
        Instant::now() + Duration::from_millis(REQUEST_DEADLINE_MS.load(Ordering::SeqCst));
    // Re-arm the per-read timeout with whatever is left of the overall deadline, so a client
    // dripping one byte at a time (slowloris) cannot hold a connection slot open.
    let arm = |s: &TcpStream| -> Result<(), ReqError> {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(ReqError::Io);
        }
        s.set_read_timeout(Some(left.min(IO_TIMEOUT)))
            .map_err(|_| ReqError::Io)
    };
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let head_end = loop {
        if let Some(i) = find_subslice(&buf, b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(ReqError::TooLarge);
        }
        arm(s)?;
        match s.read(&mut chunk) {
            Ok(0) => return Err(ReqError::Io),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return Err(ReqError::Io),
        }
    };
    if head_end > MAX_HEADER_BYTES {
        return Err(ReqError::TooLarge);
    }
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| ReqError::Bad)?;
    let mut lines = head.split("\r\n");
    let first = lines.next().ok_or(ReqError::Bad)?;
    let mut parts = first.split(' ');
    let (method, target, version) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v), None) => (m, t, v),
        _ => return Err(ReqError::Bad),
    };
    if version != "HTTP/1.1" || !target.starts_with('/') || target.contains(['\0', '\\']) {
        return Err(ReqError::Bad);
    }
    if !method.bytes().all(|b| b.is_ascii_uppercase()) || method.is_empty() || method.len() > 8 {
        return Err(ReqError::Bad);
    }
    let (mut host, mut origin, mut auth, mut ctype) = (None, None, None, None);
    let mut clen: Option<usize> = None;
    for l in lines {
        // no obsolete line folding, no header without a colon, no whitespace before the colon
        if l.starts_with(' ') || l.starts_with('\t') {
            return Err(ReqError::Bad);
        }
        let (name, value) = l.split_once(':').ok_or(ReqError::Bad)?;
        if name.is_empty() || name.bytes().any(|b| b <= b' ' || b >= 0x7f) {
            return Err(ReqError::Bad);
        }
        let value = value.trim();
        let slot = match name.to_ascii_lowercase().as_str() {
            "host" => &mut host,
            "origin" => &mut origin,
            "authorization" => &mut auth,
            "content-type" => &mut ctype,
            "transfer-encoding" => return Err(ReqError::Bad), // never chunked: no smuggling
            "content-length" => {
                if clen.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(ReqError::Bad);
                }
                clen = Some(value.parse::<usize>().map_err(|_| ReqError::TooLarge)?);
                continue;
            }
            _ => continue,
        };
        if slot.is_some() {
            return Err(ReqError::Bad); // duplicate security-relevant header
        }
        *slot = Some(value.to_string());
    }
    let n = clen.unwrap_or(0);
    if n > MAX_BODY_BYTES {
        return Err(ReqError::TooLarge);
    }
    if method == "POST" && clen.is_none() {
        return Err(ReqError::Bad);
    }
    let mut body: Vec<u8> = buf[head_end + 4..].to_vec();
    if body.len() > n {
        return Err(ReqError::Bad); // pipelined / trailing bytes
    }
    while body.len() < n {
        let want = (n - body.len()).min(64 * 1024);
        let mut tmp = vec![0u8; want];
        arm(s)?;
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return Err(ReqError::Io),
            Ok(k) => body.extend_from_slice(&tmp[..k]),
        }
    }
    Ok(Request {
        method: method.to_string(),
        path: target.to_string(),
        host,
        origin,
        authorization: auth,
        content_type: ctype,
        body,
    })
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        423 => "Locked",
        429 => "Too Many Requests",
        _ => "Internal Server Error",
    }
}

fn respond(s: &mut TcpStream, code: u16, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {code} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
Content-Security-Policy: {CSP}\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n\
Cross-Origin-Opener-Policy: same-origin\r\nCross-Origin-Resource-Policy: same-origin\r\n\
X-Frame-Options: DENY\r\nConnection: close\r\n\r\n",
        reason(code),
        body.len()
    );
    s.write_all(head.as_bytes())?;
    s.write_all(body)?;
    s.flush()
}

fn respond_json(s: &mut TcpStream, code: u16, err: &str) -> std::io::Result<()> {
    let mut m = Map::new();
    m.insert("error".to_string(), ctrlaltnotes_core::json::vs(err));
    respond(
        s,
        code,
        "application/json",
        to_json(&Value::Object(m)).as_bytes(),
    )
}
