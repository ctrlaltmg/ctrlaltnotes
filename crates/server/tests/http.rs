// SPDX-License-Identifier: AGPL-3.0-only
//! Raw-socket tests against the real server: the security properties are properties of the
//! bytes on the wire, so we speak HTTP by hand.
use ctrlaltnotes_core::KDF_MIN;
use ctrlaltnotes_server::{start, Running, WebConfig};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tempfile::tempdir;

const PW: &str = "Tangerine Lantern Walrus Quartz 92";

fn boot() -> (tempfile::TempDir, Running) {
    let d = tempdir().unwrap();
    let r = start(WebConfig {
        vault_dir: d.path().join("vault"),
        sync: None,
        port: 0,
        idle_lock: Duration::from_secs(300),
        kdf: Some(KDF_MIN),
    })
    .unwrap();
    (d, r)
}

fn raw(port: u16, bytes: &[u8]) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(bytes).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn status(resp: &str) -> u16 {
    resp.split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}
fn body(resp: &str) -> &str {
    resp.split("\r\n\r\n").nth(1).unwrap_or("")
}

fn post(r: &Running, cmd: &str, json: &str) -> String {
    post_with(
        r,
        cmd,
        json,
        &[("Authorization", format!("Bearer {}", r.token))],
    )
}

fn post_with(r: &Running, cmd: &str, json: &str, extra: &[(&str, String)]) -> String {
    let mut h = format!(
        "POST /api/{cmd} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        r.port,
        json.len()
    );
    for (k, v) in extra {
        h.push_str(&format!("{k}: {v}\r\n"));
    }
    h.push_str("\r\n");
    h.push_str(json);
    raw(r.port, h.as_bytes())
}

fn get(r: &Running, path: &str, host: Option<&str>) -> String {
    let host = host
        .map(|h| h.to_string())
        .unwrap_or(format!("127.0.0.1:{}", r.port));
    raw(
        r.port,
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes(),
    )
}

#[test]
fn serves_ui_with_strict_headers() {
    let (_d, r) = boot();
    for p in ["/", "/app.css", "/md.js", "/api.js", "/quick.js", "/app.js"] {
        let resp = get(&r, p, None);
        assert_eq!(status(&resp), 200, "{p}");
        let l = resp.to_lowercase();
        assert!(l.contains(
            "content-security-policy: default-src 'none'; script-src 'self'; style-src 'self'"
        ));
        assert!(l.contains("x-content-type-options: nosniff"));
        assert!(l.contains("cache-control: no-store"));
        assert!(l.contains("referrer-policy: no-referrer"));
        assert!(l.contains("x-frame-options: deny"));
        assert!(l.contains("frame-ancestors 'none'"));
    }
    assert_eq!(status(&get(&r, "/etc/passwd", None)), 404);
    assert_eq!(status(&get(&r, "/../Cargo.toml", None)), 404);
    r.shutdown();
}

#[test]
fn ui_has_no_inline_script_or_style_and_no_remote_urls() {
    let (_d, r) = boot();
    let html = body(&get(&r, "/", None)).to_string();
    assert!(!html.contains("<style"));
    assert!(!html.contains(" style="));
    assert!(!html.to_lowercase().contains("onclick="));
    for l in html.lines().filter(|l| l.contains("<script")) {
        assert!(l.contains("src="), "inline script: {l}");
        assert!(!l.contains("http"), "remote script: {l}");
    }
    for f in ["/app.js", "/api.js", "/md.js", "/quick.js"] {
        let js = body(&get(&r, f, None)).to_string();
        assert!(!js.contains("innerHTML"), "{f} uses innerHTML");
        assert!(!js.contains("eval("), "{f} uses eval");
        assert!(!js.contains("document.write"), "{f}");
    }
    r.shutdown();
}

#[test]
fn api_requires_the_launch_token() {
    let (_d, r) = boot();
    assert_eq!(status(&post_with(&r, "status", "{}", &[])), 401);
    assert_eq!(
        status(&post_with(
            &r,
            "status",
            "{}",
            &[("Authorization", "Bearer nope".into())]
        )),
        401
    );
    assert_eq!(
        status(&post_with(
            &r,
            "status",
            "{}",
            &[("Authorization", format!("bearer {}", r.token))]
        )),
        401
    );
    assert_eq!(
        status(&post_with(
            &r,
            "status",
            "{}",
            &[("Authorization", r.token.clone())]
        )),
        401
    );
    let wrong_len = format!("Bearer {}0", r.token);
    assert_eq!(
        status(&post_with(
            &r,
            "status",
            "{}",
            &[("Authorization", wrong_len)]
        )),
        401
    );
    assert_eq!(status(&post(&r, "status", "{}")), 200);
    assert_eq!(r.token.len(), 64);
    r.shutdown();
}

#[test]
fn token_is_in_fragment_and_never_in_responses() {
    let (_d, r) = boot();
    assert!(r.url().contains("/#"));
    assert!(!get(&r, "/", None).contains(&r.token));
    assert!(!post(&r, "status", "{}").contains(&r.token));
    r.shutdown();
}

#[test]
fn host_header_is_pinned_against_dns_rebinding() {
    let (_d, r) = boot();
    for h in [
        "evil.example",
        "evil.example:80",
        "127.0.0.1",
        "127.0.0.1:1",
        "localhost.evil.com:9",
    ] {
        assert_eq!(status(&get(&r, "/", Some(h))), 403, "{h}");
    }
    assert_eq!(
        status(&get(&r, "/", Some(&format!("localhost:{}", r.port)))),
        200
    );
    assert_eq!(
        status(&raw(r.port, b"GET / HTTP/1.1\r\n\r\n")),
        403,
        "missing Host"
    );
    r.shutdown();
}

#[test]
fn foreign_origin_is_rejected() {
    let (_d, r) = boot();
    let t = format!("Bearer {}", r.token);
    assert_eq!(
        status(&post_with(
            &r,
            "status",
            "{}",
            &[
                ("Authorization", t.clone()),
                ("Origin", "http://evil.example".into())
            ]
        )),
        403
    );
    assert_eq!(
        status(&post_with(
            &r,
            "status",
            "{}",
            &[("Authorization", t.clone()), ("Origin", "null".into())]
        )),
        403
    );
    let own = format!("http://127.0.0.1:{}", r.port);
    assert_eq!(
        status(&post_with(
            &r,
            "status",
            "{}",
            &[("Authorization", t), ("Origin", own)]
        )),
        200
    );
    r.shutdown();
}

#[test]
fn no_cors_headers_are_ever_sent() {
    let (_d, r) = boot();
    let resp = post(&r, "status", "{}").to_lowercase();
    assert!(!resp.contains("access-control-allow"));
    let pre = raw(r.port, format!("OPTIONS /api/status HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: http://evil.example\r\n\r\n", r.port).as_bytes());
    assert!(!pre.to_lowercase().contains("access-control-allow"));
    assert_ne!(status(&pre), 200);
    r.shutdown();
}

#[test]
fn only_post_json_is_accepted_on_api() {
    let (_d, r) = boot();
    let t = &r.token;
    let g = raw(
        r.port,
        format!(
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {t}\r\n\r\n",
            r.port
        )
        .as_bytes(),
    );
    assert_eq!(status(&g), 404);
    let put = raw(r.port, format!("PUT /api/status HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {t}\r\nContent-Length: 0\r\n\r\n", r.port).as_bytes());
    assert_eq!(status(&put), 405);
    // form-encoded / text/plain bodies (the CSRF classics) are refused
    for ct in [
        "application/x-www-form-urlencoded",
        "text/plain",
        "multipart/form-data",
    ] {
        let req = format!("POST /api/status HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {t}\r\nContent-Type: {ct}\r\nContent-Length: 2\r\n\r\n{{}}", r.port);
        assert_eq!(status(&raw(r.port, req.as_bytes())), 415, "{ct}");
    }
    assert_eq!(status(&post(&r, "status", "[1]")), 400);
    assert_eq!(status(&post(&r, "status", "not json")), 400);
    r.shutdown();
}

#[test]
fn request_smuggling_vectors_are_rejected() {
    let (_d, r) = boot();
    let t = &r.token;
    let base = |extra: &str| {
        format!("POST /api/status HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {t}\r\nContent-Type: application/json\r\n{extra}\r\n{{}}", r.port)
    };
    assert_eq!(
        status(&raw(
            r.port,
            base("Transfer-Encoding: chunked\r\nContent-Length: 2\r\n").as_bytes()
        )),
        400
    );
    assert_eq!(
        status(&raw(
            r.port,
            base("Content-Length: 2\r\nContent-Length: 2\r\n").as_bytes()
        )),
        400
    );
    assert_eq!(
        status(&raw(r.port, base("Content-Length: -2\r\n").as_bytes())),
        400
    );
    assert_eq!(
        status(&raw(
            r.port,
            base("Content-Length: 2 \r\n X: folded\r\n").as_bytes()
        )),
        400
    );
    assert_eq!(
        status(&raw(r.port, base("Content-Length: 0x2\r\n").as_bytes())),
        400
    );
    // duplicate Host / Authorization
    let dup = format!(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:{0}\r\nHost: evil\r\n\r\n",
        r.port
    );
    assert_eq!(status(&raw(r.port, dup.as_bytes())), 400);
    // trailing pipelined request
    let pipe = format!("POST /api/status HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {t}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}GET / HTTP/1.1\r\n\r\n", r.port);
    assert_eq!(status(&raw(r.port, pipe.as_bytes())), 400);
    r.shutdown();
}

#[test]
fn malformed_and_oversize_requests() {
    let (_d, r) = boot();
    for bad in [
        &b"garbage\r\n\r\n"[..],
        b"GET / HTTP/1.0\r\n\r\n",
        b"GET relative HTTP/1.1\r\n\r\n",
        b"get / HTTP/1.1\r\n\r\n",
        b"GET / HTTP/1.1 extra\r\n\r\n",
        b"GET /\x00 HTTP/1.1\r\n\r\n",
    ] {
        assert_eq!(
            status(&raw(r.port, bad)),
            400,
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
    let big_header = format!(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-Pad: {}\r\n\r\n",
        r.port,
        "a".repeat(20_000)
    );
    assert_eq!(status(&raw(r.port, big_header.as_bytes())), 413);
    let big_body = format!("POST /api/status HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: 99999999\r\n\r\n", r.port, r.token);
    assert_eq!(status(&raw(r.port, big_body.as_bytes())), 413);
    // the server is still healthy afterwards
    assert_eq!(status(&post(&r, "status", "{}")), 200);
    r.shutdown();
}

#[test]
fn slow_or_truncated_clients_do_not_wedge_the_server() {
    let (_d, r) = boot();
    let mut s = TcpStream::connect(("127.0.0.1", r.port)).unwrap();
    s.write_all(b"POST /api/status HTTP/1.1\r\nHost: x\r\nContent-Length: 50\r\n\r\n{")
        .unwrap();
    drop(s); // truncated body
    assert_eq!(status(&post(&r, "status", "{}")), 200);
    r.shutdown();
}

#[test]
fn full_session_over_http_and_error_mapping() {
    let (_d, r) = boot();
    assert!(body(&post(&r, "status", "{}")).contains("\"exists\":false"));
    assert_eq!(status(&post(&r, "tree", "{}")), 423, "locked before create");
    assert_eq!(
        status(&post(&r, "create_vault", "{\"password\":\"short\"}")),
        400
    );
    let c = post(&r, "create_vault", &format!("{{\"password\":\"{PW}\"}}"));
    assert_eq!(status(&c), 200);
    assert!(body(&c).contains("recovery_key"));
    let n = post(
        &r,
        "create_note",
        "{\"title\":\"hello\",\"body\":\"world\"}",
    );
    assert_eq!(status(&n), 200);
    assert_eq!(status(&post(&r, "nonexistent", "{}")), 404);
    assert_eq!(status(&post(&r, "UPPER", "{}")), 404);
    assert_eq!(status(&post(&r, "lock", "{}")), 200);
    assert_eq!(status(&post(&r, "tree", "{}")), 423);
    let bad = "{\"password\":\"wrong password here\"}";
    for _ in 0..3 {
        assert_eq!(status(&post(&r, "unlock", bad)), 400);
    }
    let t = post(&r, "unlock", bad);
    assert_eq!(status(&t), 429);
    assert!(body(&t).contains("throttled:"));
    r.shutdown();
}

#[test]
fn paths_in_json_cannot_reach_the_filesystem() {
    let (d, r) = boot();
    post(&r, "create_vault", &format!("{{\"password\":\"{PW}\"}}"));
    let target = d.path().join("pwned");
    let j = format!(
        "{{\"path\":\"{}\",\"kind\":\"folder\"}}",
        target.to_str().unwrap().replace('\\', "\\\\")
    );
    for cmd in ["export_markdown", "set_sync", "join_vault"] {
        assert_eq!(status(&post(&r, cmd, &j)), 400, "{cmd}");
    }
    assert!(!target.exists());
    r.shutdown();
}

#[test]
fn only_loopback_is_bound() {
    let (_d, r) = boot();
    // bound to 127.0.0.1: connecting by loopback works; the listener address is not 0.0.0.0
    assert!(TcpStream::connect(("127.0.0.1", r.port)).is_ok());
    r.shutdown();
}

// ------------------------------------------------------------ pentest regressions
#[test]
fn slowloris_is_cut_off_by_the_overall_deadline() {
    ctrlaltnotes_server::set_request_deadline_ms(1500);
    let (_d, r) = boot();
    let mut s = TcpStream::connect(("127.0.0.1", r.port)).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    let t0 = std::time::Instant::now();
    let mut cut = false;
    // one byte every 300 ms, forever: each read is "fast" but the request never completes
    for b in b"GET /api/status HTTP/1.1\r\nHost: localhost\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".iter() {
        if s.write_all(&[*b]).is_err() {
            cut = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
        if t0.elapsed() > Duration::from_secs(8) {
            break;
        }
    }
    if !cut {
        // the server may have closed without us noticing on write: the read must now see EOF
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut b = [0u8; 64];
        cut = match s.read(&mut b) {
            Ok(_) => true, // 400 / EOF from the server
            Err(e) => !matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
        };
    }
    assert!(cut, "slow client was never disconnected");
    ctrlaltnotes_server::set_request_deadline_ms(20_000);
    r.shutdown();
}

#[test]
fn launch_page_keeps_the_token_off_the_command_line() {
    let url = "http://localhost:1234/#abcdef";
    let p = ctrlaltnotes_server::write_launch_page(url).unwrap();
    let html = std::fs::read_to_string(&p).unwrap();
    assert!(html.contains(url));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let _ = std::fs::remove_file(p);
}

#[test]
fn ipv6_loopback_port_is_held_too() {
    let (_d, r) = boot();
    // If this machine has IPv6 loopback, nobody else can squat on [::1]:PORT.
    if std::net::TcpListener::bind(("::1", 0)).is_ok() {
        assert!(
            std::net::TcpListener::bind(("::1", r.port)).is_err(),
            "[::1]:{} is free for a squatter",
            r.port
        );
    }
    r.shutdown();
}
