// SPDX-License-Identifier: AGPL-3.0-only
//! `ctrlaltnotes-web`: the web version. Starts the local server and opens your browser.
//! The ONLY command-line use is starting this program; the vault password is created and
//! entered in the web page, never on the command line.
#![forbid(unsafe_code)]
use ctrlaltnotes_server::{start, WebConfig};
use ctrlaltnotes_service::{SyncKind, SyncTarget};
use std::path::PathBuf;
use std::time::Duration;

const HELP: &str = "\
CtrlAltNotes (web version)

USAGE:
    ctrlaltnotes-web [OPTIONS]

OPTIONS:
    --vault <DIR>         where the encrypted local vault lives (default: per-user data folder)
    --sync-folder <DIR>   folder mirrored by your cloud client (Proton Drive, iCloud, Dropbox...)
    --sync-file <FILE>    single-file sync target (bundle)
    --port <N>            fixed port (default: random free port)
    --idle-lock <SECS>    auto-lock after this many idle seconds (default 300)
    --no-open             do not open the browser automatically
    -h, --help            show this help
";

/// Default data folder (use --vault to choose another place).
fn default_vault_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if let Some(h) = std::env::var_os("HOME") {
            return PathBuf::from(h).join("Library/Application Support/CtrlAltNotes/vault");
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(h) = std::env::var_os("APPDATA") {
            return PathBuf::from(h).join("CtrlAltNotes").join("vault");
        }
    }
    // Linux / other Unix: XDG base directories (a relative XDG_DATA_HOME is invalid per spec)
    if let Some(x) = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from) {
        if x.is_absolute() {
            return x.join("ctrlaltnotes/vault");
        }
    }
    if let Some(h) = std::env::var_os("HOME") {
        return PathBuf::from(h).join(".local/share/ctrlaltnotes/vault");
    }
    PathBuf::from("ctrlaltnotes-vault")
}

fn open_browser(url: &str) {
    use std::process::{Command, Stdio};
    // The launch token is in the URL. Never put it on the opener's command line (other local
    // users can read it with `ps`): hand the opener a private temp page that redirects instead.
    let Ok(page) = ctrlaltnotes_server::write_launch_page(url) else {
        return; // the URL is printed in the terminal; the user can open it by hand
    };
    #[cfg(target_os = "macos")]
    let mut c = Command::new("open");
    #[cfg(target_os = "windows")]
    let mut c = {
        let mut c = Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler");
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut c = Command::new("xdg-open");
    let _ = c
        .arg(&page)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(30));
        let _ = std::fs::remove_file(page);
    });
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}\n\n{HELP}");
    std::process::exit(2)
}

fn main() {
    let mut vault = default_vault_dir();
    let mut sync: Option<SyncTarget> = None;
    let mut port = 0u16;
    let mut idle = 300u64;
    let mut open = true;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = |name: &str| {
            args.next()
                .unwrap_or_else(|| fail(&format!("{name} needs a value")))
        };
        match a.as_str() {
            "--vault" => vault = PathBuf::from(val("--vault")),
            "--sync-folder" => {
                sync = Some(SyncTarget {
                    kind: SyncKind::Folder,
                    path: PathBuf::from(val("--sync-folder")),
                })
            }
            "--sync-file" => {
                sync = Some(SyncTarget {
                    kind: SyncKind::Bundle,
                    path: PathBuf::from(val("--sync-file")),
                })
            }
            "--port" => {
                port = val("--port")
                    .parse()
                    .unwrap_or_else(|_| fail("--port must be 0-65535"))
            }
            "--idle-lock" => {
                idle = val("--idle-lock")
                    .parse()
                    .unwrap_or_else(|_| fail("--idle-lock must be a number"));
                if idle < 10 {
                    fail("--idle-lock must be at least 10 seconds");
                }
            }
            "--no-open" => open = false,
            "-h" | "--help" => {
                print!("{HELP}");
                return;
            }
            other => fail(&format!("unknown option {other}")),
        }
    }
    let running = match start(WebConfig {
        vault_dir: vault.clone(),
        sync,
        port,
        idle_lock: Duration::from_secs(idle),
        kdf: None,
    }) {
        Ok(r) => r,
        Err(e) => fail(&format!("could not start the server: {e}")),
    };
    let url = running.url();
    println!("CtrlAltNotes is running.\n\n  {url}\n\nVault folder : {}\nAuto-lock    : {idle}s idle\nPress Ctrl+C to quit.", vault.display());
    if open {
        open_browser(&url);
    }
    running.wait();
}
