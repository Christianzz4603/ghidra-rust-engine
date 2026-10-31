use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use ghidra_decompiler::ifacedecomp::{mainloop, register_all_commands, register_console_commands};
use ghidra_decompiler::interface::{IfaceError, IfaceStatus, new_out_stream, out_write};
use ghidra_decompiler::sleigh_arch::{add_global_language_directory, scan_global_sleigh_directories};

#[path = "webui.rs"]
mod webui;

const RELEASES_URL: &str = "https://github.com/Christianzz4603/ghidra-rust-engine/releases/latest";
const API_URL: &str = "https://api.github.com/repos/Christianzz4603/ghidra-rust-engine/releases/latest";

fn version() -> &'static str {
    option_env!("GHIDRA_ENGINE_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
}

fn cache_path() -> Option<PathBuf> {
    home_dir().map(|home| home.join(".cache").join("ghidra-engine").join("latest-release"))
}

fn parse_tag(body: &str) -> Option<String> {
    let marker = body.find("\"tag_name\"")?;
    let tail = &body[marker + "\"tag_name\"".len()..];
    let colon = tail.find(':')?;
    let value = tail[colon + 1..].trim_start();
    let value = value.strip_prefix('"')?;
    let end = value.find('"')?;
    Some(value[..end].to_string())
}

fn version_parts(value: &str) -> Option<(u64, u64, u64)> {
    let value = value.trim().trim_start_matches('v');
    let mut parts = value.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch_text = parts.next()?;
    if parts.next().is_some() || patch_text.contains('-') || patch_text.contains('+') {
        return None;
    }
    let patch = patch_text.parse().ok()?;
    Some((major, minor, patch))
}

fn fetch_latest_tag() -> Option<String> {
    let cache = cache_path()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();

    if let Ok(contents) = fs::read_to_string(&cache) {
        let mut lines = contents.lines();
        if let (Some(timestamp), Some(tag)) = (lines.next(), lines.next())
            && timestamp
                .parse::<u64>()
                .is_ok_and(|time| now.saturating_sub(time) < 21_600)
        {
            return Some(tag.to_string());
        }
    }

    let output = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--location",
            "--connect-timeout",
            "2",
            "--max-time",
            "4",
            "--header",
            "Accept: application/vnd.github+json",
            "--header",
            "User-Agent: ghidra-rust-engine",
            API_URL,
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let body = String::from_utf8(output.stdout).ok()?;
    let tag = parse_tag(&body)?;
    if let Some(parent) = cache.parent() {
        let _ = fs::create_dir_all(parent);
        let _ = fs::write(cache, format!("{now}\n{tag}\n"));
    }
    Some(tag)
}

fn setup() -> Result<(), String> {
    let home = home_dir().ok_or("Could not determine the home directory")?;
    let config = home.join(".config").join("ghidra-engine");
    let data = home.join(".local").join("share").join("ghidra-engine");
    let output = data.join("output");
    fs::create_dir_all(&config).map_err(|err| err.to_string())?;
    fs::create_dir_all(&output).map_err(|err| err.to_string())?;
    let settings = config.join("config.toml");
    if !settings.exists() {
        fs::write(
            &settings,
            "# Ghidra Rust Engine CLI settings\n# Output directory used by your analysis workflows.\noutput_dir = \"output\"\n",
        ).map_err(|err| err.to_string())?;
    }
    println!("Ghidra Rust Engine {} is initialized.", version());
    println!("Config: {}", config.display());
    println!("Workspace: {}", data.display());
    println!("This does not modify your shell PATH; place the executable in a directory already on PATH.");
    Ok(())
}

fn print_update_status() {
    match fetch_latest_tag() {
        Some(latest) => {
            let current = version_parts(version());
            let available = version_parts(&latest);
            if current.is_some() && available.is_some() && available > current {
                println!("Update available: {} -> {}", version(), latest.trim_start_matches('v'));
                println!("Release: {RELEASES_URL}");
            } else {
                println!("Ghidra Rust Engine {} is up to date.", version());
            }
        }
        None => {
            println!("Could not check for updates. Check your internet connection and try again.");
            println!("Releases: {RELEASES_URL}");
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args
        .get(1)
        .is_some_and(|arg| arg == "--help" || arg == "-h" || arg == "help")
    {
        println!("Ghidra Rust Engine {}", version());
        println!("Usage: ghidra-rust_cli [--version | --help | setup | update | web [--port=PORT]]");
        println!();
        println!("Run without arguments to open the interactive decompiler console.");
        println!("Run `ghidra-rust_cli web` to launch the built-in browser workspace.");
        println!("Inside the console: open <binary>, then decompile <function>.");
        println!("Decompiled files are saved in an output/ folder beside this executable by default.");
        println!("Set GHIDRA_DECOMPILER_OUTPUT_DIR to choose another output folder.");
        return ExitCode::SUCCESS;
    }
    if args
        .get(1)
        .is_some_and(|arg| arg == "--version" || arg == "-V" || arg == "version")
    {
        println!("ghidra-engine {}", version());
        return ExitCode::SUCCESS;
    }
    if args.get(1).is_some_and(|arg| arg == "setup") {
        return match setup() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("Setup failed: {err}");
                ExitCode::from(1)
            }
        };
    }
    if args.get(1).is_some_and(|arg| arg == "web" || arg == "--web") {
        let port = args.iter().skip(2).find_map(|arg| arg.strip_prefix("--port=").and_then(|v| v.parse::<u16>().ok())).unwrap_or(8080);
        return match webui::run(port) { Ok(()) => ExitCode::SUCCESS, Err(err) => { eprintln!("Web UI failed: {err}"); ExitCode::from(1) } };
    }
    if args.get(1).is_some_and(|arg| arg == "update") {
        print_update_status();
        return ExitCode::SUCCESS;
    }

    let mut initscript: Option<String> = None;
    let mut extrapaths: Vec<String> = Vec::new();
    let mut index = 1;
    while index < args.len() && args[index].starts_with('-') {
        let option = args[index].as_bytes().get(1).copied();
        if option == Some(b'i') {
            index += 1;
            initscript = args.get(index).cloned();
        } else if option == Some(b's') {
            index += 1;
            if let Some(path) = args.get(index) {
                extrapaths.push(path.clone());
            }
        }
        index += 1;
    }
    if let Ok(sleighhome) = std::env::var("SLEIGHHOME")
        && let Err(err) = scan_global_sleigh_directories(Path::new(&sleighhome))
    {
        eprintln!("{}", err.explain());
    }
    for path in extrapaths.iter() {
        if let Err(err) = add_global_language_directory(Path::new(path)) {
            eprintln!("{}", err.explain());
        }
    }
    let optr = new_out_stream();
    let mut status = IfaceStatus::new_term(
        "[ghidra-engine]> ",
        Box::new(BufReader::new(std::io::stdin())),
        optr.clone(),
    );
    status.attach_sink(&optr, Box::new(std::io::stdout()));
    register_all_commands(&mut status);
    register_console_commands(&mut status);
    if let Some(script) = initscript {
        match status.push_script_file(&script, "init> ") {
            Ok(()) => {}
            Err(IfaceError::Parse(message)) => {
                out_write(&optr, &format!("{message}\n"));
                status.done = true;
            }
            Err(err) => {
                eprintln!("Interface error: {}", err.explain());
                return ExitCode::from(2);
            }
        }
    }
    if !status.done {
        mainloop(&mut status);
    }
    let retval = if status.is_in_error() { 1 } else { 0 };
    status.flush_all();
    ExitCode::from(retval)
}
