use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use ghidra_decompiler::ifacedecomp::{mainloop, register_all_commands, register_console_commands};
use ghidra_decompiler::interface::{IfaceError, IfaceStatus, new_out_stream, out_write};
use ghidra_decompiler::sleigh_arch::{add_global_language_directory, scan_global_sleigh_directories};
use ghidra_decompiler::{DecompilerReconstructor, Program};

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
        if let (Some(timestamp), Some(tag)) = (lines.next(), lines.next()) {
            if timestamp
                .parse::<u64>()
                .is_ok_and(|time| now.saturating_sub(time) < 21_600)
            {
                return Some(tag.to_string());
            }
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
            "# Reverse++ CLI settings\n# Output directory used by your analysis workflows.\noutput_dir = \"output\"\n",
        )
        .map_err(|err| err.to_string())?;
    }
    println!("Reverse++ {} is initialized.", version());
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
                println!("Reverse++ {} is up to date.", version());
            }
        }
        None => {
            println!("Could not check for updates. Check your internet connection and try again.");
            println!("Releases: {RELEASES_URL}");
        }
    }
}

/// Allocation-site tracker for memory diagnostics: while enabled it remembers the call stack of
/// every allocation that is still live, so the sites that keep memory can be listed.
mod tracker {
    use std::cell::Cell;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    const DEPTH: usize = 16;

    struct State {
        live: HashMap<usize, (usize, u64)>,
        sites: HashMap<u64, [usize; DEPTH]>,
    }

    static ENABLED: AtomicBool = AtomicBool::new(false);
    static STATE: Mutex<Option<State>> = Mutex::new(None);

    thread_local! {
        // Set while the tracker itself allocates, so its own allocations are never tracked.
        static BUSY: Cell<bool> = const { Cell::new(false) };
    }

    pub fn on_alloc(pointer: *mut u8, size: usize) {
        if !ENABLED.load(Ordering::Relaxed) || BUSY.try_with(|busy| busy.replace(true)).unwrap_or(true) {
            return;
        }
        let mut frames = [0usize; DEPTH];
        let mut count = 0;
        // SAFETY: the trace is not shared between threads; this thread is guarded by BUSY.
        unsafe {
            backtrace::trace_unsynchronized(|frame| {
                if count < DEPTH {
                    frames[count] = frame.ip() as usize;
                    count += 1;
                    true
                } else {
                    false
                }
            });
        }
        let mut key = 0xcbf2_9ce4_8422_2325u64;
        for frame in &frames[..count] {
            key = (key ^ *frame as u64).wrapping_mul(0x0100_0000_01b3);
        }
        if let Ok(mut guard) = STATE.lock() {
            let state = guard.get_or_insert_with(|| State {
                live: HashMap::new(),
                sites: HashMap::new(),
            });
            state.live.insert(pointer as usize, (size, key));
            state.sites.entry(key).or_insert(frames);
        }
        let _ = BUSY.try_with(|busy| busy.set(false));
    }

    pub fn on_free(pointer: *mut u8) {
        if !ENABLED.load(Ordering::Relaxed) || BUSY.try_with(|busy| busy.replace(true)).unwrap_or(true) {
            return;
        }
        if let Ok(mut guard) = STATE.lock()
            && let Some(state) = guard.as_mut()
        {
            state.live.remove(&(pointer as usize));
        }
        let _ = BUSY.try_with(|busy| busy.set(false));
    }

    pub fn command(code: u8) {
        match code {
            1 => {
                if let Ok(mut guard) = STATE.lock() {
                    *guard = None;
                }
                ENABLED.store(true, Ordering::SeqCst);
            }
            _ => {
                ENABLED.store(false, Ordering::SeqCst);
                report();
            }
        }
    }

    fn report() {
        let _ = BUSY.try_with(|busy| busy.set(true));
        let Ok(guard) = STATE.lock() else { return };
        let Some(state) = guard.as_ref() else { return };
        let mut totals: HashMap<u64, (usize, usize)> = HashMap::new();
        for (size, key) in state.live.values() {
            let entry = totals.entry(*key).or_default();
            entry.0 += size;
            entry.1 += 1;
        }
        let mut sorted: Vec<_> = totals.into_iter().collect();
        sorted.sort_by_key(|(_, (bytes, _))| std::cmp::Reverse(*bytes));
        let total: usize = sorted.iter().map(|(_, (bytes, _))| *bytes).sum();
        eprintln!("[leak] {total} live bytes from {} allocation sites", sorted.len());
        for (key, (bytes, count)) in sorted.into_iter().take(8) {
            eprintln!("[leak] site: {bytes} bytes in {count} allocations");
            if let Some(frames) = state.sites.get(&key) {
                let mut shown = 0;
                for &frame in frames.iter().filter(|frame| **frame != 0) {
                    let mut name = String::new();
                    // SAFETY: single-threaded use here; BUSY is set so nothing is tracked.
                    unsafe {
                        backtrace::resolve_unsynchronized(frame as *mut std::ffi::c_void, |symbol| {
                            if name.is_empty()
                                && let Some(found) = symbol.name()
                            {
                                name = found.to_string();
                            }
                        });
                    }
                    if name.starts_with("alloc::") || name.starts_with("std::") || name.starts_with("core::") || name.contains("tracker") || name.contains("backtrace") || name.is_empty() {
                        continue;
                    }
                    eprintln!("[leak]     at {name}");
                    shown += 1;
                    if shown >= 7 {
                        break;
                    }
                }
            }
        }
    }
}

/// Counts live heap bytes so the memory probe can tell real retention from allocator fragmentation.
struct CountingAllocator;

// SAFETY: every call is forwarded unchanged to the system allocator; only a counter is updated.
unsafe impl std::alloc::GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let pointer = unsafe { std::alloc::System.alloc(layout) };
        if !pointer.is_null() {
            tracker::on_alloc(pointer, layout.size());
            ghidra_decompiler::ifacedecomp::LIVE_BYTES.fetch_add(layout.size(), std::sync::atomic::Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        tracker::on_free(pointer);
        unsafe { std::alloc::System.dealloc(pointer, layout) };
        ghidra_decompiler::ifacedecomp::LIVE_BYTES.fetch_sub(layout.size(), std::sync::atomic::Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn main() -> ExitCode {
    let _ = ghidra_decompiler::ifacedecomp::TRACK_HOOK.set(tracker::command);
    let args: Vec<String> = std::env::args().collect();
    if args
        .get(1)
        .is_some_and(|arg| arg == "--help" || arg == "-h" || arg == "help")
    {
        println!("Reverse++ {}", version());
        println!("Usage: ghidra-rust_cli [--version | --help | setup | update | reconstruct <binary> <address>]");
        println!();
        println!("Run without arguments to open the interactive decompiler console.");
        println!("Run `ghidra-rust_cli reconstruct <binary> <address>` for pseudocode and reconstruction evidence.");
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
    if args.get(1).is_some_and(|arg| arg == "reconstruct") {
        let (Some(binary), Some(raw_address)) = (args.get(2), args.get(3)) else {
            eprintln!("Usage: ghidra-rust_cli reconstruct <binary> <address>");
            return ExitCode::from(2);
        };
        let address = raw_address
            .strip_prefix("0x")
            .map(|value| u64::from_str_radix(value, 16))
            .unwrap_or_else(|| raw_address.parse::<u64>());
        let address = match address {
            Ok(value) => value,
            Err(_) => {
                eprintln!("Invalid address: {raw_address}");
                return ExitCode::from(2);
            }
        };
        let mut program = match Program::open(Path::new(binary), None) {
            Ok(program) => program,
            Err(error) => {
                eprintln!("Could not open binary: {}", error.explain());
                return ExitCode::from(1);
            }
        };
        let reconstruction = match DecompilerReconstructor.reconstruct_function(&mut program, address) {
            Ok(result) => result,
            Err(error) => {
                eprintln!("Reconstruction failed: {}", error.explain());
                return ExitCode::from(1);
            }
        };
        println!(
            "Function: {} at {:#x}",
            reconstruction.function.name, reconstruction.function.address
        );
        if let Some(declaration) = &reconstruction.decompiler_declaration {
            println!("Recovered declaration: {declaration}");
        }
        println!("\\n===== Decompiled pseudocode =====\\n{}", reconstruction.pseudocode);
        println!("\\n===== Reconstruction evidence =====");
        println!("{:#?}", reconstruction.result);
        return ExitCode::SUCCESS;
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
