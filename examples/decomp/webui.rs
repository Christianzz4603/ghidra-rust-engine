use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ghidra_decompiler::Program;

type SharedProgram = Arc<Mutex<Option<Program>>>;

const PAGE: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ghidra Rust Engine</title>
<style>
:root{color-scheme:dark;--bg:#101216;--panel:#171b22;--line:#292f39;--muted:#8993a3;--text:#e8edf5;--green:#8bd49c;--blue:#83b7f5}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px system-ui, sans-serif}
header{height:56px;display:flex;align-items:center;gap:14px;padding:0 18px;border-bottom:1px solid var(--line);background:#141820}
.logo{font-weight:750;letter-spacing:.2px}.dot{width:9px;height:9px;border-radius:50%;background:var(--green);display:inline-block;margin-right:8px}
#status{color:var(--muted);font-size:12px;margin-left:auto}
main{height:calc(100vh - 56px);display:grid;grid-template-columns:minmax(210px,25%) 1fr;min-height:0}
aside{background:var(--panel);border-right:1px solid var(--line);display:flex;flex-direction:column;min-height:0}
.open{padding:14px;border-bottom:1px solid var(--line)}input{width:100%;background:#0e1117;border:1px solid var(--line);border-radius:7px;padding:10px;color:var(--text);outline:none}
button{border:1px solid #385c48;background:#20392b;color:#b8f0c7;padding:9px 12px;border-radius:7px;cursor:pointer;font-weight:650}
.open button{width:100%;margin-top:8px}.open button:disabled{opacity:.5}
.search{padding:10px;border-bottom:1px solid var(--line)}.section{padding:10px 13px;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px}
#functions{overflow:auto;min-height:0}.fn{display:block;width:100%;text-align:left;background:transparent;border:0;border-radius:0;padding:9px 13px;color:var(--text);font:12px ui-monospace,monospace;font-weight:400}.fn:hover,.fn.active{background:#242c38}.fn small{display:block;color:var(--muted);margin-top:3px}
.content{display:grid;grid-template-rows:auto 1fr;min-width:0;min-height:0}.tabs{display:flex;gap:4px;padding:9px 12px;border-bottom:1px solid var(--line);background:#141820}
.tab{background:transparent;border-color:transparent;color:var(--muted);padding:7px 11px}.tab.active{background:#252d39;color:var(--text);border-color:#364150}
#viewer{overflow:auto;padding:16px;min-height:0}pre{margin:0;white-space:pre;tab-size:4;font:12px/1.7 ui-monospace,SFMono-Regular,monospace;color:#d5deeb}
.placeholder{color:var(--muted);padding:32px;text-align:center}.error{color:#ff9b9b;padding:12px}
@media(max-width:650px){main{grid-template-columns:145px 1fr}.open{padding:8px}.fn{padding:8px;font-size:11px}.tabs{overflow:auto}.tab{white-space:nowrap;padding:7px 9px}#viewer{padding:10px}}
</style></head>
<body>
<header><span class="logo"><i class="dot"></i>GHIDRA RUST ENGINE</span><span id="binary">No binary loaded</span><span id="status">Local analysis workspace</span></header>
<main><aside><div class="open"><input id="path" placeholder="/sdcard/home/libminecraftpe.so"><button id="load">Open binary</button></div>
<div class="search"><input id="filter" placeholder="Filter functions..."></div><div class="section">Functions</div><div id="functions"><div class="placeholder">Open a binary to begin.</div></div></aside>
<section class="content"><nav class="tabs"><button class="tab active" data-view="decompile">Pseudocode</button><button class="tab" data-view="assembly">Disassembly</button><button class="tab" data-view="hex">Hex</button></nav>
<div id="viewer"><div class="placeholder">Load a binary, then select a function.</div></div></section></main>
<script>
const $=s=>document.querySelector(s);let functions=[],selected=null,view="decompile";
const status=t=>$("#status").textContent=t;
async function api(url,options={}){const r=await fetch(url,options);const d=await r.json();if(!r.ok)throw Error(d.error||r.statusText);return d}
function show(text){$("#viewer").innerHTML="";const p=document.createElement("pre");p.textContent=text;$("#viewer").append(p)}
function fail(e){$("#viewer").innerHTML='<div class="error"></div>';$("#viewer .error").textContent=e.message;status("Request failed")}
function renderFunctions(){const q=$("#filter").value.toLowerCase();const box=$("#functions");box.innerHTML="";const shown=functions.filter(f=>f.name.toLowerCase().includes(q)||f.address.includes(q));for(const f of shown){const b=document.createElement("button");b.className="fn"+(selected&&selected.address===f.address?" active":"");b.innerHTML="";b.textContent=f.name;const small=document.createElement("small");small.textContent=f.address;b.append(small);b.onclick=()=>selectFunction(f);box.append(b)}if(!shown.length)box.innerHTML='<div class="placeholder">No matching functions.</div>'}
async function loadBinary(){const path=$("#path").value.trim();if(!path)return;$("#load").disabled=true;status("Loading and discovering functions...");try{const result=await api("/api/open",{method:"POST",headers:{"Content-Type":"text/plain"},body:path});$("#binary").textContent=result.name;functions=result.functions;selected=null;renderFunctions();show("Binary loaded: "+result.name+"\n"+functions.length+" functions discovered.\nSelect a function from the left panel.");status(functions.length+" functions")}catch(e){fail(e)}finally{$("#load").disabled=false}}
async function selectFunction(f){selected=f;renderFunctions();status("Decompiling "+f.name+"...");try{await renderView()}catch(e){fail(e)}}
async function renderView(){if(!selected)return;status("Loading "+view+"...");if(view==="decompile"){const d=await api("/api/decompile?address="+selected.address);show(d.code)}else if(view==="assembly"){const d=await api("/api/disassembly?address="+selected.address);show(d.instructions.map(i=>i.address+"  "+i.bytes+"  "+i.mnemonic+" "+i.operands).join("\n")||"No instructions")}else{const d=await api("/api/hex?address="+selected.address);show(d.hex)}status(selected.name+" · "+selected.address)}
$("#load").onclick=loadBinary;$("#path").addEventListener("keydown",e=>{if(e.key==="Enter")loadBinary()});$("#filter").oninput=renderFunctions;
document.querySelectorAll(".tab").forEach(b=>b.onclick=async()=>{document.querySelectorAll(".tab").forEach(x=>x.classList.toggle("active",x===b));view=b.dataset.view;try{await renderView()}catch(e){fail(e)}});
</script></body></html>"##;

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn response(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)
}

fn json_response(stream: &mut TcpStream, status: &str, body: String) -> std::io::Result<()> {
    response(stream, status, "application/json; charset=utf-8", body.as_bytes())
}

fn error_json(message: &str) -> String {
    format!("{{\"error\":\"{}\"}}", json_escape(message))
}

fn query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|part| {
        let (name, value) = part.split_once('=')?;
        (name == key).then_some(value)
    })
}

fn parse_address(query: &str) -> Result<u64, String> {
    let value = query_value(query, "address").ok_or("missing address parameter")?;
    let value = value.strip_prefix("0x").unwrap_or(value);
    u64::from_str_radix(value, 16).map_err(|_| "invalid hexadecimal address".to_string())
}

fn handle(mut stream: TcpStream, state: SharedProgram) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut request = Vec::with_capacity(4096);
    let mut chunk = [0u8; 2048];
    let header_end;
    loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Ok(());
        }
        request.extend_from_slice(&chunk[..count]);
        if request.len() > 16 * 1024 {
            return response(&mut stream, "413 Payload Too Large", "text/plain", b"Request too large");
        }
        if let Some(pos) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
    }
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let mut lines = headers.lines();
    let Some(first) = lines.next() else {
        return Ok(());
    };
    let mut first_parts = first.split_whitespace();
    let method = first_parts.next().unwrap_or("").to_string();
    let target = first_parts.next().unwrap_or("/").to_string();
    let content_length = lines
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    if content_length > 8192 {
        return response(
            &mut stream,
            "413 Payload Too Large",
            "text/plain",
            b"Request body too large",
        );
    }
    while request.len() < header_end + content_length {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..count]);
    }
    if request.len() < header_end + content_length {
        return response(&mut stream, "400 Bad Request", "text/plain", b"Incomplete request");
    }
    let body = &request[header_end..header_end + content_length];
    let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
    match (method.as_str(), path) {
        ("GET", "/") => response(&mut stream, "200 OK", "text/html; charset=utf-8", PAGE.as_bytes()),
        ("GET", "/api/functions") => {
            let guard = state.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(program) => {
                    let functions = program.functions().map_err(|e| std::io::Error::other(e.explain()))?;
                    let entries = functions
                        .iter()
                        .map(|f| {
                            format!(
                                "{{\"name\":\"{}\",\"address\":\"{:#x}\"}}",
                                json_escape(&f.name),
                                f.address
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    json_response(&mut stream, "200 OK", format!("{{\"functions\":[{entries}]}}"))
                }
                None => json_response(&mut stream, "409 Conflict", error_json("No binary loaded")),
            }
        }
        ("POST", "/api/open") => {
            let path = String::from_utf8_lossy(body).trim().to_string();
            if path.is_empty() {
                return json_response(&mut stream, "400 Bad Request", error_json("Binary path is empty"));
            }
            status_line("Opening binary and discovering functions...");
            match Program::open(Path::new(&path), None) {
                Ok(mut program) => match program.discover_functions() {
                    Ok(()) => {
                        let functions = match program.functions() {
                            Ok(items) => items,
                            Err(error) => {
                                return json_response(
                                    &mut stream,
                                    "500 Internal Server Error",
                                    error_json(error.explain()),
                                );
                            }
                        };
                        let entries = functions
                            .iter()
                            .map(|f| {
                                format!(
                                    "{{\"name\":\"{}\",\"address\":\"{:#x}\"}}",
                                    json_escape(&f.name),
                                    f.address
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(",");
                        let name = Path::new(&path).file_name().and_then(|s| s.to_str()).unwrap_or(&path);
                        *state.lock().unwrap_or_else(|e| e.into_inner()) = Some(program);
                        json_response(
                            &mut stream,
                            "200 OK",
                            format!("{{\"name\":\"{}\",\"functions\":[{entries}]}}", json_escape(name)),
                        )
                    }
                    Err(error) => json_response(&mut stream, "500 Internal Server Error", error_json(error.explain())),
                },
                Err(error) => json_response(&mut stream, "400 Bad Request", error_json(error.explain())),
            }
        }
        ("GET", "/api/decompile") => match parse_address(query) {
            Ok(address) => {
                let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
                match guard.as_mut() {
                    Some(program) => match program.decompile(address) {
                        Ok(code) => json_response(
                            &mut stream,
                            "200 OK",
                            format!("{{\"code\":\"{}\"}}", json_escape(&code)),
                        ),
                        Err(error) => {
                            json_response(&mut stream, "422 Unprocessable Entity", error_json(error.explain()))
                        }
                    },
                    None => json_response(&mut stream, "409 Conflict", error_json("No binary loaded")),
                }
            }
            Err(error) => json_response(&mut stream, "400 Bad Request", error_json(&error)),
        },
        ("GET", "/api/disassembly") => match parse_address(query) {
            Ok(address) => {
                let guard = state.lock().unwrap_or_else(|e| e.into_inner());
                match guard.as_ref() {
                    Some(program) => match program.disassemble(address, 160) {
                        Ok(instructions) => {
                            let rows = instructions.iter().map(|i| {
                                let bytes = i.bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
                                format!("{{\"address\":\"{:#x}\",\"bytes\":\"{}\",\"mnemonic\":\"{}\",\"operands\":\"{}\"}}",
                                    i.address, bytes, json_escape(&i.mnemonic), json_escape(&i.operands))
                            }).collect::<Vec<_>>().join(",");
                            json_response(&mut stream, "200 OK", format!("{{\"instructions\":[{rows}]}}"))
                        }
                        Err(error) => {
                            json_response(&mut stream, "422 Unprocessable Entity", error_json(error.explain()))
                        }
                    },
                    None => json_response(&mut stream, "409 Conflict", error_json("No binary loaded")),
                }
            }
            Err(error) => json_response(&mut stream, "400 Bad Request", error_json(&error)),
        },
        ("GET", "/api/hex") => match parse_address(query) {
            Ok(address) => {
                let guard = state.lock().unwrap_or_else(|e| e.into_inner());
                match guard.as_ref() {
                    Some(program) => match program.read_code(address, 256) {
                        Ok(bytes) => {
                            let mut rows = Vec::new();
                            for (index, row) in bytes.chunks(16).enumerate() {
                                let hex = row.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
                                let ascii = row
                                    .iter()
                                    .map(|b| {
                                        if b.is_ascii_graphic() || *b == b' ' {
                                            *b as char
                                        } else {
                                            '.'
                                        }
                                    })
                                    .collect::<String>();
                                rows.push(format!(
                                    "{:#010x}  {:<47}  {}",
                                    address + (index * 16) as u64,
                                    hex,
                                    ascii
                                ));
                            }
                            json_response(
                                &mut stream,
                                "200 OK",
                                format!("{{\"hex\":\"{}\"}}", json_escape(&rows.join("\n"))),
                            )
                        }
                        Err(error) => {
                            json_response(&mut stream, "422 Unprocessable Entity", error_json(error.explain()))
                        }
                    },
                    None => json_response(&mut stream, "409 Conflict", error_json("No binary loaded")),
                }
            }
            Err(error) => json_response(&mut stream, "400 Bad Request", error_json(&error)),
        },
        _ => response(&mut stream, "404 Not Found", "text/plain; charset=utf-8", b"Not found"),
    }
}

fn status_line(message: &str) {
    eprintln!("[webui] {message}");
}

pub fn run(port: u16) -> std::io::Result<()> {
    let address = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&address)?;
    let state: SharedProgram = Arc::new(Mutex::new(None));
    println!("Ghidra Rust Engine Web UI");
    println!("Open http://{address} in your Android browser");
    println!("This server only listens on localhost.");
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let shared = Arc::clone(&state);
                std::thread::spawn(move || {
                    if let Err(error) = handle(stream, shared) {
                        eprintln!("[webui] request error: {error}");
                    }
                });
            }
            Err(error) => eprintln!("[webui] connection error: {error}"),
        }
    }
    Ok(())
}
