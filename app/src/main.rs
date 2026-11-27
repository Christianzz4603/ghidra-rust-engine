//! Reverse++ native app: open a binary, browse the recovered functions, and read the
//! pseudocode and disassembly of each. All engine work runs on a dedicated thread so the UI
//! never blocks; the window talks to it over channels.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};

use eframe::egui;
use ghidra_decompiler::Program;

/// The decompiler recurses deeply on large functions, so the engine thread gets a large stack.
const ENGINE_STACK_BYTES: usize = 256 * 1024 * 1024;

struct FunctionRow {
    name: String,
    address: u64,
}

enum Request {
    Open(PathBuf),
    Show(u64),
}

enum Response {
    Status(String),
    Opened { file: String, functions: Vec<FunctionRow> },
    Function { address: u64, pseudocode: String, disassembly: String },
    Failed(String),
}

fn engine_thread(requests: Receiver<Request>, responses: Sender<Response>, ctx: egui::Context) {
    let send = |response: Response| {
        let _ = responses.send(response);
        ctx.request_repaint();
    };
    let mut program: Option<Program> = None;
    while let Ok(request) = requests.recv() {
        match request {
            Request::Open(path) => {
                program = None;
                send(Response::Status(format!("Opening {} ...", path.display())));
                let mut opened = match Program::open(&path, None) {
                    Ok(opened) => opened,
                    Err(err) => {
                        send(Response::Failed(format!("Cannot open {}: {}", path.display(), err.explain())));
                        continue;
                    }
                };
                send(Response::Status("Discovering functions ...".to_string()));
                if let Err(err) = opened.discover_functions() {
                    send(Response::Failed(format!("Function discovery failed: {}", err.explain())));
                    continue;
                }
                match opened.functions() {
                    Ok(entries) => {
                        let functions = entries
                            .into_iter()
                            .map(|entry| FunctionRow {
                                name: entry.name,
                                address: entry.address,
                            })
                            .collect();
                        let file = path.file_name().map_or_else(
                            || path.display().to_string(),
                            |name| name.to_string_lossy().into_owned(),
                        );
                        program = Some(opened);
                        send(Response::Opened { file, functions });
                    }
                    Err(err) => send(Response::Failed(format!("Cannot list functions: {}", err.explain()))),
                }
            }
            Request::Show(address) => {
                let Some(program) = program.as_mut() else {
                    continue;
                };
                send(Response::Status(format!("Decompiling {address:#x} ...")));
                let pseudocode = match program.decompile(address) {
                    Ok(text) => text,
                    Err(err) => format!("/* decompilation failed: {} */\n", err.explain()),
                };
                let disassembly = disassemble(program, address);
                send(Response::Function {
                    address,
                    pseudocode,
                    disassembly,
                });
            }
        }
    }
}

fn disassemble(program: &Program, address: u64) -> String {
    let size = match program.function_size(address) {
        Ok(size) if size > 0 => size,
        Ok(_) => return "; function size is zero\n".to_string(),
        Err(err) => return format!("; size lookup failed: {}\n", err.explain()),
    };
    let report = match program.disassemble_range_recovering(address, size) {
        Ok(report) => report,
        Err(err) => return format!("; disassembly failed: {}\n", err.explain()),
    };
    let mut text = String::new();
    for instruction in &report.instructions {
        let bytes = instruction
            .bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        text.push_str(&format!(
            "{:#010x}  {:<24} {} {}\n",
            instruction.address, bytes, instruction.mnemonic, instruction.operands
        ));
    }
    for gap in &report.gaps {
        text.push_str(&format!("{:#010x}  <undecoded {} byte(s)>\n", gap.address, gap.length));
    }
    text
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Pseudocode,
    Disassembly,
}

struct App {
    requests: Sender<Request>,
    responses: Receiver<Response>,
    path_input: String,
    file: Option<String>,
    functions: Vec<FunctionRow>,
    filter: String,
    selected: Option<u64>,
    pseudocode: String,
    disassembly: String,
    tab: Tab,
    status: String,
}

impl App {
    fn new(ctx: egui::Context) -> App {
        let (request_tx, request_rx) = mpsc::channel();
        let (response_tx, response_rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("reverse-pp-engine".to_string())
            .stack_size(ENGINE_STACK_BYTES)
            .spawn(move || engine_thread(request_rx, response_tx, ctx))
            .expect("cannot start the engine thread");
        App {
            requests: request_tx,
            responses: response_rx,
            path_input: String::new(),
            file: None,
            functions: Vec::new(),
            filter: String::new(),
            selected: None,
            pseudocode: String::new(),
            disassembly: String::new(),
            tab: Tab::Pseudocode,
            status: "Drop a binary onto the window, or type a path and press Open.".to_string(),
        }
    }

    fn open(&mut self, path: PathBuf) {
        self.path_input = path.display().to_string();
        self.functions.clear();
        self.selected = None;
        self.pseudocode.clear();
        self.disassembly.clear();
        let _ = self.requests.send(Request::Open(path));
    }

    fn poll(&mut self) {
        while let Ok(response) = self.responses.try_recv() {
            match response {
                Response::Status(text) => self.status = text,
                Response::Opened { file, functions } => {
                    self.status = format!("{file}: {} functions", functions.len());
                    self.file = Some(file);
                    self.functions = functions;
                }
                Response::Function {
                    address,
                    pseudocode,
                    disassembly,
                } => {
                    if self.selected == Some(address) {
                        self.status = format!("{address:#x}");
                        self.pseudocode = pseudocode;
                        self.disassembly = disassembly;
                    }
                }
                Response::Failed(message) => self.status = message,
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        let dropped = ctx.input(|input| input.raw.dropped_files.iter().find_map(|file| file.path.clone()));
        if let Some(path) = dropped {
            self.open(path);
        }

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("File:");
                let edit = ui.add(egui::TextEdit::singleline(&mut self.path_input).desired_width(480.0));
                let submitted = edit.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
                if (ui.button("Open").clicked() || submitted) && !self.path_input.trim().is_empty() {
                    self.open(PathBuf::from(self.path_input.trim()));
                }
            });
        });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.label(&self.status);
        });

        egui::SidePanel::left("functions").default_width(320.0).show(ctx, |ui| {
            ui.heading(match &self.file {
                Some(file) => format!("Functions - {file}"),
                None => "Functions".to_string(),
            });
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("filter by name or address"));
            let needle = self.filter.trim().to_lowercase();
            let shown: Vec<usize> = (0..self.functions.len())
                .filter(|&index| {
                    needle.is_empty() || {
                        let row = &self.functions[index];
                        row.name.to_lowercase().contains(&needle) || format!("{:x}", row.address).contains(&needle)
                    }
                })
                .collect();
            ui.label(format!("{} shown", shown.len()));
            let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
            let mut clicked = None;
            egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(
                ui,
                row_height,
                shown.len(),
                |ui, range| {
                    for &index in &shown[range] {
                        let row = &self.functions[index];
                        let label = format!("{:#010x}  {}", row.address, row.name);
                        let selected = self.selected == Some(row.address);
                        if ui.selectable_label(selected, egui::RichText::new(label).monospace()).clicked() {
                            clicked = Some(row.address);
                        }
                    }
                },
            );
            if let Some(address) = clicked {
                self.selected = Some(address);
                let _ = self.requests.send(Request::Show(address));
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Pseudocode, "Pseudocode");
                ui.selectable_value(&mut self.tab, Tab::Disassembly, "Disassembly");
            });
            ui.separator();
            let text = match self.tab {
                Tab::Pseudocode => &self.pseudocode,
                Tab::Disassembly => &self.disassembly,
            };
            egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                // A read-only, selectable text view; `&str` makes the editor non-editable.
                ui.add(
                    egui::TextEdit::multiline(&mut text.as_str())
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                );
            });
        });
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Reverse++")
            .with_inner_size([1280.0, 800.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Reverse++",
        options,
        Box::new(|creation| Ok(Box::new(App::new(creation.egui_ctx.clone())))),
    )
}
