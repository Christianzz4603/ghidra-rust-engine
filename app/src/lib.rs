//! Reverse++ native app. The layout follows Ghidra's tool windows (symbol tree, listing,
//! decompiler, function graph) but rearranged for touch: on a narrow screen (phones) the windows
//! become pages behind a bottom navigation bar, on a wide screen they sit side by side.
//! All engine work runs on a dedicated thread; the UI talks to it over channels.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};

use eframe::egui::{self, Align2, Color32, CornerRadius, FontId, Margin, RichText, Stroke, Vec2};
use ghidra_decompiler::Program;
use ghidra_decompiler::intelligence::{BinaryIntelligence, FlowKind};
use ghidra_decompiler::patch::PatchableImage;

/// The decompiler recurses deeply on large functions, so the engine thread gets a large stack.
const ENGINE_STACK_BYTES: usize = 256 * 1024 * 1024;
/// Below this width the layout switches to the phone layout.
const PHONE_WIDTH: f32 = 760.0;

// ---------------------------------------------------------------- theme

const BG: Color32 = Color32::from_rgb(0x0D, 0x10, 0x16);
const SURFACE: Color32 = Color32::from_rgb(0x14, 0x19, 0x22);
const CARD: Color32 = Color32::from_rgb(0x1B, 0x22, 0x2D);
const CARD_HOT: Color32 = Color32::from_rgb(0x26, 0x2F, 0x3F);
const BORDER: Color32 = Color32::from_rgb(0x2A, 0x33, 0x42);
const ACCENT: Color32 = Color32::from_rgb(0x8B, 0x7B, 0xFF);
const ACCENT_2: Color32 = Color32::from_rgb(0x2D, 0xD4, 0xBF);
const TEXT: Color32 = Color32::from_rgb(0xE6, 0xE9, 0xF0);
const DIM: Color32 = Color32::from_rgb(0x8A, 0x93, 0xA5);
const GOOD: Color32 = Color32::from_rgb(0x4A, 0xDE, 0x80);
const BAD: Color32 = Color32::from_rgb(0xF8, 0x71, 0x71);
const WARN: Color32 = Color32::from_rgb(0xFB, 0xBF, 0x24);
const BLUE: Color32 = Color32::from_rgb(0x60, 0xA5, 0xFA);

fn apply_theme(ctx: &egui::Context, phone: bool) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = BG;
    visuals.window_fill = SURFACE;
    visuals.extreme_bg_color = Color32::from_rgb(0x0A, 0x0D, 0x12);
    visuals.override_text_color = Some(TEXT);
    visuals.selection.bg_fill = ACCENT.gamma_multiply(0.45);
    visuals.hyperlink_color = ACCENT_2;
    let radius = CornerRadius::same(12);
    for widget in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        widget.corner_radius = radius;
    }
    visuals.widgets.inactive.bg_fill = CARD;
    visuals.widgets.inactive.weak_bg_fill = CARD;
    visuals.widgets.hovered.bg_fill = CARD_HOT;
    visuals.widgets.hovered.weak_bg_fill = CARD_HOT;
    visuals.widgets.active.bg_fill = ACCENT.gamma_multiply(0.6);
    visuals.widgets.active.weak_bg_fill = ACCENT.gamma_multiply(0.6);
    ctx.set_visuals(visuals);
    ctx.style_mut(|style| {
        // Bigger touch targets on phones.
        style.spacing.interact_size.y = if phone { 42.0 } else { 30.0 };
        style.spacing.item_spacing = Vec2::new(10.0, if phone { 10.0 } else { 6.0 });
        style.spacing.button_padding = Vec2::new(14.0, 8.0);
        style.text_styles.insert(
            egui::TextStyle::Monospace,
            FontId::monospace(if phone { 14.0 } else { 13.0 }),
        );
        style.text_styles.insert(
            egui::TextStyle::Body,
            FontId::proportional(if phone { 16.0 } else { 14.0 }),
        );
        style.text_styles.insert(
            egui::TextStyle::Button,
            FontId::proportional(if phone { 16.0 } else { 14.0 }),
        );
    });
}

fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(CARD)
        .corner_radius(CornerRadius::same(16))
        .stroke(Stroke::new(1.0, BORDER))
        .inner_margin(Margin::same(14))
        .show(ui, add)
        .inner
}

// ---------------------------------------------------------------- engine thread

struct FunctionRow {
    name: String,
    address: u64,
}

struct InsnRow {
    address: u64,
    bytes: String,
    text: String,
}

#[derive(Clone, Copy, PartialEq)]
enum EdgeKind {
    Taken,
    NotTaken,
    Jump,
    Fall,
}

struct GraphBlock {
    start: u64,
    lines: Vec<String>,
}

struct GraphData {
    blocks: Vec<GraphBlock>,
    edges: Vec<(usize, usize, EdgeKind)>,
}

enum PatchOp {
    Nop { address: u64, length: usize },
    InvertBranch { address: u64 },
    ReturnConst { address: u64, value: u32 },
    Bytes { address: u64, data: Vec<u8> },
    Undo,
    RevertAll,
    Save(PathBuf),
}

enum Request {
    Open(PathBuf),
    Show(u64),
    Patch(PatchOp),
}

enum Response {
    Status(String),
    Opened {
        file: String,
        functions: Vec<FunctionRow>,
        can_patch: bool,
    },
    Function {
        address: u64,
        pseudocode: String,
        listing: Vec<InsnRow>,
        graph: Option<GraphData>,
    },
    PatchReport {
        text: String,
        saved: Option<PathBuf>,
    },
    Failed(String),
}

fn engine_thread(requests: Receiver<Request>, responses: Sender<Response>, ctx: egui::Context) {
    let send = |response: Response| {
        let _ = responses.send(response);
        ctx.request_repaint();
    };
    let mut program: Option<Program> = None;
    let mut image: Option<PatchableImage> = None;
    while let Ok(request) = requests.recv() {
        match request {
            Request::Open(path) => {
                program = None;
                image = None;
                send(Response::Status(format!("Opening {} ...", path.display())));
                let mut opened = match Program::open(&path, None) {
                    Ok(opened) => opened,
                    Err(err) => {
                        send(Response::Failed(format!(
                            "Cannot open {}: {}",
                            path.display(),
                            err.explain()
                        )));
                        continue;
                    }
                };
                send(Response::Status("Discovering functions ...".to_string()));
                if let Err(err) = opened.discover_functions() {
                    send(Response::Failed(format!(
                        "Function discovery failed: {}",
                        err.explain()
                    )));
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
                        // Patching works on the file bytes; APK/DEX/class inputs are not patchable here.
                        image = PatchableImage::open(&path).ok();
                        program = Some(opened);
                        send(Response::Opened {
                            file,
                            functions,
                            can_patch: image.is_some(),
                        });
                    }
                    Err(err) => send(Response::Failed(format!(
                        "Cannot list functions: {}",
                        err.explain()
                    ))),
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
                let listing = listing_rows(program, address);
                let graph = BinaryIntelligence::new(program)
                    .function_cfg(address)
                    .ok()
                    .map(|cfg| graph_data(&cfg));
                send(Response::Function {
                    address,
                    pseudocode,
                    listing,
                    graph,
                });
            }
            Request::Patch(op) => {
                let Some(image) = image.as_mut() else {
                    send(Response::Failed(
                        "This file cannot be patched (not an ELF, PE or Mach-O image).".to_string(),
                    ));
                    continue;
                };
                let mut saved = None;
                let result = match op {
                    PatchOp::Nop { address, length } => image.nop(address, length),
                    PatchOp::InvertBranch { address } => image.invert_branch(address),
                    PatchOp::ReturnConst { address, value } => image.return_const(address, value),
                    PatchOp::Bytes { address, data } => image.write(address, &data, "manual bytes"),
                    PatchOp::Undo => {
                        image.undo();
                        Ok(())
                    }
                    PatchOp::RevertAll => {
                        image.revert_all();
                        Ok(())
                    }
                    PatchOp::Save(path) => {
                        image.fix_pe_checksum();
                        let result = image.save(&path);
                        if result.is_ok() {
                            saved = Some(path);
                        }
                        result
                    }
                };
                match result {
                    Ok(()) => send(Response::PatchReport {
                        text: image.report(),
                        saved,
                    }),
                    Err(err) => send(Response::Failed(format!("Patch failed: {}", err.explain()))),
                }
            }
        }
    }
}

fn listing_rows(program: &mut Program, address: u64) -> Vec<InsnRow> {
    let size = match program.function_size(address) {
        Ok(size) if size > 0 => size,
        _ => return Vec::new(),
    };
    let Ok(report) = program.disassemble_range_recovering(address, size) else {
        return Vec::new();
    };
    let mut rows: Vec<InsnRow> = report
        .instructions
        .iter()
        .map(|instruction| InsnRow {
            address: instruction.address,
            bytes: instruction
                .bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" "),
            text: format!("{} {}", instruction.mnemonic, instruction.operands),
        })
        .collect();
    for gap in &report.gaps {
        rows.push(InsnRow {
            address: gap.address,
            bytes: String::new(),
            text: format!("<undecoded {} byte(s)>", gap.length),
        });
    }
    rows.sort_by_key(|row| row.address);
    rows
}

fn graph_data(cfg: &ghidra_decompiler::intelligence::ControlFlowGraph) -> GraphData {
    let mut order: Vec<(u64, usize)> = cfg
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start, index))
        .collect();
    order.sort_unstable();
    let block_of = |address: u64| -> Option<usize> {
        let position = order.partition_point(|(start, _)| *start <= address);
        let (_, index) = *order.get(position.checked_sub(1)?)?;
        (address < cfg.blocks[index].end.max(cfg.blocks[index].start + 1)).then_some(index)
    };
    let blocks: Vec<GraphBlock> = cfg
        .blocks
        .iter()
        .map(|block| {
            let mut lines: Vec<String> = block
                .instructions
                .iter()
                .take(10)
                .map(|instruction| {
                    format!(
                        "{:#x}  {} {}",
                        instruction.address, instruction.mnemonic, instruction.operands
                    )
                })
                .collect();
            if block.instructions.len() > 10 {
                lines.push(format!("... {} more", block.instructions.len() - 10));
            }
            GraphBlock {
                start: block.start,
                lines,
            }
        })
        .collect();
    let mut has_conditional = vec![false; cfg.blocks.len()];
    for edge in &cfg.edges {
        if edge.kind == FlowKind::ConditionalBranch
            && let Some(from) = block_of(edge.from)
        {
            has_conditional[from] = true;
        }
    }
    let mut edges = Vec::new();
    for edge in &cfg.edges {
        let (Some(from), Some(to_address)) = (block_of(edge.from), edge.to) else {
            continue;
        };
        let Some(to) = block_of(to_address) else {
            continue;
        };
        let kind = match edge.kind {
            FlowKind::ConditionalBranch => EdgeKind::Taken,
            FlowKind::Branch => EdgeKind::Jump,
            FlowKind::Fallthrough if has_conditional[from] => EdgeKind::NotTaken,
            FlowKind::Fallthrough => EdgeKind::Fall,
            _ => continue,
        };
        edges.push((from, to, kind));
    }
    GraphData { blocks, edges }
}

// ---------------------------------------------------------------- graph layout

struct GraphView {
    data: GraphData,
    rects: Vec<egui::Rect>,
    size: Vec2,
}

const BLOCK_WIDTH: f32 = 300.0;
const LINE_HEIGHT: f32 = 15.0;
const GAP_X: f32 = 40.0;
const GAP_Y: f32 = 56.0;

impl GraphView {
    fn new(data: GraphData) -> GraphView {
        let count = data.blocks.len();
        let mut successors = vec![Vec::new(); count];
        for (from, to, _) in &data.edges {
            successors[*from].push(*to);
        }
        let mut layer = vec![usize::MAX; count];
        if count > 0 {
            layer[0] = 0;
            let mut queue = VecDeque::from([0usize]);
            while let Some(block) = queue.pop_front() {
                for &next in &successors[block] {
                    if layer[next] == usize::MAX {
                        layer[next] = layer[block] + 1;
                        queue.push_back(next);
                    }
                }
            }
        }
        let deepest = layer
            .iter()
            .copied()
            .filter(|layer| *layer != usize::MAX)
            .max()
            .unwrap_or(0);
        for entry in &mut layer {
            if *entry == usize::MAX {
                *entry = deepest + 1;
            }
        }
        let mut rows: Vec<Vec<usize>> = vec![Vec::new(); deepest + 2];
        for (block, &row) in layer.iter().enumerate() {
            rows[row].push(block);
        }
        let mut rects = vec![egui::Rect::NOTHING; count];
        let mut y = 0.0f32;
        let mut width = 0.0f32;
        for row in &rows {
            let height = row
                .iter()
                .map(|&block| 26.0 + LINE_HEIGHT * data.blocks[block].lines.len().max(1) as f32)
                .fold(0.0f32, f32::max);
            for (column, &block) in row.iter().enumerate() {
                let x = column as f32 * (BLOCK_WIDTH + GAP_X);
                let own = 26.0 + LINE_HEIGHT * data.blocks[block].lines.len().max(1) as f32;
                rects[block] = egui::Rect::from_min_size(egui::pos2(x, y), Vec2::new(BLOCK_WIDTH, own));
                width = width.max(x + BLOCK_WIDTH);
            }
            y += height + GAP_Y;
        }
        GraphView {
            data,
            rects,
            size: Vec2::new(width.max(1.0), y.max(1.0)),
        }
    }

    fn draw(&self, ui: &mut egui::Ui, zoom: f32) {
        let margin = 20.0;
        let (response, painter) =
            ui.allocate_painter(self.size * zoom + Vec2::splat(margin * 2.0), egui::Sense::hover());
        let origin = response.rect.min + Vec2::splat(margin);
        let place = |rect: egui::Rect| {
            egui::Rect::from_min_max(
                origin + rect.min.to_vec2() * zoom,
                origin + rect.max.to_vec2() * zoom,
            )
        };
        for &(from, to, kind) in &self.data.edges {
            let color = match kind {
                EdgeKind::Taken => GOOD,
                EdgeKind::NotTaken => BAD,
                EdgeKind::Jump => BLUE,
                EdgeKind::Fall => DIM,
            };
            let a = place(self.rects[from]);
            let b = place(self.rects[to]);
            let start = egui::pos2(a.center().x, a.bottom());
            let end = egui::pos2(b.center().x, b.top());
            painter.line_segment([start, end], Stroke::new(1.6, color));
            let direction = (end - start).normalized();
            if direction.x.is_finite() && direction.y.is_finite() {
                let normal = Vec2::new(-direction.y, direction.x);
                let scale = zoom.max(0.6);
                let base = end - direction * 10.0 * scale;
                painter.add(egui::Shape::convex_polygon(
                    vec![end, base + normal * 5.0 * scale, base - normal * 5.0 * scale],
                    color,
                    Stroke::NONE,
                ));
            }
        }
        for (index, block) in self.data.blocks.iter().enumerate() {
            let rect = place(self.rects[index]);
            painter.rect_filled(rect, CornerRadius::same(10), BORDER);
            painter.rect_filled(rect.shrink(1.5), CornerRadius::same(9), CARD);
            let header = egui::Rect::from_min_size(rect.min, Vec2::new(rect.width(), 22.0 * zoom));
            painter.rect_filled(
                header.shrink(1.5),
                CornerRadius {
                    nw: 9,
                    ne: 9,
                    sw: 0,
                    se: 0,
                },
                ACCENT.gamma_multiply(0.35),
            );
            painter.text(
                header.left_center() + Vec2::new(8.0 * zoom, 0.0),
                Align2::LEFT_CENTER,
                format!("{:#x}", block.start),
                FontId::monospace(12.0 * zoom),
                TEXT,
            );
            for (line_index, line) in block.lines.iter().enumerate() {
                painter.text(
                    egui::pos2(
                        rect.left() + 8.0 * zoom,
                        rect.top() + (24.0 + LINE_HEIGHT * line_index as f32) * zoom,
                    ),
                    Align2::LEFT_TOP,
                    line,
                    FontId::monospace(11.5 * zoom),
                    TEXT,
                );
            }
        }
    }
}

// ---------------------------------------------------------------- syntax coloring

const C_KEYWORDS: &[&str] = &[
    "if",
    "else",
    "while",
    "for",
    "do",
    "return",
    "goto",
    "switch",
    "case",
    "break",
    "continue",
    "default",
    "void",
    "int",
    "char",
    "long",
    "short",
    "unsigned",
    "signed",
    "float",
    "double",
    "struct",
    "union",
    "enum",
    "sizeof",
    "bool",
    "undefined",
    "undefined1",
    "undefined2",
    "undefined4",
    "undefined8",
    "code",
    "byte",
    "uint",
    "ulong",
];

fn highlight_c(line: &str) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let (code, comment) = match line.find("//") {
        Some(position) => (&line[..position], Some(&line[position..])),
        None => (line, None),
    };
    let mut word = String::new();
    for character in code.chars() {
        if character.is_alphanumeric() || character == '_' {
            word.push(character);
        } else {
            flush_word(&mut job, &mut word);
            let mut buffer = [0u8; 4];
            append_text(&mut job, character.encode_utf8(&mut buffer), DIM);
        }
    }
    flush_word(&mut job, &mut word);
    if let Some(comment) = comment {
        append_text(&mut job, comment, DIM);
    }
    job
}

fn append_text(job: &mut egui::text::LayoutJob, text: &str, color: Color32) {
    job.append(
        text,
        0.0,
        egui::TextFormat {
            font_id: FontId::monospace(13.0),
            color,
            ..Default::default()
        },
    );
}

fn flush_word(job: &mut egui::text::LayoutJob, word: &mut String) {
    if word.is_empty() {
        return;
    }
    let color = if C_KEYWORDS.contains(&word.as_str()) {
        ACCENT
    } else if word.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        WARN
    } else if word.starts_with("FUN_") || word.starts_with("sub_") {
        ACCENT_2
    } else {
        TEXT
    };
    append_text(job, word, color);
    word.clear();
}

// ---------------------------------------------------------------- app

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Functions,
    Listing,
    Pseudocode,
    Graph,
    Patch,
}

impl Tab {
    fn title(self) -> &'static str {
        match self {
            Tab::Functions => "Functions",
            Tab::Listing => "Listing",
            Tab::Pseudocode => "Decompile",
            Tab::Graph => "Graph",
            Tab::Patch => "Patch",
        }
    }
}

#[derive(Default)]
struct PatchUi {
    address: String,
    length: String,
    value: String,
    bytes: String,
    save_path: String,
    log: String,
    can_patch: bool,
    saved: Option<PathBuf>,
}

struct App {
    requests: Sender<Request>,
    responses: Receiver<Response>,
    path_input: String,
    file: Option<String>,
    functions: Vec<FunctionRow>,
    filter: String,
    selected: Option<u64>,
    pseudocode: Vec<String>,
    listing: Vec<InsnRow>,
    graph: Option<GraphView>,
    graph_zoom: f32,
    selected_insn: Option<u64>,
    tab: Tab,
    status: String,
    patch: PatchUi,
}

fn parse_number(text: &str) -> Option<u64> {
    let text = text.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(text, 16).ok()
}

fn parse_bytes(text: &str) -> Option<Vec<u8>> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace() && *c != ',').collect();
    let digits = digits.trim_start_matches("0x");
    if digits.is_empty() || digits.len() % 2 != 0 {
        return None;
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).ok())
        .collect()
}

fn tab_button(ui: &mut egui::Ui, tab: Tab, current: Tab, size: f32) -> bool {
    let selected = tab == current;
    let label = RichText::new(tab.title())
        .size(size)
        .color(if selected { ACCENT } else { DIM });
    let fill = if selected {
        ACCENT.gamma_multiply(0.18)
    } else {
        Color32::TRANSPARENT
    };
    ui.add(egui::Button::new(label).fill(fill)).clicked()
}

fn primary_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_string()).strong()).fill(ACCENT.gamma_multiply(0.7))
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
            pseudocode: Vec::new(),
            listing: Vec::new(),
            graph: None,
            graph_zoom: 1.0,
            selected_insn: None,
            tab: Tab::Functions,
            status: "Open a binary to start.".to_string(),
            patch: PatchUi {
                length: "1".to_string(),
                value: "0".to_string(),
                ..Default::default()
            },
        }
    }

    fn open(&mut self, path: PathBuf) {
        self.path_input = path.display().to_string();
        self.patch.save_path = format!("{}.patched", path.display());
        self.functions.clear();
        self.selected = None;
        self.pseudocode.clear();
        self.listing.clear();
        self.graph = None;
        self.selected_insn = None;
        self.patch.log.clear();
        self.patch.saved = None;
        let _ = self.requests.send(Request::Open(path));
    }

    fn select(&mut self, address: u64, phone: bool) {
        self.selected = Some(address);
        self.patch.address = format!("{address:#x}");
        let _ = self.requests.send(Request::Show(address));
        if phone {
            self.tab = Tab::Pseudocode;
        }
    }

    fn poll(&mut self) {
        while let Ok(response) = self.responses.try_recv() {
            match response {
                Response::Status(text) => self.status = text,
                Response::Opened {
                    file,
                    functions,
                    can_patch,
                } => {
                    self.status = format!("{file}: {} functions", functions.len());
                    self.file = Some(file);
                    self.functions = functions;
                    self.patch.can_patch = can_patch;
                }
                Response::Function {
                    address,
                    pseudocode,
                    listing,
                    graph,
                } => {
                    if self.selected == Some(address) {
                        self.status = format!("{address:#x}");
                        self.pseudocode = pseudocode.lines().map(str::to_string).collect();
                        self.listing = listing;
                        self.graph = graph.map(GraphView::new);
                    }
                }
                Response::PatchReport { text, saved } => {
                    self.patch.log = text;
                    if let Some(path) = saved {
                        self.status = format!("Saved {}", path.display());
                        self.patch.saved = Some(path);
                    }
                }
                Response::Failed(message) => self.status = message,
            }
        }
    }

    // -- pages

    fn open_card(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            ui.label(RichText::new("Open a binary").strong().size(18.0));
            ui.label(RichText::new("ELF, PE, Mach-O, DEX/APK, Java class/JAR, Python pyc").color(DIM));
            ui.add_space(6.0);
            let edit = ui.add(
                egui::TextEdit::singleline(&mut self.path_input)
                    .hint_text("/path/to/library.so")
                    .desired_width(f32::INFINITY),
            );
            let submitted = edit.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
            ui.horizontal(|ui| {
                let open = ui.add(primary_button("Open"));
                if (open.clicked() || submitted) && !self.path_input.trim().is_empty() {
                    self.open(PathBuf::from(self.path_input.trim()));
                }
                ui.label(RichText::new("or drop a file on the window").color(DIM));
            });
        });
    }

    fn functions_page(&mut self, ui: &mut egui::Ui, phone: bool) {
        if self.file.is_none() {
            self.open_card(ui);
            return;
        }
        ui.horizontal(|ui| {
            ui.label(RichText::new(self.file.clone().unwrap_or_default()).strong().size(18.0));
            ui.label(RichText::new(format!("{} functions", self.functions.len())).color(DIM));
        });
        ui.add(
            egui::TextEdit::singleline(&mut self.filter)
                .hint_text("Filter by name or address")
                .desired_width(f32::INFINITY),
        );
        let needle = self.filter.trim().to_lowercase();
        let shown: Vec<usize> = (0..self.functions.len())
            .filter(|&index| {
                needle.is_empty() || {
                    let row = &self.functions[index];
                    row.name.to_lowercase().contains(&needle) || format!("{:x}", row.address).contains(&needle)
                }
            })
            .collect();
        let row_height = 58.0;
        let mut clicked = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, row_height, shown.len(), |ui, range| {
                for &index in &shown[range] {
                    let row = &self.functions[index];
                    let (rect, response) =
                        ui.allocate_exact_size(Vec2::new(ui.available_width(), row_height - 8.0), egui::Sense::click());
                    let selected = self.selected == Some(row.address);
                    let fill = if selected {
                        ACCENT.gamma_multiply(0.30)
                    } else if response.hovered() {
                        CARD_HOT
                    } else {
                        CARD
                    };
                    ui.painter().rect_filled(rect, CornerRadius::same(14), fill);
                    ui.painter().text(
                        rect.left_top() + Vec2::new(14.0, 9.0),
                        Align2::LEFT_TOP,
                        &row.name,
                        FontId::proportional(15.5),
                        TEXT,
                    );
                    ui.painter().text(
                        rect.left_bottom() + Vec2::new(14.0, -8.0),
                        Align2::LEFT_BOTTOM,
                        format!("{:#010x}", row.address),
                        FontId::monospace(12.0),
                        ACCENT_2,
                    );
                    if response.clicked() {
                        clicked = Some(row.address);
                    }
                }
            });
        if let Some(address) = clicked {
            self.select(address, phone);
        }
    }

    fn listing_page(&mut self, ui: &mut egui::Ui) {
        if self.listing.is_empty() {
            ui.label(RichText::new("Select a function.").color(DIM));
            return;
        }
        ui.label(RichText::new("Tap an instruction to use it as the patch address.").color(DIM));
        let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 8.0;
        let mut clicked = None;
        egui::ScrollArea::both()
            .auto_shrink([false, false])
            .show_rows(ui, row_height, self.listing.len(), |ui, range| {
                for row in &self.listing[range] {
                    let mut job = egui::text::LayoutJob::default();
                    let font = FontId::monospace(13.0);
                    let mut part = |text: String, color: Color32| {
                        job.append(
                            &text,
                            0.0,
                            egui::TextFormat {
                                font_id: font.clone(),
                                color,
                                ..Default::default()
                            },
                        );
                    };
                    part(format!("{:#010x}  ", row.address), ACCENT_2);
                    part(format!("{:<24} ", row.bytes), DIM);
                    part(row.text.clone(), TEXT);
                    let selected = self.selected_insn == Some(row.address);
                    if ui.selectable_label(selected, job).clicked() {
                        clicked = Some(row.address);
                    }
                }
            });
        if let Some(address) = clicked {
            self.selected_insn = Some(address);
            self.patch.address = format!("{address:#x}");
            self.status = format!("Patch address {address:#x}");
        }
    }

    fn pseudocode_page(&mut self, ui: &mut egui::Ui) {
        if self.pseudocode.is_empty() {
            ui.label(RichText::new("Select a function.").color(DIM));
            return;
        }
        let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 3.0;
        egui::ScrollArea::both()
            .auto_shrink([false, false])
            .show_rows(ui, row_height, self.pseudocode.len(), |ui, range| {
                for line in &self.pseudocode[range] {
                    ui.label(highlight_c(line));
                }
            });
    }

    fn graph_page(&mut self, ui: &mut egui::Ui) {
        let Some(graph) = &self.graph else {
            ui.label(RichText::new("Select a function to see its control-flow graph.").color(DIM));
            return;
        };
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!(
                    "{} blocks, {} edges",
                    graph.data.blocks.len(),
                    graph.data.edges.len()
                ))
                .color(DIM),
            );
            ui.add(egui::Slider::new(&mut self.graph_zoom, 0.3..=2.0).text("zoom"));
            ui.label(RichText::new("taken").color(GOOD));
            ui.label(RichText::new("not taken").color(BAD));
            ui.label(RichText::new("jump").color(BLUE));
        });
        egui::ScrollArea::both()
            .auto_shrink([false, false])
            .show(ui, |ui| graph.draw(ui, self.graph_zoom));
    }

    fn patch_page(&mut self, ui: &mut egui::Ui) {
        if !self.patch.can_patch {
            card(ui, |ui| {
                ui.label(RichText::new("Patching").strong().size(18.0));
                ui.label(RichText::new("Open an ELF, PE or Mach-O file to patch it.").color(DIM));
            });
            return;
        }
        let address = parse_number(&self.patch.address);
        let requests = self.requests.clone();
        let send = move |op: PatchOp| {
            let _ = requests.send(Request::Patch(op));
        };
        card(ui, |ui| {
            ui.label(RichText::new("Binary patch").strong().size(18.0));
            ui.label(
                RichText::new(
                    "Edits a copy of the file bytes at a virtual address. The listing keeps showing the original until you save and reopen.",
                )
                .color(DIM),
            );
            ui.horizontal(|ui| {
                ui.label("Address");
                ui.add(egui::TextEdit::singleline(&mut self.patch.address).desired_width(150.0));
            });
            ui.horizontal_wrapped(|ui| {
                ui.label("NOP bytes");
                ui.add(egui::TextEdit::singleline(&mut self.patch.length).desired_width(60.0));
                if ui.button("NOP").clicked()
                    && let (Some(address), Ok(length)) = (address, self.patch.length.trim().parse::<usize>())
                {
                    send(PatchOp::Nop { address, length });
                }
                if ui.button("Invert branch").clicked()
                    && let Some(address) = address
                {
                    send(PatchOp::InvertBranch { address });
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label("Return value (hex)");
                ui.add(egui::TextEdit::singleline(&mut self.patch.value).desired_width(90.0));
                if ui.button("Return constant").clicked()
                    && let (Some(address), Some(value)) = (address, parse_number(&self.patch.value))
                {
                    send(PatchOp::ReturnConst {
                        address,
                        value: value as u32,
                    });
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label("Bytes");
                ui.add(
                    egui::TextEdit::singleline(&mut self.patch.bytes)
                        .hint_text("90 90 c3")
                        .desired_width(220.0),
                );
                if ui.button("Write").clicked()
                    && let (Some(address), Some(data)) = (address, parse_bytes(&self.patch.bytes))
                {
                    send(PatchOp::Bytes { address, data });
                }
            });
            ui.horizontal(|ui| {
                if ui.button("Undo").clicked() {
                    send(PatchOp::Undo);
                }
                if ui.button("Revert all").clicked() {
                    send(PatchOp::RevertAll);
                }
            });
        });
        let requests = self.requests.clone();
        card(ui, |ui| {
            ui.label(RichText::new("Save").strong().size(16.0));
            ui.add(egui::TextEdit::singleline(&mut self.patch.save_path).desired_width(f32::INFINITY));
            ui.horizontal(|ui| {
                if ui.add(primary_button("Save patched file")).clicked() && !self.patch.save_path.trim().is_empty() {
                    let _ = requests.send(Request::Patch(PatchOp::Save(PathBuf::from(self.patch.save_path.trim()))));
                }
                if let Some(path) = self.patch.saved.clone()
                    && ui.button("Open patched file").clicked()
                {
                    self.open(path);
                }
            });
        });
        card(ui, |ui| {
            ui.label(RichText::new("Patch journal").strong().size(16.0));
            egui::ScrollArea::vertical().max_height(220.0).show(ui, |ui| {
                let text = if self.patch.log.is_empty() {
                    "No patches yet."
                } else {
                    &self.patch.log
                };
                ui.label(RichText::new(text).monospace());
            });
        });
    }

    fn page(&mut self, ui: &mut egui::Ui, phone: bool) {
        match self.tab {
            Tab::Functions => self.functions_page(ui, phone),
            Tab::Listing => self.listing_page(ui),
            Tab::Pseudocode => self.pseudocode_page(ui),
            Tab::Graph => self.graph_page(ui),
            Tab::Patch => self.patch_page(ui),
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let phone = ctx.screen_rect().width() < PHONE_WIDTH;
        apply_theme(ctx, phone);
        self.poll();
        let dropped = ctx.input(|input| input.raw.dropped_files.iter().find_map(|file| file.path.clone()));
        if let Some(path) = dropped {
            self.open(path);
        }
        let frame = |fill: Color32| egui::Frame::new().fill(fill).inner_margin(Margin::symmetric(14, 10));

        egui::TopBottomPanel::top("app_bar").frame(frame(SURFACE)).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Reverse++").strong().size(20.0).color(ACCENT));
                if let Some(file) = &self.file {
                    ui.label(RichText::new(file).color(DIM));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.file.is_some() && ui.button("Open").clicked() {
                        self.file = None;
                        self.tab = Tab::Functions;
                    }
                });
            });
        });

        if phone {
            egui::TopBottomPanel::bottom("nav").frame(frame(SURFACE)).show(ctx, |ui| {
                ui.columns(5, |columns| {
                    let tabs = [Tab::Functions, Tab::Listing, Tab::Pseudocode, Tab::Graph, Tab::Patch];
                    for (column, tab) in columns.iter_mut().zip(tabs) {
                        if tab_button(column, tab, self.tab, 13.0) {
                            self.tab = tab;
                        }
                    }
                });
            });
            egui::TopBottomPanel::bottom("status")
                .frame(frame(BG))
                .show(ctx, |ui| {
                    ui.label(RichText::new(&self.status).color(DIM).size(12.5));
                });
            egui::CentralPanel::default()
                .frame(frame(BG))
                .show(ctx, |ui| self.page(ui, true));
        } else {
            egui::TopBottomPanel::bottom("status")
                .frame(frame(SURFACE))
                .show(ctx, |ui| {
                    ui.label(RichText::new(&self.status).color(DIM));
                });
            egui::SidePanel::left("functions")
                .default_width(360.0)
                .frame(frame(BG))
                .show(ctx, |ui| {
                    self.functions_page(ui, false);
                });
            egui::CentralPanel::default().frame(frame(BG)).show(ctx, |ui| {
                ui.horizontal(|ui| {
                    for tab in [Tab::Pseudocode, Tab::Listing, Tab::Graph, Tab::Patch] {
                        if tab_button(ui, tab, self.tab, 14.0) {
                            self.tab = tab;
                        }
                    }
                });
                ui.separator();
                if self.tab == Tab::Functions {
                    self.tab = Tab::Pseudocode;
                }
                self.page(ui, false);
            });
        }
    }
}

/// Desktop entry point (Linux and Windows; macOS and iOS are not supported targets).
pub fn run_desktop() -> eframe::Result {
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

/// Android entry point. The Android activity calls this instead of `main`; the whole UI is the
/// same code as on the desktop, switching to the phone layout on narrow screens.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(app: winit::platform::android::activity::AndroidApp) {
    use winit::platform::android::EventLoopBuilderExtAndroid;

    let options = eframe::NativeOptions {
        event_loop_builder: Some(Box::new(move |builder| {
            builder.with_android_app(app);
        })),
        ..Default::default()
    };
    let _ = eframe::run_native(
        "Reverse++",
        options,
        Box::new(|creation| Ok(Box::new(App::new(creation.egui_ctx.clone())))),
    );
}
