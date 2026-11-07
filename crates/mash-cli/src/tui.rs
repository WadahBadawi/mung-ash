use mash_core::{DissectedPacket, Frame};
use mash_dissect::Registry;
use mash_filter::CompiledFilter;
use std::io::{self, BufRead, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiPane {
    PacketList,
    ProtocolTree,
    HexDump,
}

impl TuiPane {
    pub const fn next(self) -> Self {
        match self {
            Self::PacketList => Self::ProtocolTree,
            Self::ProtocolTree => Self::HexDump,
            Self::HexDump => Self::PacketList,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::PacketList => "Packet List",
            Self::ProtocolTree => "Protocol Tree",
            Self::HexDump => "Hex / ASCII Bytes",
        }
    }
}

pub struct TuiApp {
    pub title: String,
    pub frames: Vec<Frame>,
    pub packets: Vec<DissectedPacket>,
    pub filtered_indices: Vec<usize>,
    pub selected: usize,
    pub active_pane: TuiPane,
    pub filter_expr: String,
    pub status: String,
}

impl TuiApp {
    pub fn new(
        title: impl Into<String>,
        frames: Vec<Frame>,
        packets: Vec<DissectedPacket>,
        initial_filter: Option<String>,
    ) -> Self {
        let filtered_indices = (0..packets.len()).collect();
        Self {
            title: title.into(),
            frames,
            packets,
            filtered_indices,
            selected: 0,
            active_pane: TuiPane::PacketList,
            filter_expr: initial_filter.unwrap_or_default(),
            status: "Ready — Type 'j'/'k' to navigate, '/<expr>' to filter, 'tab' to switch pane, 'q' to quit".to_string(),
        }
    }

    pub fn apply_filter(&mut self, expr: &str, registry: Option<&Registry>) {
        match CompiledFilter::compile(expr, registry) {
            Ok(compiled) => {
                self.filter_expr = expr.to_string();
                self.filtered_indices = self
                    .packets
                    .iter()
                    .enumerate()
                    .filter(|(_, p)| compiled.matches(p))
                    .map(|(i, _)| i)
                    .collect();
                self.selected = 0;
                self.status = format!(
                    "Filter applied: '{}' ({}/{} packets matched)",
                    expr,
                    self.filtered_indices.len(),
                    self.packets.len()
                );
            }
            Err(diag) => {
                self.status = format!("Filter error: {}", diag.message);
            }
        }
    }

    pub fn render_snapshot(&self, width: usize) -> String {
        let w = width.max(76);
        let border = "─".repeat(w.saturating_sub(2));
        let mut out = String::new();

        // Top Title & Filter Bar
        out.push_str(&format!("┌{border}┐\n"));
        let hdr = format!(
            " MUNG-ASH TUI | {} | Displayed: {}/{} | Active Pane: [{}]",
            self.title,
            self.filtered_indices.len(),
            self.packets.len(),
            self.active_pane.label()
        );
        out.push_str(&format!("│{:<width$}│\n", truncate_str(&hdr, w - 2), width = w - 2));
        let fbar = format!(
            " Filter: {}",
            if self.filter_expr.is_empty() {
                "<none>"
            } else {
                &self.filter_expr
            }
        );
        out.push_str(&format!("│{:<width$}│\n", truncate_str(&fbar, w - 2), width = w - 2));
        out.push_str(&format!("├{border}┤\n"));

        // Pane 1: Packet List (8 rows window)
        let col_hdr = format!(
            " {:>4} {:>10} {:>16} -> {:<16} {:<8} {:>5} {}",
            "No.", "Time", "Source", "Destination", "Proto", "Len", "Info"
        );
        out.push_str(&format!(
            "│{:<width$}│\n",
            truncate_str(&col_hdr, w - 2),
            width = w - 2
        ));
        let start = self.selected.saturating_sub(3);
        let end = (start + 8).min(self.filtered_indices.len());
        for vis_idx in start..end {
            let pkt_idx = self.filtered_indices[vis_idx];
            let pkt = &self.packets[pkt_idx];
            let s = &pkt.summary;
            let marker = if vis_idx == self.selected { ">" } else { " " };
            let line = format!(
                "{marker}{:>4} {:>10.6} {:>16} -> {:<16} {:<8} {:>5} {}",
                s.number, s.rel_time_sec, s.source, s.destination, s.protocol, s.length, s.info
            );
            out.push_str(&format!(
                "│{:<width$}│\n",
                truncate_str(&line, w - 2),
                width = w - 2
            ));
        }
        out.push_str(&format!("├{border}┤\n"));

        // Pane 2: Protocol Tree for selected packet
        out.push_str(&format!(
            "│{:<width$}│\n",
            truncate_str(" [Protocol Details]", w - 2),
            width = w - 2
        ));
        if let Some(&pkt_idx) = self.filtered_indices.get(self.selected) {
            let pkt = &self.packets[pkt_idx];
            for &root_id in &pkt.tree.roots {
                if let Some(root) = pkt.tree.node(root_id) {
                    let rline = format!("  ▼ {}", root.label);
                    out.push_str(&format!(
                        "│{:<width$}│\n",
                        truncate_str(&rline, w - 2),
                        width = w - 2
                    ));
                    for &cid in root.children.iter().take(4) {
                        if let Some(child) = pkt.tree.node(cid) {
                            let cline = format!("      • {}", child.label);
                            out.push_str(&format!(
                                "│{:<width$}│\n",
                                truncate_str(&cline, w - 2),
                                width = w - 2
                            ));
                        }
                    }
                }
            }
        }
        out.push_str(&format!("├{border}┤\n"));

        // Pane 3: Hex / ASCII Dump (first 4 lines = 64 bytes)
        out.push_str(&format!(
            "│{:<width$}│\n",
            truncate_str(" [Hex / ASCII Packet Bytes]", w - 2),
            width = w - 2
        ));
        if let Some(&pkt_idx) = self.filtered_indices.get(self.selected) {
            if let Some(frame) = self.frames.get(pkt_idx) {
                for (row_i, chunk) in frame.data.chunks(16).take(4).enumerate() {
                    let off = row_i * 16;
                    let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
                    let ascii: String = chunk
                        .iter()
                        .map(|&b| {
                            if (0x20..=0x7e).contains(&b) {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    let hline = format!("  {off:04x}  {:<47}  {ascii}", hex.join(" "));
                    out.push_str(&format!(
                        "│{:<width$}│\n",
                        truncate_str(&hline, w - 2),
                        width = w - 2
                    ));
                }
            }
        }
        out.push_str(&format!("├{border}┤\n"));
        out.push_str(&format!(
            "│{:<width$}│\n",
            truncate_str(&format!(" {}", self.status), w - 2),
            width = w - 2
        ));
        out.push_str(&format!("└{border}┘\n"));
        out
    }

    pub fn run_interactive(&mut self, registry: &Registry) {
        let stdin = io::stdin();
        let mut stdout = io::stdout();
        loop {
            print!("\x1b[2J\x1b[H{}", self.render_snapshot(100));
            let _ = stdout.flush();
            let mut line = String::new();
            if stdin.lock().read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let cmd = line.trim();
            match cmd {
                "q" | "quit" | "exit" => break,
                "j" | "down" | "n" | "" => {
                    if self.selected + 1 < self.filtered_indices.len() {
                        self.selected += 1;
                    }
                }
                "k" | "up" | "p" => {
                    self.selected = self.selected.saturating_sub(1);
                }
                "g" | "top" => self.selected = 0,
                "G" | "bottom" => {
                    self.selected = self.filtered_indices.len().saturating_sub(1);
                }
                "tab" | "t" => {
                    self.active_pane = self.active_pane.next();
                }
                "clear" => {
                    self.apply_filter("", Some(registry));
                }
                other if other.starts_with('/') => {
                    let expr = other.trim_start_matches('/').trim();
                    self.apply_filter(expr, Some(registry));
                }
                other => {
                    if let Ok(num) = other.parse::<usize>() {
                        if num >= 1 && num <= self.filtered_indices.len() {
                            self.selected = num - 1;
                        }
                    }
                }
            }
        }
    }
}

fn truncate_str(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        s.to_string()
    } else {
        s.chars().take(max_chars.saturating_sub(1)).collect::<String>() + "…"
    }
}
