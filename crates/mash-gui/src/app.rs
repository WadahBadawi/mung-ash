use crate::{AnalyzerWorkspace, FilterBarStatus};
use eframe::egui::{
    self, Color32, FontId, RichText, ScrollArea, Sense, Stroke, TextEdit, TopBottomPanel, Ui,
};
use egui_extras::{Column, TableBuilder};
use mash_capture::{capture_frames, list_capture_interfaces, BpfFilter, CaptureOptions};
use mash_cli::{
    apply_capture_edits, export_ek_lines, export_pdml, export_psml, EditOptions,
};
use mash_core::{Frame, InterfaceInfo, LinkType, NodeId, Timestamp};
use mash_mcp::{JsonRpcRequest, McpServer};
use mash_pcapfile::text2pcap::{parse_hexdump_packets, Text2PcapOptions};
use mash_pcapfile::{
    merge_captures, read_capture_file, write_capture_file, CaptureFile, CaptureFormat, MergeMode,
};
use mash_reassembly::{ReassembledStream, StreamDisplayFormat};
use mash_stats::{
    build_protocol_hierarchy, compute_conversations, compute_endpoints, compute_io_graph,
    compute_packet_length_distribution, summarize_expert_info, CaptureProperties,
    ConversationLayer,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Active tool modal / dock window inside the unified 3-pane desktop GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveToolTab {
    Capture,
    FileInfo,
    EditAnonymize,
    MergeFiles,
    Text2Pcap,
    FollowStream,
    Statistics,
    AiAnalyst,
    McpInspector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatsSubTab {
    ProtocolHierarchy,
    Conversations,
    Endpoints,
    IoGraph,
    PacketLengths,
    ExpertInfo,
}

/// Unified MUNG-ASH Desktop GUI Application (`eframe::App`) integrating all 8 tools.
pub struct MashGuiApp {
    pub ws: AnalyzerWorkspace,
    pub dark_mode: bool,
    pub status_line: String,

    // Active tool window
    pub open_tool_window: bool,
    pub active_tool: ActiveToolTab,

    // 1. Live Capture (`mash-cap`) state
    pub interfaces: Vec<InterfaceInfo>,
    pub selected_iface_idx: usize,
    pub capture_bpf: String,
    pub capture_count: u64,
    pub capture_snaplen: u32,
    pub capture_promisc: bool,

    // 2. Edit & Anonymizer (`mash-edit`) state
    pub edit_dedup_enabled: bool,
    pub edit_dedup_window: usize,
    pub edit_snaplen_enabled: bool,
    pub edit_snaplen: u32,
    pub edit_timeshift_secs: f64,
    pub edit_anon_enabled: bool,
    pub edit_anon_key: String,
    pub edit_scrub_payload: bool,

    // 3. Merge (`mash-merge`) state
    pub merge_files: Vec<String>,
    pub merge_chronological: bool,

    // 4. Text2Pcap (`mash-text2pcap`) state
    pub text2pcap_input: String,
    pub text2pcap_src_port: u16,
    pub text2pcap_dst_port: u16,
    pub text2pcap_use_udp: bool,

    // 5. Follow Stream & Statistics (`mash-stats`) state
    pub stats_tab: StatsSubTab,
    pub conv_layer: ConversationLayer,
    pub follow_stream_id: u32,
    pub follow_is_udp: bool,
    pub follow_format: StreamDisplayFormat,
    pub tcp_streams: BTreeMap<u32, ReassembledStream>,
    pub udp_streams: BTreeMap<u32, ReassembledStream>,

    // 6. AI Analyst (`mash-ai`) & MCP (`mash-mcp`) state
    pub ai_nl_query: String,
    pub ai_output_log: String,
    pub mcp_method_idx: usize,
    pub mcp_params_json: String,
    pub mcp_response_json: String,
}

impl MashGuiApp {
    pub fn new(mut ws: AnalyzerWorkspace) -> Self {
        if ws.frames.is_empty() {
            ws.load_capture(generate_sample_showcase_capture());
        }
        let interfaces = list_capture_interfaces();
        let mut app = Self {
            ws,
            dark_mode: true,
            status_line: "Ready — Loaded multi-protocol showcase capture (14 packets). Click any packet, field, or byte to inspect.".to_string(),
            open_tool_window: false,
            active_tool: ActiveToolTab::Statistics,
            interfaces,
            selected_iface_idx: 0,
            capture_bpf: String::new(),
            capture_count: 25,
            capture_snaplen: 262_144,
            capture_promisc: true,
            edit_dedup_enabled: false,
            edit_dedup_window: 5,
            edit_snaplen_enabled: false,
            edit_snaplen: 128,
            edit_timeshift_secs: 0.0,
            edit_anon_enabled: true,
            edit_anon_key: "mung-ash-secret-key".to_string(),
            edit_scrub_payload: false,
            merge_files: Vec::new(),
            merge_chronological: true,
            text2pcap_input: "0000  47 45 54 20 2f 61 70 69 2f 76 31 20 48 54 54 50  GET /api/v1 HTTP\n0010  2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 6d 61 73 68  /1.1..Host: mash\n0020  2e 6c 6f 63 61 6c 0d 0a 0d 0a                    .local....\n".to_string(),
            text2pcap_src_port: 54321,
            text2pcap_dst_port: 80,
            text2pcap_use_udp: false,
            stats_tab: StatsSubTab::ProtocolHierarchy,
            conv_layer: ConversationLayer::Ipv4,
            follow_stream_id: 0,
            follow_is_udp: false,
            follow_format: StreamDisplayFormat::Ascii,
            tcp_streams: BTreeMap::new(),
            udp_streams: BTreeMap::new(),
            ai_nl_query: "http or dns".to_string(),
            ai_output_log: String::new(),
            mcp_method_idx: 0,
            mcp_params_json: "{}".to_string(),
            mcp_response_json: String::new(),
        };
        app.rebuild_streams();
        app
    }

    pub fn rebuild_streams(&mut self) {
        self.tcp_streams.clear();
        self.udp_streams.clear();
        for (frame, pkt) in self.ws.frames.iter().zip(self.ws.dissected.iter()) {
            let tcp_sid = pkt
                .tree
                .by_abbrev("tcp.stream")
                .next()
                .and_then(|n| n.value.as_u64())
                .map(|v| v as u32);
            let udp_sid = pkt
                .tree
                .by_abbrev("udp.stream")
                .next()
                .and_then(|n| n.value.as_u64())
                .map(|v| v as u32);

            if let Some(sid) = tcp_sid {
                let sport = pkt
                    .tree
                    .by_abbrev("tcp.srcport")
                    .next()
                    .and_then(|n| n.value.as_u64())
                    .unwrap_or(0) as u16;
                let dport = pkt
                    .tree
                    .by_abbrev("tcp.dstport")
                    .next()
                    .and_then(|n| n.value.as_u64())
                    .unwrap_or(0) as u16;
                let seq = pkt
                    .tree
                    .by_abbrev("tcp.seq")
                    .next()
                    .and_then(|n| n.value.as_u64())
                    .unwrap_or(0) as u32;
                let flags = pkt
                    .tree
                    .by_abbrev("tcp.flags")
                    .next()
                    .and_then(|n| n.value.as_u64())
                    .unwrap_or(0) as u16;
                let payload_start = pkt
                    .tree
                    .by_abbrev("tcp")
                    .next()
                    .map(|n| n.byte_range.end)
                    .unwrap_or(frame.data.len());
                let payload = frame.data.get(payload_start..).unwrap_or(&[]);
                self.tcp_streams
                    .entry(sid)
                    .or_insert_with(|| ReassembledStream::new(sid))
                    .push_tcp_segment(
                        frame.number,
                        frame.timestamp,
                        &pkt.summary.source,
                        sport,
                        &pkt.summary.destination,
                        dport,
                        seq,
                        (flags & 0x02) != 0,
                        payload,
                    );
            } else if let Some(sid) = udp_sid {
                let sport = pkt
                    .tree
                    .by_abbrev("udp.srcport")
                    .next()
                    .and_then(|n| n.value.as_u64())
                    .unwrap_or(0) as u16;
                let dport = pkt
                    .tree
                    .by_abbrev("udp.dstport")
                    .next()
                    .and_then(|n| n.value.as_u64())
                    .unwrap_or(0) as u16;
                let payload_start = pkt
                    .tree
                    .by_abbrev("udp")
                    .next()
                    .map(|n| n.byte_range.end)
                    .unwrap_or(frame.data.len());
                let payload = frame.data.get(payload_start..).unwrap_or(&[]);
                self.udp_streams
                    .entry(sid)
                    .or_insert_with(|| ReassembledStream::new(sid))
                    .push_udp_datagram(
                        frame.number,
                        frame.timestamp,
                        &pkt.summary.source,
                        sport,
                        &pkt.summary.destination,
                        dport,
                        payload,
                    );
            }
        }
    }

    fn open_tool(&mut self, tab: ActiveToolTab) {
        self.active_tool = tab;
        self.open_tool_window = true;
    }

    fn action_open_file(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Capture Files", &["pcapng", "pcap", "cap", "gz", "lz4"])
            .pick_file()
        {
            match self.ws.load_file(&path) {
                Ok(()) => {
                    self.rebuild_streams();
                    self.status_line = format!(
                        "Opened '{}' ({} packets)",
                        path.display(),
                        self.ws.frames.len()
                    );
                }
                Err(e) => {
                    self.status_line = format!("Failed to open '{}': {e}", path.display());
                }
            }
        }
    }

    fn action_save_file(&mut self, displayed_only: bool) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("PCAPNG", &["pcapng"])
            .add_filter("Classic PCAP", &["pcap"])
            .set_file_name("capture.pcapng")
            .save_file()
        {
            let fmt = if path.extension().and_then(|s| s.to_str()) == Some("pcap") {
                CaptureFormat::PcapMicros
            } else {
                CaptureFormat::PcapNg
            };
            let mut cap = CaptureFile::new(fmt);
            if displayed_only {
                for &idx in &self.ws.filtered_indices {
                    if let Some(f) = self.ws.frames.get(idx) {
                        cap.frames.push(f.clone());
                    }
                }
            } else {
                cap.frames = self.ws.frames.clone();
            }
            match write_capture_file(&path, &cap) {
                Ok(()) => {
                    self.status_line = format!(
                        "Saved {} packets to '{}'",
                        cap.frames.len(),
                        path.display()
                    );
                }
                Err(e) => {
                    self.status_line = format!("Save failed: {e}");
                }
            }
        }
    }

    fn action_export_text(&mut self, kind: &str) {
        let ext = match kind {
            "pdml" | "psml" => "xml",
            "json" | "ek" => "json",
            _ => "txt",
        };
        if let Some(path) = rfd::FileDialog::new()
            .set_file_name(format!("export.{ext}"))
            .save_file()
        {
            let displayed: Vec<_> = self
                .ws
                .filtered_indices
                .iter()
                .filter_map(|&i| self.ws.dissected.get(i).cloned())
                .collect();
            let content = match kind {
                "pdml" => export_pdml(&displayed),
                "psml" => export_psml(&displayed),
                "ek" => displayed.iter().map(export_ek_lines).collect::<String>(),
                _ => serde_json::to_string_pretty(&displayed).unwrap_or_default(),
            };
            match fs::write(&path, content) {
                Ok(()) => {
                    self.status_line =
                        format!("Exported {} packets as {} to '{}'", displayed.len(), kind.to_uppercase(), path.display());
                }
                Err(e) => self.status_line = format!("Export failed: {e}"),
            }
        }
    }

    fn render_menu_bar(&mut self, ui: &mut Ui) {
        egui::menu::bar(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("📂 Open Capture File...").clicked() {
                    ui.close_menu();
                    self.action_open_file();
                }
                if ui.button("⚡ Load Multi-Protocol Showcase Capture").clicked() {
                    ui.close_menu();
                    self.ws.load_capture(generate_sample_showcase_capture());
                    self.rebuild_streams();
                    self.status_line = "Loaded 14-packet multi-protocol showcase capture.".to_string();
                }
                ui.separator();
                if ui.button("💾 Save All Packets As...").clicked() {
                    ui.close_menu();
                    self.action_save_file(false);
                }
                if ui.button("💾 Save Displayed Packets As...").clicked() {
                    ui.close_menu();
                    self.action_save_file(true);
                }
                ui.separator();
                if ui.button("🔀 Merge Capture Files (mash-merge)...").clicked() {
                    ui.close_menu();
                    self.open_tool(ActiveToolTab::MergeFiles);
                }
                if ui.button("📝 Import Hex Dump (mash-text2pcap)...").clicked() {
                    ui.close_menu();
                    self.open_tool(ActiveToolTab::Text2Pcap);
                }
                ui.separator();
                ui.menu_button("📤 Export Packet Dissections", |ui| {
                    if ui.button("As JSON...").clicked() {
                        ui.close_menu();
                        self.action_export_text("json");
                    }
                    if ui.button("As XML PDML (Packet Details)...").clicked() {
                        ui.close_menu();
                        self.action_export_text("pdml");
                    }
                    if ui.button("As XML PSML (Packet Summaries)...").clicked() {
                        ui.close_menu();
                        self.action_export_text("psml");
                    }
                    if ui.button("As Elastic Bulk NDJSON (EK)...").clicked() {
                        ui.close_menu();
                        self.action_export_text("ek");
                    }
                });
            });

            ui.menu_button("Edit", |ui| {
                if ui.button("🔖 Mark / Unmark Selected Packet (Ctrl+M)").clicked() {
                    ui.close_menu();
                    if let Some(fno) = self.ws.selected_frame {
                        self.ws.toggle_mark_frame(fno);
                    }
                }
                if ui.button("🚫 Ignore / Unignore Selected Packet (Ctrl+D)").clicked() {
                    ui.close_menu();
                    if let Some(fno) = self.ws.selected_frame {
                        self.ws.toggle_ignore_frame(fno);
                    }
                }
                if ui.button("⏱ Set / Unset Time Reference (Ctrl+T)").clicked() {
                    ui.close_menu();
                    if let Some(fno) = self.ws.selected_frame {
                        self.ws.toggle_time_reference(fno);
                    }
                }
                ui.separator();
                if ui.button("✂ Packet Editor & Anonymizer (mash-edit)...").clicked() {
                    ui.close_menu();
                    self.open_tool(ActiveToolTab::EditAnonymize);
                }
            });

            ui.menu_button("View", |ui| {
                if ui
                    .button(if self.dark_mode {
                        "☀ Switch to Light Theme"
                    } else {
                        "🌙 Switch to Dark Theme"
                    })
                    .clicked()
                {
                    ui.close_menu();
                    self.dark_mode = !self.dark_mode;
                }
                if ui.button("Expand All Protocol Nodes").clicked() {
                    ui.close_menu();
                    if let Some(fno) = self.ws.selected_frame {
                        if let Some(pkt) = self.ws.dissected.get((fno - 1) as usize) {
                            for n in &pkt.tree.nodes {
                                self.ws.expanded_nodes.insert(n.id);
                            }
                        }
                    }
                }
                if ui.button("Collapse All Protocol Nodes").clicked() {
                    ui.close_menu();
                    self.ws.expanded_nodes.clear();
                }
            });

            ui.menu_button("Capture", |ui| {
                if ui.button("▶ Capture Options & Start (mash-cap)...").clicked() {
                    ui.close_menu();
                    self.open_tool(ActiveToolTab::Capture);
                }
                if ui.button("⚡ Quick Capture 20 Packets on Primary Interface").clicked() {
                    ui.close_menu();
                    self.run_live_capture();
                }
            });

            ui.menu_button("Analyze", |ui| {
                if ui.button("🌊 Follow TCP / UDP Stream...").clicked() {
                    ui.close_menu();
                    self.open_tool(ActiveToolTab::FollowStream);
                }
                if let Some(expr) = self.ws.filter_from_selected_node() {
                    if ui.button(format!("🔍 Apply Selected Field as Filter ({expr})")).clicked() {
                        ui.close_menu();
                        self.ws.set_display_filter(&expr);
                    }
                }
                ui.separator();
                ui.label("Quick Display Filters:");
                for (label, expr) in [
                    ("HTTP Traffic", "http"),
                    ("DNS Queries & Responses", "dns"),
                    ("TLS Handshakes & Records", "tls"),
                    ("Routing (BGP & OSPF)", "bgp || ospf"),
                    ("Industrial / IoT (MQTT & Modbus)", "mqtt || modbus"),
                    ("Enterprise (SMB2 & gRPC)", "smb2 || grpc"),
                    ("TCP SYN / FIN", "tcp.flags.syn == true || tcp.flags.fin == true"),
                ] {
                    if ui.button(format!("{label} ({expr})")).clicked() {
                        ui.close_menu();
                        self.ws.set_display_filter(expr);
                    }
                }
            });

            ui.menu_button("Statistics", |ui| {
                if ui.button("🔍 Capture File Properties (mash-info)...").clicked() {
                    ui.close_menu();
                    self.open_tool(ActiveToolTab::FileInfo);
                }
                ui.separator();
                for (label, sub) in [
                    ("📊 Protocol Hierarchy (io,phs)", StatsSubTab::ProtocolHierarchy),
                    ("🖧 Conversations (conv,*)", StatsSubTab::Conversations),
                    ("🖥 Endpoints (endpoints,*)", StatsSubTab::Endpoints),
                    ("📈 I/O Throughput Graph (io,stat)", StatsSubTab::IoGraph),
                    ("📏 Packet Lengths Distribution (plen)", StatsSubTab::PacketLengths),
                    ("⚠ Expert Information (expert)", StatsSubTab::ExpertInfo),
                ] {
                    if ui.button(label).clicked() {
                        ui.close_menu();
                        self.stats_tab = sub;
                        self.open_tool(ActiveToolTab::Statistics);
                    }
                }
            });

            ui.menu_button("AI & MCP", |ui| {
                if ui.button("🤖 AI Security Analyst & NL Filter (mash-ai)...").clicked() {
                    ui.close_menu();
                    self.open_tool(ActiveToolTab::AiAnalyst);
                }
                if ui.button("🔌 MCP JSON-RPC 2.0 Tool Console (mash-mcp)...").clicked() {
                    ui.close_menu();
                    self.open_tool(ActiveToolTab::McpInspector);
                }
            });
        });
    }

    fn render_toolbar(&mut self, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            let cap_btn = egui::Button::new(
                RichText::new("▶ Capture (mash-cap)")
                    .strong()
                    .color(Color32::from_rgb(220, 255, 220)),
            )
            .fill(Color32::from_rgb(25, 110, 55));
            if ui
                .add(cap_btn)
                .on_hover_text("Open Live Capture & BPF Filter dialog")
                .clicked()
            {
                self.open_tool(ActiveToolTab::Capture);
            }

            if ui
                .button("⚡ Demo Capture")
                .on_hover_text("Load 14-packet multi-protocol showcase capture (ARP, DNS, TCP, HTTP, TLS, BGP, MQTT, Modbus, ICMP)")
                .clicked()
            {
                self.ws.load_capture(generate_sample_showcase_capture());
                self.rebuild_streams();
                self.status_line = "Loaded 14-packet multi-protocol showcase capture.".to_string();
            }

            if ui.button("📂 Open").on_hover_text("Open .pcap / .pcapng file").clicked() {
                self.action_open_file();
            }
            if ui.button("💾 Save").on_hover_text("Save capture file").clicked() {
                self.action_save_file(false);
            }

            ui.separator();

            if ui
                .button("🔍 File Info (mash-info)")
                .on_hover_text("Inspect SHA-256, timing, and capture metadata")
                .clicked()
            {
                self.open_tool(ActiveToolTab::FileInfo);
            }
            if ui
                .button("✂ Edit / Anonymize (mash-edit)")
                .on_hover_text("Deduplicate, slice, time-shift, or HMAC-anonymize IPs & MACs")
                .clicked()
            {
                self.open_tool(ActiveToolTab::EditAnonymize);
            }
            if ui
                .button("🔀 Merge (mash-merge)")
                .on_hover_text("Merge multiple capture files chronologically")
                .clicked()
            {
                self.open_tool(ActiveToolTab::MergeFiles);
            }
            if ui
                .button("📝 Hex2Pcap (mash-text2pcap)")
                .on_hover_text("Convert ASCII hex dumps into dissected packets")
                .clicked()
            {
                self.open_tool(ActiveToolTab::Text2Pcap);
            }

            ui.separator();

            if ui
                .button("🌊 Follow Stream")
                .on_hover_text("Reassemble and view TCP/UDP payload streams")
                .clicked()
            {
                self.open_tool(ActiveToolTab::FollowStream);
            }
            if ui
                .button("📊 Statistics")
                .on_hover_text("Protocol Hierarchy, Conversations, Endpoints, I/O Graph, Expert Info")
                .clicked()
            {
                self.open_tool(ActiveToolTab::Statistics);
            }
            if ui
                .button("🤖 AI Analyst (mash-ai)")
                .on_hover_text("AI Packet Explainer, Anomaly Detector & NL Filter")
                .clicked()
            {
                self.open_tool(ActiveToolTab::AiAnalyst);
            }
            if ui
                .button("🔌 MCP Server (mash-mcp)")
                .on_hover_text("Test Model Context Protocol JSON-RPC 2.0 tools")
                .clicked()
            {
                self.open_tool(ActiveToolTab::McpInspector);
            }
        });
    }

    fn render_filter_bar(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Filter:").strong());

            let bg_color = match &self.ws.filter_status {
                FilterBarStatus::Empty => {
                    if self.dark_mode {
                        Color32::from_rgb(35, 38, 45)
                    } else {
                        Color32::from_rgb(245, 245, 250)
                    }
                }
                FilterBarStatus::Valid => {
                    if self.dark_mode {
                        Color32::from_rgb(22, 72, 38)
                    } else {
                        Color32::from_rgb(205, 245, 210)
                    }
                }
                FilterBarStatus::Invalid(_) => {
                    if self.dark_mode {
                        Color32::from_rgb(95, 25, 28)
                    } else {
                        Color32::from_rgb(255, 210, 210)
                    }
                }
            };

            let mut expr = self.ws.filter_input.clone();
            let edit = TextEdit::singleline(&mut expr)
                .hint_text("Apply a display filter... e.g. http || dns || tcp.port == 443 || bgp || mqtt")
                .background_color(bg_color)
                .desired_width(ui.available_width() - 280.0);
            let resp = ui.add(edit);
            if resp.changed() {
                self.ws.set_display_filter(&expr);
            }

            if ui.button("✖ Clear").clicked() {
                self.ws.set_display_filter("");
            }

            for preset in ["http", "dns", "tls", "tcp", "bgp", "mqtt", "modbus"] {
                if ui.small_button(preset).clicked() {
                    self.ws.set_display_filter(preset);
                }
            }
        });

        if let FilterBarStatus::Invalid(diag) = self.ws.filter_status.clone() {
            ui.horizontal(|ui| {
                ui.colored_label(
                    Color32::from_rgb(255, 110, 110),
                    format!("⚠ Filter Syntax Error: {}", diag.message),
                );
                if let Some(sug) = diag.suggestions.first() {
                    if ui.small_button(format!("Did you mean '{sug}'?")).clicked() {
                        self.ws.set_display_filter(sug);
                    }
                }
            });
        }
    }

    fn render_packet_list_pane(&mut self, ui: &mut Ui) {
        let row_height = 20.0;
        let total_rows = self.ws.filtered_indices.len();
        let mut clicked_frame: Option<u64> = None;
        let mut context_action: Option<(u64, &'static str)> = None;

        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(55.0).at_least(40.0)) // No.
            .column(Column::initial(95.0).at_least(70.0)) // Time
            .column(Column::initial(145.0).at_least(90.0)) // Source
            .column(Column::initial(145.0).at_least(90.0)) // Destination
            .column(Column::initial(80.0).at_least(55.0)) // Protocol
            .column(Column::initial(65.0).at_least(50.0)) // Length
            .column(Column::remainder().at_least(200.0)) // Info
            .header(22.0, |mut header| {
                for title in [
                    "No.",
                    "Time (s)",
                    "Source",
                    "Destination",
                    "Protocol",
                    "Length",
                    "Info",
                ] {
                    header.col(|ui| {
                        ui.label(RichText::new(title).strong());
                    });
                }
            })
            .body(|body| {
                body.rows(row_height, total_rows, |mut row| {
                    let row_idx = row.index();
                    let Some(&pkt_idx) = self.ws.filtered_indices.get(row_idx) else {
                        return;
                    };
                    let Some(pkt) = self.ws.dissected.get(pkt_idx) else {
                        return;
                    };
                    let fno = pkt.summary.number;
                    let is_selected = self.ws.selected_frame == Some(fno);
                    row.set_selected(is_selected);

                    let (fg_color, badge_bg) = if is_selected {
                        (
                            Color32::from_rgb(255, 255, 255),
                            Color32::from_rgb(20, 95, 190),
                        )
                    } else if let Some((fg, bg)) = self.ws.color_for_packet(pkt) {
                        (
                            Color32::from_rgb(fg.0, fg.1, fg.2),
                            Color32::from_rgb(bg.0, bg.1, bg.2),
                        )
                    } else {
                        let fg = if self.dark_mode {
                            Color32::from_rgb(220, 225, 235)
                        } else {
                            Color32::from_rgb(25, 30, 40)
                        };
                        (fg, Color32::TRANSPARENT)
                    };

                    let cols = [
                        format!("{fno}"),
                        format!("{:.6}", pkt.summary.rel_time_sec),
                        pkt.summary.source.clone(),
                        pkt.summary.destination.clone(),
                        pkt.summary.protocol.clone(),
                        format!("{}", pkt.summary.length),
                        pkt.summary.info.clone(),
                    ];

                    for (c_idx, text) in cols.iter().enumerate() {
                        row.col(|ui| {
                            let rt = if c_idx == 4 && badge_bg != Color32::TRANSPARENT {
                                RichText::new(format!(" {text} "))
                                    .monospace()
                                    .color(fg_color)
                                    .background_color(badge_bg)
                            } else {
                                RichText::new(text).monospace().color(fg_color)
                            };
                            let resp = ui.add(egui::Label::new(rt).sense(Sense::click()));
                            if resp.clicked() {
                                clicked_frame = Some(fno);
                            }
                            resp.context_menu(|ui| {
                                if ui.button("🔖 Mark / Unmark Packet").clicked() {
                                    context_action = Some((fno, "mark"));
                                    ui.close_menu();
                                }
                                if ui.button("⏱ Set / Unset Time Reference").clicked() {
                                    context_action = Some((fno, "timeref"));
                                    ui.close_menu();
                                }
                                if ui.button("🌊 Follow Stream").clicked() {
                                    context_action = Some((fno, "follow"));
                                    ui.close_menu();
                                }
                                if ui.button("🤖 Explain Packet with AI").clicked() {
                                    context_action = Some((fno, "ai"));
                                    ui.close_menu();
                                }
                            });
                        });
                    }
                });
            });

        if let Some(fno) = clicked_frame {
            self.ws.select_frame(fno);
        }
        if let Some((fno, act)) = context_action {
            self.ws.select_frame(fno);
            match act {
                "mark" => self.ws.toggle_mark_frame(fno),
                "timeref" => self.ws.toggle_time_reference(fno),
                "follow" => self.open_tool(ActiveToolTab::FollowStream),
                "ai" => {
                    if let Some(pkt) = self.ws.dissected.get((fno - 1) as usize) {
                        if let Ok(exp) = self.ws.ai.explain_packet(pkt) {
                            self.ai_output_log = exp;
                        }
                    }
                    self.open_tool(ActiveToolTab::AiAnalyst);
                }
                _ => {}
            }
        }
    }

    fn render_protocol_tree_pane(&mut self, ui: &mut Ui) {
        let Some(fno) = self.ws.selected_frame else {
            ui.label("Select a packet in the Packet List above to inspect its protocol tree.");
            return;
        };
        let Some(pkt) = self.ws.dissected.get((fno - 1) as usize).cloned() else {
            return;
        };

        ScrollArea::vertical()
            .id_salt("pane2_protocol_tree")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for &root_id in &pkt.tree.roots {
                    self.render_tree_node(ui, &pkt, root_id, 0);
                }
            });
    }

    fn render_tree_node(
        &mut self,
        ui: &mut Ui,
        pkt: &mash_core::DissectedPacket,
        node_id: NodeId,
        depth: usize,
    ) {
        let Some(node) = pkt.tree.node(node_id) else {
            return;
        };
        let has_children = !node.children.is_empty();
        let is_expanded = self.ws.expanded_nodes.contains(&node_id) || depth == 0 && self.ws.expanded_nodes.is_empty();
        let is_selected = self.ws.selected_node == Some(node_id);

        ui.horizontal(|ui| {
            ui.add_space((depth as f32) * 18.0);
            if has_children {
                let icon = if is_expanded { "▼" } else { "▶" };
                if ui.small_button(icon).clicked() {
                    if self.ws.expanded_nodes.contains(&node_id) {
                        self.ws.expanded_nodes.remove(&node_id);
                    } else {
                        self.ws.expanded_nodes.insert(node_id);
                    }
                }
            } else {
                ui.add_space(22.0);
            }

            let label_color = if is_selected {
                Color32::from_rgb(255, 230, 120)
            } else if depth == 0 {
                if self.dark_mode {
                    Color32::from_rgb(155, 210, 255)
                } else {
                    Color32::from_rgb(15, 70, 145)
                }
            } else if self.dark_mode {
                Color32::from_rgb(220, 225, 230)
            } else {
                Color32::from_rgb(30, 35, 45)
            };

            let bg = if is_selected {
                Color32::from_rgb(35, 75, 135)
            } else {
                Color32::TRANSPARENT
            };

            let text = RichText::new(&node.label)
                .monospace()
                .color(label_color)
                .background_color(bg);
            let resp = ui.add(egui::Label::new(text).sense(Sense::click()));
            if resp.clicked() {
                self.ws.select_field_node(node_id);
                if has_children {
                    self.ws.expanded_nodes.insert(node_id);
                }
                self.status_line = format!(
                    "{} ({}) — Bytes {}..{} ({} bytes)",
                    node.name,
                    node.abbrev,
                    node.byte_range.start,
                    node.byte_range.end,
                    node.byte_range.len()
                );
            }
            resp.context_menu(|ui| {
                if ui.button("🔍 Apply as Filter").clicked() {
                    self.ws.select_field_node(node_id);
                    if let Some(f) = self.ws.filter_from_selected_node() {
                        self.ws.set_display_filter(&f);
                    }
                    ui.close_menu();
                }
                if ui.button("📋 Copy Field Abbreviation").clicked() {
                    ui.ctx().copy_text(node.abbrev.clone());
                    ui.close_menu();
                }
                if ui.button("📋 Copy Field Label").clicked() {
                    ui.ctx().copy_text(node.label.clone());
                    ui.close_menu();
                }
            });

            if let Some(exp) = &node.expert {
                let badge_col = match exp.severity {
                    mash_core::ExpertSeverity::Error => Color32::from_rgb(200, 45, 45),
                    mash_core::ExpertSeverity::Warn => Color32::from_rgb(195, 130, 20),
                    _ => Color32::from_rgb(45, 115, 185),
                };
                ui.label(
                    RichText::new(format!(
                        " [{} / {}: {}] ",
                        exp.severity.as_str(),
                        exp.group.as_str(),
                        exp.summary
                    ))
                    .small()
                    .color(Color32::WHITE)
                    .background_color(badge_col),
                );
            }
        });

        if has_children && is_expanded {
            for &cid in &node.children {
                self.render_tree_node(ui, pkt, cid, depth + 1);
            }
        }
    }

    fn render_hex_dump_pane(&mut self, ui: &mut Ui) {
        let Some(fno) = self.ws.selected_frame else {
            return;
        };
        let Some(frame) = self.ws.frames.get((fno - 1) as usize).cloned() else {
            return;
        };

        // Data source tab bar (Frame Bytes + Secondary DataSources)
        ui.horizontal(|ui| {
            let tab0_selected = self.ws.active_source_tab == 0;
            if ui
                .selectable_label(
                    tab0_selected,
                    format!("Frame ({} bytes)", frame.data.len()),
                )
                .clicked()
            {
                self.ws.active_source_tab = 0;
            }
            for (idx, ds) in frame.extra_sources.iter().enumerate() {
                let tab_id = (idx + 1) as u8;
                if ui
                    .selectable_label(
                        self.ws.active_source_tab == tab_id,
                        format!("{} ({} bytes)", ds.name, ds.data.len()),
                    )
                    .clicked()
                {
                    self.ws.active_source_tab = tab_id;
                }
            }
        });
        ui.separator();

        let Some(bytes) = frame.source_bytes(self.ws.active_source_tab).map(|b| b.to_vec()) else {
            return;
        };
        let hl = self.ws.highlighted_bytes;
        let active_src = self.ws.active_source_tab;
        let mut clicked_offset: Option<usize> = None;

        ScrollArea::vertical()
            .id_salt("pane3_hexdump")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.style_mut().spacing.item_spacing.x = 4.0;
                for (row_idx, chunk) in bytes.chunks(16).enumerate() {
                    let row_base = row_idx * 16;
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("{row_base:04x}  "))
                                .monospace()
                                .color(Color32::from_rgb(130, 145, 165)),
                        );

                        // 16 hex bytes
                        for col in 0..16 {
                            if col == 8 {
                                ui.add_space(6.0);
                            }
                            if let Some(&b) = chunk.get(col) {
                                let abs_off = row_base + col;
                                let is_hi = hl.is_some_and(|r| {
                                    r.source_idx == active_src
                                        && abs_off >= r.start
                                        && abs_off < r.end
                                });
                                let mut rt = RichText::new(format!("{b:02x}")).monospace();
                                if is_hi {
                                    rt = rt
                                        .color(Color32::from_rgb(255, 245, 150))
                                        .background_color(Color32::from_rgb(25, 95, 195))
                                        .strong();
                                }
                                if ui.add(egui::Label::new(rt).sense(Sense::click())).clicked() {
                                    clicked_offset = Some(abs_off);
                                }
                            } else {
                                ui.label(RichText::new("  ").monospace());
                            }
                        }

                        ui.add_space(14.0);

                        // 16 ASCII characters
                        for (col, &b) in chunk.iter().enumerate() {
                            let abs_off = row_base + col;
                            let is_hi = hl.is_some_and(|r| {
                                r.source_idx == active_src && abs_off >= r.start && abs_off < r.end
                            });
                            let ch = if (0x20..=0x7e).contains(&b) {
                                b as char
                            } else {
                                '.'
                            };
                            let mut rt = RichText::new(ch.to_string()).monospace();
                            if is_hi {
                                rt = rt
                                    .color(Color32::from_rgb(255, 245, 150))
                                    .background_color(Color32::from_rgb(25, 95, 195))
                                    .strong();
                            }
                            if ui.add(egui::Label::new(rt).sense(Sense::click())).clicked() {
                                clicked_offset = Some(abs_off);
                            }
                        }
                    });
                }
            });

        if let Some(off) = clicked_offset {
            if let Some(nid) = self.ws.select_byte_offset(active_src, off) {
                if let Some(pkt) = self.ws.dissected.get((fno - 1) as usize) {
                    if let Some(node) = pkt.tree.node(nid) {
                        self.status_line = format!(
                            "Selected byte 0x{off:04x} -> {} ({}) [Bytes {}..{}]",
                            node.name, node.abbrev, node.byte_range.start, node.byte_range.end
                        );
                    }
                }
            }
        }
    }

    fn run_live_capture(&mut self) {
        let iface_name = self
            .interfaces
            .get(self.selected_iface_idx)
            .map(|i| i.name.clone())
            .unwrap_or_else(|| "eth0".to_string());
        let opts = CaptureOptions {
            interfaces: vec![iface_name.clone()],
            bpf_filter: if self.capture_bpf.trim().is_empty() {
                None
            } else {
                Some(self.capture_bpf.trim().to_string())
            },
            promiscuous: self.capture_promisc,
            snap_len: self.capture_snaplen,
            max_packets: Some(self.capture_count.max(1)),
            ..CaptureOptions::default()
        };
        match capture_frames(&opts) {
            Ok(frames) => {
                let count = frames.len();
                let mut cap = CaptureFile::new(CaptureFormat::PcapNg);
                cap.frames = frames;
                self.ws.load_capture(cap);
                self.rebuild_streams();
                self.status_line = format!(
                    "Captured {count} packets from interface '{iface_name}'"
                );
            }
            Err(e) => {
                self.status_line = format!("Capture error: {e}");
            }
        }
    }

    fn render_tool_window(&mut self, ctx: &egui::Context) {
        if !self.open_tool_window {
            return;
        }
        let mut is_open = self.open_tool_window;
        egui::Window::new("🛠 MUNG-ASH All-in-One Tool Suite")
            .open(&mut is_open)
            .resizable(true)
            .default_width(780.0)
            .default_height(520.0)
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    for (tab, label) in [
                        (ActiveToolTab::Capture, "▶ Capture (mash-cap)"),
                        (ActiveToolTab::FileInfo, "🔍 File Info (mash-info)"),
                        (ActiveToolTab::EditAnonymize, "✂ Edit & Scrub (mash-edit)"),
                        (ActiveToolTab::MergeFiles, "🔀 Merge (mash-merge)"),
                        (ActiveToolTab::Text2Pcap, "📝 Hex2Pcap (mash-text2pcap)"),
                        (ActiveToolTab::FollowStream, "🌊 Follow Stream"),
                        (ActiveToolTab::Statistics, "📊 Statistics"),
                        (ActiveToolTab::AiAnalyst, "🤖 AI Analyst (mash-ai)"),
                        (ActiveToolTab::McpInspector, "🔌 MCP Console (mash-mcp)"),
                    ] {
                        if ui.selectable_label(self.active_tool == tab, label).clicked() {
                            self.active_tool = tab;
                        }
                    }
                });
                ui.separator();

                match self.active_tool {
                    ActiveToolTab::Capture => self.ui_tool_capture(ui),
                    ActiveToolTab::FileInfo => self.ui_tool_file_info(ui),
                    ActiveToolTab::EditAnonymize => self.ui_tool_edit_anonymize(ui),
                    ActiveToolTab::MergeFiles => self.ui_tool_merge(ui),
                    ActiveToolTab::Text2Pcap => self.ui_tool_text2pcap(ui),
                    ActiveToolTab::FollowStream => self.ui_tool_follow_stream(ui),
                    ActiveToolTab::Statistics => self.ui_tool_statistics(ui),
                    ActiveToolTab::AiAnalyst => self.ui_tool_ai_analyst(ui),
                    ActiveToolTab::McpInspector => self.ui_tool_mcp_inspector(ui),
                }
            });
        self.open_tool_window = is_open;
    }

    fn ui_tool_capture(&mut self, ui: &mut Ui) {
        ui.heading("Live Capture & Traffic Generator (mash-cap)");
        ui.label("Select a host network interface:");
        ScrollArea::vertical().max_height(130.0).show(ui, |ui| {
            for (idx, iface) in self.interfaces.iter().enumerate() {
                let desc = iface.description.as_deref().unwrap_or("Adapter");
                let addrs = if iface.addresses.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", iface.addresses.join(", "))
                };
                let label = format!("{}. {} — {}{}", idx + 1, iface.name, desc, addrs);
                if ui
                    .selectable_label(self.selected_iface_idx == idx, label)
                    .clicked()
                {
                    self.selected_iface_idx = idx;
                }
            }
        });

        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Capture BPF Filter (-f):");
            ui.text_edit_singleline(&mut self.capture_bpf);
            let bpf_ok = BpfFilter::compile(&self.capture_bpf).is_ok();
            ui.colored_label(
                if bpf_ok {
                    Color32::from_rgb(90, 230, 120)
                } else {
                    Color32::from_rgb(255, 100, 100)
                },
                if bpf_ok { "✓ Valid BPF" } else { "✖ Invalid BPF" },
            );
        });
        ui.horizontal(|ui| {
            ui.label("Packet Count (-c):");
            ui.add(egui::DragValue::new(&mut self.capture_count).range(1..=10_000));
            ui.label("SnapLen (-s):");
            ui.add(egui::DragValue::new(&mut self.capture_snaplen).range(64..=262_144));
            ui.checkbox(&mut self.capture_promisc, "Promiscuous Mode");
        });
        ui.horizontal(|ui| {
            if ui.button("▶ Start Capture on Selected Interface").clicked() {
                self.run_live_capture();
            }
            if ui
                .button("⚡ Load Multi-Protocol Showcase Capture (14 Packets)")
                .clicked()
            {
                self.ws.load_capture(generate_sample_showcase_capture());
                self.rebuild_streams();
                self.status_line = "Loaded 14-packet multi-protocol showcase capture.".to_string();
            }
        });
    }

    fn ui_tool_file_info(&mut self, ui: &mut Ui) {
        ui.heading("Capture File Properties & Cryptographic Digests (mash-info)");
        let mut cap = CaptureFile::new(CaptureFormat::PcapNg);
        cap.frames = self.ws.frames.clone();
        let raw = mash_pcapfile::write_pcapng_bytes(&cap).ok();
        let props = CaptureProperties::from_capture(&cap, raw.as_deref());
        ScrollArea::vertical().show(ui, |ui| {
            ui.monospace(props.format_text());
        });
    }

    fn ui_tool_edit_anonymize(&mut self, ui: &mut Ui) {
        ui.heading("Packet Editor, Slicer, Deduplicator & HMAC Anonymizer (mash-edit)");
        ui.checkbox(
            &mut self.edit_dedup_enabled,
            "Remove Duplicate Packets (-d / -D)",
        );
        if self.edit_dedup_enabled {
            ui.horizontal(|ui| {
                ui.label("Deduplication Sliding Window:");
                ui.add(egui::DragValue::new(&mut self.edit_dedup_window).range(1..=1000));
            });
        }

        ui.checkbox(&mut self.edit_snaplen_enabled, "Truncate Packet SnapLen (-s)");
        if self.edit_snaplen_enabled {
            ui.horizontal(|ui| {
                ui.label("Max Bytes per Packet:");
                ui.add(egui::DragValue::new(&mut self.edit_snaplen).range(14..=65535));
            });
        }

        ui.horizontal(|ui| {
            ui.label("Shift Timestamps by Seconds (-t):");
            ui.add(egui::DragValue::new(&mut self.edit_timeshift_secs).speed(0.1));
        });

        ui.separator();
        ui.checkbox(
            &mut self.edit_anon_enabled,
            "🔒 Pseudonymize IPv4/IPv6 & Ethernet MAC Addresses (--anonymize)",
        );
        if self.edit_anon_enabled {
            ui.horizontal(|ui| {
                ui.label("HMAC Secret Key:");
                ui.text_edit_singleline(&mut self.edit_anon_key);
            });
            ui.checkbox(
                &mut self.edit_scrub_payload,
                "Zero out L4 TCP/UDP Payloads (--scrub-payload)",
            );
        }

        if ui
            .button("✨ Apply Edits & Anonymization to Active Workspace")
            .clicked()
        {
            let opts = EditOptions {
                snap_len: if self.edit_snaplen_enabled {
                    Some(self.edit_snaplen)
                } else {
                    None
                },
                time_shift_secs: if self.edit_timeshift_secs.abs() > 1e-9 {
                    Some(self.edit_timeshift_secs)
                } else {
                    None
                },
                deduplicate_window: if self.edit_dedup_enabled {
                    Some(self.edit_dedup_window)
                } else {
                    None
                },
                anonymize_key: if self.edit_anon_enabled {
                    Some(self.edit_anon_key.clone())
                } else {
                    None
                },
                scrub_payload: self.edit_scrub_payload,
                ..EditOptions::default()
            };
            let mut cap = CaptureFile::new(CaptureFormat::PcapNg);
            cap.frames = self.ws.frames.clone();
            apply_capture_edits(&mut cap, &opts);
            self.ws.load_capture(cap);
            self.rebuild_streams();
            self.status_line = format!(
                "Applied mash-edit transformations ({} packets remaining).",
                self.ws.frames.len()
            );
        }
    }

    fn ui_tool_merge(&mut self, ui: &mut Ui) {
        ui.heading("Multi-File Capture Merger (mash-merge)");
        ui.horizontal(|ui| {
            if ui.button("➕ Add Capture Files...").clicked() {
                if let Some(files) = rfd::FileDialog::new()
                    .add_filter("Capture Files", &["pcapng", "pcap", "cap", "gz", "lz4"])
                    .pick_files()
                {
                    for f in files {
                        self.merge_files.push(f.display().to_string());
                    }
                }
            }
            if ui.button("🗑 Clear List").clicked() {
                self.merge_files.clear();
            }
            ui.checkbox(
                &mut self.merge_chronological,
                "Chronological Sort (uncheck to Concatenate)",
            );
        });

        for (i, path) in self.merge_files.iter().enumerate() {
            ui.monospace(format!("{}. {}", i + 1, path));
        }

        if ui
            .button("🔀 Merge Selected Files into Current Workspace")
            .clicked()
        {
            let mut caps = Vec::new();
            let mut cur = CaptureFile::new(CaptureFormat::PcapNg);
            cur.frames = self.ws.frames.clone();
            caps.push(cur);
            for p in &self.merge_files {
                if let Ok(c) = read_capture_file(p) {
                    caps.push(c);
                }
            }
            let mode = if self.merge_chronological {
                MergeMode::Chronological
            } else {
                MergeMode::Concatenate
            };
            let merged = merge_captures(&caps, mode, CaptureFormat::PcapNg);
            let total = merged.frames.len();
            self.ws.load_capture(merged);
            self.rebuild_streams();
            self.status_line = format!("Merged captures into workspace ({total} total packets).");
        }
    }

    fn ui_tool_text2pcap(&mut self, ui: &mut Ui) {
        ui.heading("ASCII Hex Dump to Packet Converter (mash-text2pcap)");
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.text2pcap_use_udp, "Wrap in UDP (uncheck for TCP)");
            ui.label("Src Port:");
            ui.add(egui::DragValue::new(&mut self.text2pcap_src_port));
            ui.label("Dst Port:");
            ui.add(egui::DragValue::new(&mut self.text2pcap_dst_port));
        });
        ui.add(
            TextEdit::multiline(&mut self.text2pcap_input)
                .font(FontId::monospace(13.0))
                .desired_rows(8)
                .desired_width(f32::INFINITY),
        );
        ui.horizontal(|ui| {
            if ui.button("📥 Import Hex Dump as New Capture").clicked() {
                let opts = if self.text2pcap_use_udp {
                    Text2PcapOptions {
                        prepend_udp_ports: Some((self.text2pcap_src_port, self.text2pcap_dst_port)),
                        ..Text2PcapOptions::default()
                    }
                } else {
                    Text2PcapOptions {
                        prepend_tcp_ports: Some((self.text2pcap_src_port, self.text2pcap_dst_port)),
                        ..Text2PcapOptions::default()
                    }
                };
                let frames = parse_hexdump_packets(&self.text2pcap_input, &opts);
                let count = frames.len();
                let mut cap = CaptureFile::new(CaptureFormat::PcapNg);
                cap.frames = frames;
                self.ws.load_capture(cap);
                self.rebuild_streams();
                self.status_line = format!("Imported {count} packet(s) from hex dump.");
            }
            if ui.button("➕ Append Hex Dump Packet to Current Capture").clicked() {
                let opts = if self.text2pcap_use_udp {
                    Text2PcapOptions {
                        prepend_udp_ports: Some((self.text2pcap_src_port, self.text2pcap_dst_port)),
                        ..Text2PcapOptions::default()
                    }
                } else {
                    Text2PcapOptions {
                        prepend_tcp_ports: Some((self.text2pcap_src_port, self.text2pcap_dst_port)),
                        ..Text2PcapOptions::default()
                    }
                };
                let mut frames = parse_hexdump_packets(&self.text2pcap_input, &opts);
                let mut cap = CaptureFile::new(CaptureFormat::PcapNg);
                cap.frames = self.ws.frames.clone();
                for mut f in frames.drain(..) {
                    f.number = (cap.frames.len() + 1) as u64;
                    cap.frames.push(f);
                }
                self.ws.load_capture(cap);
                self.rebuild_streams();
            }
        });
    }

    fn ui_tool_follow_stream(&mut self, ui: &mut Ui) {
        ui.heading("Follow TCP / UDP Stream Reassembly");
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.follow_is_udp, "UDP Stream (uncheck for TCP)");
            ui.label("Stream Index:");
            ui.add(egui::DragValue::new(&mut self.follow_stream_id));
            for (fmt, name) in [
                (StreamDisplayFormat::Ascii, "ASCII"),
                (StreamDisplayFormat::HexDump, "Hex Dump"),
                (StreamDisplayFormat::RawHex, "Raw Hex"),
            ] {
                if ui.selectable_label(self.follow_format == fmt, name).clicked() {
                    self.follow_format = fmt;
                }
            }
            if ui.button("🔍 Filter This Stream in Packet List").clicked() {
                let f = if self.follow_is_udp {
                    format!("udp.stream == {}", self.follow_stream_id)
                } else {
                    format!("tcp.stream == {}", self.follow_stream_id)
                };
                self.ws.set_display_filter(&f);
            }
        });
        ui.separator();

        let stream_opt = if self.follow_is_udp {
            self.udp_streams.get(&self.follow_stream_id)
        } else {
            self.tcp_streams.get(&self.follow_stream_id)
        };
        ScrollArea::vertical().show(ui, |ui| {
            if let Some(st) = stream_opt {
                ui.monospace(st.format_stream(self.follow_format));
            } else {
                ui.label("No stream data found for the selected stream ID.");
            }
        });
    }

    fn ui_tool_statistics(&mut self, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            for (sub, name) in [
                (StatsSubTab::ProtocolHierarchy, "Protocol Hierarchy"),
                (StatsSubTab::Conversations, "Conversations"),
                (StatsSubTab::Endpoints, "Endpoints"),
                (StatsSubTab::IoGraph, "I/O Throughput"),
                (StatsSubTab::PacketLengths, "Packet Lengths"),
                (StatsSubTab::ExpertInfo, "Expert Info"),
            ] {
                if ui.selectable_label(self.stats_tab == sub, name).clicked() {
                    self.stats_tab = sub;
                }
            }
        });
        ui.separator();

        let displayed: Vec<_> = self
            .ws
            .filtered_indices
            .iter()
            .filter_map(|&i| self.ws.dissected.get(i).cloned())
            .collect();

        ScrollArea::vertical().show(ui, |ui| match self.stats_tab {
            StatsSubTab::ProtocolHierarchy => {
                let phs = build_protocol_hierarchy(&displayed);
                ui.monospace(phs.format_table());
            }
            StatsSubTab::Conversations => {
                ui.horizontal(|ui| {
                    for (lyr, name) in [
                        (ConversationLayer::Ethernet, "Ethernet"),
                        (ConversationLayer::Ipv4, "IPv4"),
                        (ConversationLayer::Ipv6, "IPv6"),
                        (ConversationLayer::Tcp, "TCP"),
                        (ConversationLayer::Udp, "UDP"),
                    ] {
                        if ui.selectable_label(self.conv_layer == lyr, name).clicked() {
                            self.conv_layer = lyr;
                        }
                    }
                });
                let rows = compute_conversations(&displayed, self.conv_layer);
                for r in rows {
                    ui.monospace(format!(
                        "{:<22} <-> {:<22} | {:>5} pkts | {:>9} bytes | {:.3}s",
                        r.addr_a,
                        r.addr_b,
                        r.total_packets,
                        r.total_bytes,
                        r.duration_sec()
                    ));
                }
            }
            StatsSubTab::Endpoints => {
                let rows = compute_endpoints(&displayed, self.conv_layer);
                for r in rows {
                    ui.monospace(format!(
                        "{:<24} | TX: {:>5} pkts ({:>8} B) | RX: {:>5} pkts ({:>8} B)",
                        r.address, r.tx_packets, r.tx_bytes, r.rx_packets, r.rx_bytes
                    ));
                }
            }
            StatsSubTab::IoGraph => {
                let buckets = compute_io_graph(&displayed, 1.0);
                for b in buckets {
                    let bars = "█".repeat((b.packets as usize).clamp(1, 40));
                    ui.monospace(format!(
                        "{:>6.1}s - {:>6.1}s | {:>5} pkts | {:>9} B | {:>10.1} bps  {bars}",
                        b.start_sec, b.end_sec, b.packets, b.bytes, b.bits_per_sec
                    ));
                }
            }
            StatsSubTab::PacketLengths => {
                let dist = compute_packet_length_distribution(&displayed);
                for b in dist {
                    ui.monospace(format!(
                        "{:<14} | {:>6} pkts ({:>6.2}%)",
                        b.label, b.count, b.percentage
                    ));
                }
            }
            StatsSubTab::ExpertInfo => {
                let items = summarize_expert_info(&displayed);
                if items.is_empty() {
                    ui.label("No expert warnings or anomalies detected in displayed packets.");
                }
                for item in items {
                    ui.monospace(format!(
                        "[{:<7} / {:<10}] {:<8} ({:>3}x) — {}",
                        item.severity.as_str(),
                        item.group.as_str(),
                        item.protocol,
                        item.count,
                        item.summary
                    ));
                }
            }
        });
    }

    fn ui_tool_ai_analyst(&mut self, ui: &mut Ui) {
        ui.heading("AI Packet Explainer, Anomaly Detector & NL Filter (mash-ai)");
        ui.horizontal(|ui| {
            ui.checkbox(
                &mut self.ws.ai.policy.local_only,
                "Strict Local-Only Mode (AIP-01)",
            );
            ui.checkbox(
                &mut self.ws.ai.policy.redact_sensitive,
                "Auto-Redact IPs / MACs / Hostnames",
            );
        });
        ui.horizontal(|ui| {
            ui.label("Natural Language Filter:");
            ui.text_edit_singleline(&mut self.ai_nl_query);
            if ui.button("✨ Compile & Apply Filter").clicked() {
                match self
                    .ws
                    .ai
                    .nl_to_display_filter(&self.ai_nl_query, &self.ws.engine.registry)
                {
                    Ok(cf) => {
                        self.ai_output_log =
                            format!("Compiled NL query '{}' -> {}", self.ai_nl_query, cf.source);
                        self.ws.set_display_filter(&cf.source);
                    }
                    Err(e) => {
                        self.ai_output_log = format!("NL filter error: {e}");
                    }
                }
            }
        });
        ui.horizontal(|ui| {
            if ui.button("🤖 Explain Currently Selected Packet").clicked() {
                if let Some(fno) = self.ws.selected_frame {
                    if let Some(pkt) = self.ws.dissected.get((fno - 1) as usize) {
                        if let Ok(text) = self.ws.ai.explain_packet(pkt) {
                            self.ai_output_log = text;
                        }
                    }
                }
            }
            if ui
                .button("📋 Generate Full Capture Security & Anomaly Summary")
                .clicked()
            {
                let mut cap = CaptureFile::new(CaptureFormat::PcapNg);
                cap.frames = self.ws.frames.clone();
                let props = CaptureProperties::from_capture(&cap, None);
                if let Ok(text) = self.ws.ai.summarize_capture(&props, &self.ws.dissected) {
                    self.ai_output_log = text;
                }
            }
        });
        ui.separator();
        ScrollArea::vertical().show(ui, |ui| {
            ui.monospace(&self.ai_output_log);
        });
    }

    fn ui_tool_mcp_inspector(&mut self, ui: &mut Ui) {
        ui.heading("Model Context Protocol (MCP) JSON-RPC 2.0 Console (mash-mcp)");
        let methods = [
            ("tools/list", "{}"),
            ("get_capture_overview", "{}"),
            ("list_packets", "{\"filter\": \"\", \"limit\": 10}"),
            ("get_packet_details", "{\"frame_number\": 8}"),
            ("get_stream", "{\"stream_id\": 0, \"protocol\": \"tcp\"}"),
            ("get_conversations", "{\"layer\": \"ip\"}"),
            ("get_expert_info", "{}"),
        ];
        ui.horizontal_wrapped(|ui| {
            for (idx, (m, sample_p)) in methods.iter().enumerate() {
                if ui.selectable_label(self.mcp_method_idx == idx, *m).clicked() {
                    self.mcp_method_idx = idx;
                    self.mcp_params_json = (*sample_p).to_string();
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label("Params JSON:");
            ui.text_edit_singleline(&mut self.mcp_params_json);
            if ui.button("▶ Execute MCP Request").clicked() {
                let mut srv = McpServer::new();
                let mut cap = CaptureFile::new(CaptureFormat::PcapNg);
                cap.frames = self.ws.frames.clone();
                srv.load_capture(cap);

                let method_name = methods[self.mcp_method_idx].0;
                let parsed_params: serde_json::Value =
                    serde_json::from_str(&self.mcp_params_json).unwrap_or_else(|_| json!({}));
                let req = if method_name == "tools/list" {
                    JsonRpcRequest {
                        jsonrpc: Some("2.0".to_string()),
                        id: Some(json!(1)),
                        method: "tools/list".to_string(),
                        params: json!({}),
                    }
                } else {
                    JsonRpcRequest {
                        jsonrpc: Some("2.0".to_string()),
                        id: Some(json!(1)),
                        method: "tools/call".to_string(),
                        params: json!({
                            "name": method_name,
                            "arguments": parsed_params
                        }),
                    }
                };
                let resp = srv.handle_request(req);
                self.mcp_response_json =
                    serde_json::to_string_pretty(&resp).unwrap_or_default();
            }
        });
        ui.separator();
        ScrollArea::vertical().show(ui, |ui| {
            ui.monospace(&self.mcp_response_json);
        });
    }
}

impl eframe::App for MashGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.dark_mode {
            ctx.set_visuals(egui::Visuals::dark());
        } else {
            ctx.set_visuals(egui::Visuals::light());
        }

        // Top Menu Bar + Toolbar + Display Filter Bar
        TopBottomPanel::top("mash_top_bars").show(ctx, |ui| {
            self.render_menu_bar(ui);
            ui.separator();
            self.render_toolbar(ui);
            ui.separator();
            self.render_filter_bar(ui);
        });

        // Bottom Status Bar
        TopBottomPanel::bottom("mash_status_bar")
            .exact_height(24.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(&self.status_line);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let total = self.ws.dissected.len();
                        let disp = self.ws.filtered_indices.len();
                        let pct = if total > 0 {
                            (disp as f64 / total as f64) * 100.0
                        } else {
                            0.0
                        };
                        let marked = self.ws.frames.iter().filter(|f| f.flags.marked).count();
                        ui.label(
                            RichText::new(format!(
                                "Packets: {total} | Displayed: {disp} ({pct:.1}%) | Marked: {marked} | Profile: {}",
                                self.ws.profile.name
                            ))
                            .strong(),
                        );
                    });
                });
            });

        // Pane 3 (Bottom Split): Synchronized Hex + ASCII Packet Bytes
        TopBottomPanel::bottom("pane3_packet_bytes")
            .resizable(true)
            .default_height(195.0)
            .min_height(100.0)
            .show(ctx, |ui| {
                ui.heading("Packet Bytes (Hex / ASCII — Click any byte to jump to field)");
                self.render_hex_dump_pane(ui);
            });

        // Pane 2 (Middle Split): Hierarchical Protocol Tree
        TopBottomPanel::bottom("pane2_protocol_tree")
            .resizable(true)
            .default_height(225.0)
            .min_height(110.0)
            .show(ctx, |ui| {
                ui.heading("Packet Details (Protocol Tree — Click any field to highlight bytes, Right-click to filter)");
                ui.separator();
                self.render_protocol_tree_pane(ui);
            });

        // Pane 1 (Top Central Split): Packet List Table
        egui::CentralPanel::default().show(ctx, |ui| {
            let _ = Stroke::NONE;
            self.render_packet_list_pane(ui);
        });

        // Floating All-in-One Tool Suite Window
        self.render_tool_window(ctx);
    }
}

/// Launch the native 3-pane desktop GUI window (`mash-gui`).
pub fn run_native_gui(ws: AnalyzerWorkspace) -> std::result::Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("MUNG-ASH Network Protocol Analyzer (All-in-One Suite)")
            .with_inner_size([1360.0, 860.0])
            .with_min_inner_size([900.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "MUNG-ASH Network Protocol Analyzer",
        options,
        Box::new(|_cc| Ok(Box::new(MashGuiApp::new(ws)))),
    )
    .map_err(|e| format!("GUI error: {e}"))
}

/// Generate a rich 14-packet multi-protocol showcase capture (ARP, DNS, TCP, HTTP, TLSv1.3, BGP, MQTT, Modbus/TCP, ICMP).
pub fn generate_sample_showcase_capture() -> CaptureFile {
    let mut cap = CaptureFile::new(CaptureFormat::PcapNg);
    let mac_c = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
    let mac_s = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
    let ip_c = [192, 168, 1, 10];
    let ip_gw = [192, 168, 1, 1];
    let ip_web = [93, 184, 216, 34];

    let push_eth = |cap: &mut CaptureFile, sec: u64, nanos: u32, et: u16, l3: &[u8]| {
        let mut d = Vec::with_capacity(14 + l3.len());
        d.extend_from_slice(&mac_s);
        d.extend_from_slice(&mac_c);
        d.extend_from_slice(&et.to_be_bytes());
        d.extend_from_slice(l3);
        let no = (cap.frames.len() + 1) as u64;
        cap.frames.push(Frame::new(
            no,
            Timestamp::from_secs_nanos(1_700_000_000 + sec, nanos),
            LinkType::Ethernet,
            d,
        ));
    };

    let build_ipv4 = |src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]| -> Vec<u8> {
        let total = (20 + l4.len()) as u16;
        let mut v = Vec::with_capacity(total as usize);
        v.extend_from_slice(&[0x45, 0x00]);
        v.extend_from_slice(&total.to_be_bytes());
        v.extend_from_slice(&[0x12, 0x34, 0x40, 0x00, 64, proto, 0x00, 0x00]);
        v.extend_from_slice(&src);
        v.extend_from_slice(&dst);
        v.extend_from_slice(l4);
        v
    };

    let build_udp = |sport: u16, dport: u16, payload: &[u8]| -> Vec<u8> {
        let ulen = (8 + payload.len()) as u16;
        let mut u = Vec::with_capacity(ulen as usize);
        u.extend_from_slice(&sport.to_be_bytes());
        u.extend_from_slice(&dport.to_be_bytes());
        u.extend_from_slice(&ulen.to_be_bytes());
        u.extend_from_slice(&0u16.to_be_bytes());
        u.extend_from_slice(payload);
        u
    };

    let build_tcp =
        |sport: u16, dport: u16, seq: u32, ack: u32, flags: u16, payload: &[u8]| -> Vec<u8> {
            let mut t = Vec::with_capacity(20 + payload.len());
            t.extend_from_slice(&sport.to_be_bytes());
            t.extend_from_slice(&dport.to_be_bytes());
            t.extend_from_slice(&seq.to_be_bytes());
            t.extend_from_slice(&ack.to_be_bytes());
            t.extend_from_slice(&(0x5000u16 | flags).to_be_bytes());
            t.extend_from_slice(&65535u16.to_be_bytes());
            t.extend_from_slice(&[0, 0, 0, 0]);
            t.extend_from_slice(payload);
            t
        };

    // 1 & 2: ARP Request & Reply
    let mut arp_req = vec![0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01];
    arp_req.extend_from_slice(&mac_c);
    arp_req.extend_from_slice(&ip_c);
    arp_req.extend_from_slice(&[0; 6]);
    arp_req.extend_from_slice(&ip_gw);
    push_eth(&mut cap, 0, 100_000, 0x0806, &arp_req);

    let mut arp_rep = vec![0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x02];
    arp_rep.extend_from_slice(&mac_s);
    arp_rep.extend_from_slice(&ip_gw);
    arp_rep.extend_from_slice(&mac_c);
    arp_rep.extend_from_slice(&ip_c);
    push_eth(&mut cap, 0, 450_000, 0x0806, &arp_rep);

    // 3 & 4: DNS Query & Response for api.mung-ash.io
    let mut dns_q = vec![0x1a, 0x2b, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    dns_q.extend_from_slice(b"\x03api\x08mung-ash\x02io\x00\x00\x01\x00\x01");
    push_eth(
        &mut cap,
        0,
        1_200_000,
        0x0800,
        &build_ipv4(ip_c, ip_gw, 17, &build_udp(53111, 53, &dns_q)),
    );

    let mut dns_r = vec![0x1a, 0x2b, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    dns_r.extend_from_slice(b"\x03api\x08mung-ash\x02io\x00\x00\x01\x00\x01");
    dns_r.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0x01, 0x2c, 0, 4]);
    dns_r.extend_from_slice(&ip_web);
    push_eth(
        &mut cap,
        0,
        8_500_000,
        0x0800,
        &build_ipv4(ip_gw, ip_c, 17, &build_udp(53, 53111, &dns_r)),
    );

    // 5, 6, 7: TCP 3-way Handshake
    push_eth(
        &mut cap,
        0,
        10_000_000,
        0x0800,
        &build_ipv4(ip_c, ip_web, 6, &build_tcp(54321, 80, 1000, 0, 0x02, b"")),
    );
    push_eth(
        &mut cap,
        0,
        24_000_000,
        0x0800,
        &build_ipv4(
            ip_web,
            ip_c,
            6,
            &build_tcp(80, 54321, 5000, 1001, 0x12, b""),
        ),
    );
    push_eth(
        &mut cap,
        0,
        25_000_000,
        0x0800,
        &build_ipv4(
            ip_c,
            ip_web,
            6,
            &build_tcp(54321, 80, 1001, 5001, 0x10, b""),
        ),
    );

    // 8 & 9: HTTP GET & 200 OK JSON Response
    let req_http =
        b"GET /api/v1/telemetry HTTP/1.1\r\nHost: api.mung-ash.io\r\nUser-Agent: mung-ash/0.1\r\n\r\n";
    push_eth(
        &mut cap,
        0,
        30_000_000,
        0x0800,
        &build_ipv4(
            ip_c,
            ip_web,
            6,
            &build_tcp(54321, 80, 1001, 5001, 0x18, req_http),
        ),
    );
    let resp_http = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 48\r\n\r\n{\"status\":\"ok\",\"engine\":\"mung-ash\",\"safe\":true}\n";
    push_eth(
        &mut cap,
        0,
        55_000_000,
        0x0800,
        &build_ipv4(
            ip_web,
            ip_c,
            6,
            &build_tcp(80, 54321, 5001, 1001 + req_http.len() as u32, 0x18, resp_http),
        ),
    );

    // 10: TLS ClientHello
    let tls_ch = [
        0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b, 0x03, 0x03, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x00, 0x00,
        0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x00,
    ];
    push_eth(
        &mut cap,
        1,
        0,
        0x0800,
        &build_ipv4(
            ip_c,
            ip_web,
            6,
            &build_tcp(54322, 443, 1, 1, 0x18, &tls_ch),
        ),
    );

    // 11: BGP OPEN
    let mut bgp = vec![0xff; 16];
    bgp.extend_from_slice(&29u16.to_be_bytes());
    bgp.extend_from_slice(&[1, 4, 0xfd, 0xe9, 0x00, 0xb4, 192, 0, 2, 1, 0]);
    push_eth(
        &mut cap,
        1,
        100_000_000,
        0x0800,
        &build_ipv4(ip_c, ip_gw, 6, &build_tcp(49100, 179, 1, 1, 0x18, &bgp)),
    );

    // 12: MQTT PUBLISH
    let mqtt = b"\x30\x16\x00\x0esensors/rack0124.8C";
    push_eth(
        &mut cap,
        1,
        200_000_000,
        0x0800,
        &build_ipv4(ip_c, ip_gw, 6, &build_tcp(49200, 1883, 1, 1, 0x18, mqtt)),
    );

    // 13: Modbus/TCP Read Holding Registers
    let modbus = [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x6b, 0x00, 0x03];
    push_eth(
        &mut cap,
        1,
        300_000_000,
        0x0800,
        &build_ipv4(ip_c, ip_gw, 6, &build_tcp(49300, 502, 1, 1, 0x18, &modbus)),
    );

    // 14: ICMP Echo Request
    let icmp = [8, 0, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x01, b'p', b'i', b'n', b'g'];
    push_eth(
        &mut cap,
        1,
        400_000_000,
        0x0800,
        &build_ipv4(ip_c, ip_web, 1, &icmp),
    );

    cap
}
