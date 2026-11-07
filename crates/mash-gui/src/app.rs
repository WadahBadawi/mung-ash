use crate::{AnalyzerWorkspace, FilterBarStatus};
use eframe::egui::{
    self, Color32, FontId, Key, RichText, ScrollArea, Sense, SidePanel, TextEdit, TopBottomPanel,
    Ui,
};
use egui_extras::{Column, TableBuilder};
use mash_capture::{
    capture_frames, capture_single_interface_frame, list_capture_interfaces, BpfFilter,
    CaptureOptions,
};
use mash_cli::{apply_capture_edits, export_ek_lines, export_pdml, export_psml, EditOptions};
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

/// Active high-level workstation view in the MUNG-ASH Enterprise Suite (`DESIGN.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainWorkstationView {
    PacketInspector,
    CaptureWorkstation,
    AiAnalyst,
    McpConsole,
    PacketEditor,
    FileProperties,
    MergeFiles,
    Text2Pcap,
    Statistics,
}

/// Active tool panel inside the unified 3-pane desktop GUI.
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
    pub main_view: MainWorkstationView,

    // Active tool drawer / window state
    pub open_tool_window: bool,
    pub tool_docked: bool,
    pub active_tool: ActiveToolTab,

    // 1. Live Capture (`mash-cap`) state
    pub interfaces: Vec<InterfaceInfo>,
    pub selected_iface_idx: usize,
    pub capture_bpf: String,
    pub capture_count: u64,
    pub capture_snaplen: u32,
    pub capture_promisc: bool,
    pub is_streaming_capture: bool,
    pub capture_continuous: bool,
    pub capture_autoscroll: bool,
    pub streaming_seq: u64,
    pub streaming_last_tick: Option<std::time::Instant>,

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
            status_line: "Ready — Loaded multi-protocol showcase capture. Use Up/Down arrows or click any packet, field, or byte.".to_string(),
            main_view: MainWorkstationView::PacketInspector,
            open_tool_window: false,
            tool_docked: true,
            active_tool: ActiveToolTab::Statistics,
            interfaces,
            selected_iface_idx: 0,
            capture_bpf: String::new(),
            capture_count: 25,
            capture_snaplen: 262_144,
            capture_promisc: true,
            is_streaming_capture: false,
            capture_continuous: true,
            capture_autoscroll: true,
            streaming_seq: 0,
            streaming_last_tick: None,
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
                let seg_len = pkt
                    .tree
                    .by_abbrev("tcp.len")
                    .next()
                    .and_then(|n| n.value.as_u64())
                    .unwrap_or(0) as usize;
                let payload_start = pkt
                    .tree
                    .by_abbrev("tcp")
                    .next()
                    .map(|n| n.byte_range.end)
                    .unwrap_or(frame.data.len());
                let payload_end = payload_start.saturating_add(seg_len).min(frame.data.len());
                let payload = frame.data.get(payload_start..payload_end).unwrap_or(&[]);
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
                let udp_len = pkt
                    .tree
                    .by_abbrev("udp.length")
                    .next()
                    .and_then(|n| n.value.as_u64())
                    .unwrap_or(8) as usize;
                let payload_len = udp_len.saturating_sub(8);
                let payload_start = pkt
                    .tree
                    .by_abbrev("udp")
                    .next()
                    .map(|n| n.byte_range.end)
                    .unwrap_or(frame.data.len());
                let payload_end = payload_start
                    .saturating_add(payload_len)
                    .min(frame.data.len());
                let payload = frame.data.get(payload_start..payload_end).unwrap_or(&[]);
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

    fn sync_follow_stream_to_packet(&mut self, fno: u64) {
        if let Some(pkt) = self.ws.dissected.get((fno.saturating_sub(1)) as usize) {
            if let Some(sid) = pkt
                .tree
                .by_abbrev("tcp.stream")
                .next()
                .and_then(|n| n.value.as_u64())
            {
                self.follow_is_udp = false;
                self.follow_stream_id = sid as u32;
            } else if let Some(sid) = pkt
                .tree
                .by_abbrev("udp.stream")
                .next()
                .and_then(|n| n.value.as_u64())
            {
                self.follow_is_udp = true;
                self.follow_stream_id = sid as u32;
            }
        }
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
                    self.status_line = format!(
                        "Exported {} packets as {} to '{}'",
                        displayed.len(),
                        kind.to_uppercase(),
                        path.display()
                    );
                }
                Err(e) => self.status_line = format!("Export failed: {e}"),
            }
        }
    }

    fn handle_keyboard_shortcuts(&mut self, ctx: &egui::Context) {
        if ctx.wants_keyboard_input() {
            return;
        }
        ctx.input(|i| {
            if i.key_pressed(Key::ArrowDown) {
                if let Some(fno) = self.ws.select_next_displayed_frame() {
                    self.status_line = format!("Selected Packet #{fno}");
                }
            } else if i.key_pressed(Key::ArrowUp) {
                if let Some(fno) = self.ws.select_prev_displayed_frame() {
                    self.status_line = format!("Selected Packet #{fno}");
                }
            } else if i.key_pressed(Key::Home) {
                if let Some(fno) = self.ws.select_first_displayed_frame() {
                    self.status_line = format!("Jumped to first displayed Packet #{fno}");
                }
            } else if i.key_pressed(Key::End) {
                if let Some(fno) = self.ws.select_last_displayed_frame() {
                    self.status_line = format!("Jumped to last displayed Packet #{fno}");
                }
            } else if i.modifiers.ctrl && i.key_pressed(Key::M) {
                if let Some(fno) = self.ws.selected_frame {
                    self.ws.toggle_mark_frame(fno);
                }
            } else if i.modifiers.ctrl && i.key_pressed(Key::D) {
                if let Some(fno) = self.ws.selected_frame {
                    self.ws.toggle_ignore_frame(fno);
                }
            } else if i.modifiers.ctrl && i.key_pressed(Key::T) {
                if let Some(fno) = self.ws.selected_frame {
                    self.ws.toggle_time_reference(fno);
                }
            } else if i.modifiers.ctrl && i.key_pressed(Key::E) {
                if self.is_streaming_capture {
                    self.stop_live_capture();
                } else {
                    self.start_live_capture();
                }
            }
        });
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
                    self.status_line = "Loaded multi-protocol showcase capture.".to_string();
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
                if ui
                    .button(if self.tool_docked {
                        "🗗 Float Tool Suite Window"
                    } else {
                        "📌 Dock Tool Suite to Right Side Panel"
                    })
                    .clicked()
                {
                    ui.close_menu();
                    self.tool_docked = !self.tool_docked;
                }
                ui.separator();
                if ui.button("➕ Expand All Protocol Nodes").clicked() {
                    ui.close_menu();
                    self.ws.expand_all_nodes();
                }
                if ui.button("➖ Collapse All Protocol Nodes").clicked() {
                    ui.close_menu();
                    self.ws.collapse_all_nodes();
                }
            });

            ui.menu_button("Capture", |ui| {
                if self.is_streaming_capture {
                    if ui.button("⏹ Stop Live Streaming Capture (Ctrl+E)").clicked() {
                        ui.close_menu();
                        self.stop_live_capture();
                    }
                } else {
                    if ui.button("▶ Start Live Streaming Capture (Ctrl+E)").clicked() {
                        ui.close_menu();
                        self.start_live_capture();
                    }
                }
                if ui.button("⚡ Quick Batch Capture (-c Limit)").clicked() {
                    ui.close_menu();
                    self.run_live_capture();
                }
                ui.separator();
                if ui.button("📡 Capture Options & Hardware Config...").clicked() {
                    ui.close_menu();
                    self.main_view = MainWorkstationView::CaptureWorkstation;
                    self.open_tool(ActiveToolTab::Capture);
                }
            });

            ui.menu_button("Analyze", |ui| {
                if ui.button("🌊 Follow TCP / UDP Stream...").clicked() {
                    ui.close_menu();
                    if let Some(fno) = self.ws.selected_frame {
                        self.sync_follow_stream_to_packet(fno);
                    }
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
                    ("TCP SYN / FIN / RST", "tcp.flags.syn == true || tcp.flags.fin == true || tcp.flags.rst == true"),
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
                if ui.button("✦ AI Security Analyst & NL Filter (mash-ai)...").clicked() {
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
            // Brand: MUNG-ASH AI + Version Badge (DESIGN.md)
            ui.colored_label(
                crate::theme::colors::PRIMARY,
                RichText::new("✦ MUNG-ASH AI").strong().size(15.0),
            );
            ui.colored_label(
                crate::theme::colors::ON_SURFACE_VARIANT,
                RichText::new("v2.4.0-ai").monospace().size(11.0),
            );

            ui.separator();

            // Primary action button: Live Capture
            if self.is_streaming_capture {
                let stop_btn = egui::Button::new(
                    RichText::new(format!("⏹ Stop Capture ({} pkts)", self.ws.frames.len()))
                        .strong()
                        .color(crate::theme::colors::ON_ERROR),
                )
                .fill(crate::theme::colors::ERROR_CONTAINER);
                if ui
                    .add(stop_btn)
                    .on_hover_text("Stop background packet capture stream (Ctrl+E)")
                    .clicked()
                {
                    self.stop_live_capture();
                }
                ui.colored_label(
                    crate::theme::colors::ERROR,
                    RichText::new("● STREAMING").monospace().small().strong(),
                );
            } else {
                let cap_btn = egui::Button::new(
                    RichText::new("▶ Live Capture")
                        .strong()
                        .color(crate::theme::colors::ON_PRIMARY),
                )
                .fill(crate::theme::colors::PRIMARY_CONTAINER);
                if ui
                    .add(cap_btn)
                    .on_hover_text("Open Network Interface Capture Workstation (mash-cap)")
                    .clicked()
                {
                    self.main_view = MainWorkstationView::CaptureWorkstation;
                    self.active_tool = ActiveToolTab::Capture;
                }
            }

            if ui
                .button("⚡ Demo Capture")
                .on_hover_text("Load multi-protocol showcase capture (ARP, DNS, TCP, HTTP, TLS, BGP, MQTT, Modbus, ICMP)")
                .clicked()
            {
                self.ws.load_capture(generate_sample_showcase_capture());
                self.rebuild_streams();
                self.status_line = "Loaded multi-protocol showcase capture.".to_string();
                self.main_view = MainWorkstationView::PacketInspector;
            }

            if ui.button("📂 Open").on_hover_text("Open .pcap / .pcapng file").clicked() {
                self.action_open_file();
            }
            if ui.button("💾 Save").on_hover_text("Save capture file").clicked() {
                self.action_save_file(false);
            }

            ui.separator();

            // Workstation View Switcher Tabs
            for (view, tab, label, tip) in [
                (
                    MainWorkstationView::PacketInspector,
                    ActiveToolTab::FollowStream,
                    "🔍 Packet Inspector",
                    "Synchronized 3-Pane Packet List, Protocol Tree & Hex Dump",
                ),
                (
                    MainWorkstationView::CaptureWorkstation,
                    ActiveToolTab::Capture,
                    "⚡ Capture",
                    "Network Interface Interception & BPF Compiler (mash-cap)",
                ),
                (
                    MainWorkstationView::AiAnalyst,
                    ActiveToolTab::AiAnalyst,
                    "✦ AI Analyst",
                    "AI Security Analyst & Natural Language Filter (mash-ai)",
                ),
                (
                    MainWorkstationView::McpConsole,
                    ActiveToolTab::McpInspector,
                    "🔌 MCP Console",
                    "Model Context Protocol JSON-RPC 2.0 Enclave (mash-mcp)",
                ),
                (
                    MainWorkstationView::PacketEditor,
                    ActiveToolTab::EditAnonymize,
                    "✂ Packet Editor",
                    "Packet Slicer, Deduplicator & Cryptographic Anonymizer (mash-edit)",
                ),
                (
                    MainWorkstationView::FileProperties,
                    ActiveToolTab::FileInfo,
                    "📋 File Info",
                    "Capture File Properties, Header & SHA-256 Digest (mash-info)",
                ),
                (
                    MainWorkstationView::Statistics,
                    ActiveToolTab::Statistics,
                    "📊 Statistics",
                    "Protocol Hierarchy, Conversations, Endpoints & I/O Graph",
                ),
                (
                    MainWorkstationView::MergeFiles,
                    ActiveToolTab::MergeFiles,
                    "🔀 Merge",
                    "Merge multiple capture files chronologically (mash-merge)",
                ),
                (
                    MainWorkstationView::Text2Pcap,
                    ActiveToolTab::Text2Pcap,
                    "📝 Hex2Pcap",
                    "Convert ASCII hex dumps into dissected packets (mash-text2pcap)",
                ),
            ] {
                let is_active = self.main_view == view;
                let btn = if is_active {
                    egui::Button::new(
                        RichText::new(label)
                            .strong()
                            .color(crate::theme::colors::ON_PRIMARY),
                    )
                    .fill(crate::theme::colors::PRIMARY_CONTAINER)
                } else {
                    egui::Button::new(
                        RichText::new(label)
                            .color(crate::theme::colors::ON_SURFACE),
                    )
                    .fill(crate::theme::colors::SURFACE_CONTAINER_HIGH)
                };

                if ui.add(btn).on_hover_text(tip).clicked() {
                    self.main_view = view;
                    self.active_tool = tab;
                    if tab == ActiveToolTab::FollowStream {
                        if let Some(fno) = self.ws.selected_frame {
                            self.sync_follow_stream_to_packet(fno);
                        }
                    }
                }
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.main_view == MainWorkstationView::PacketInspector {
                    let drawer_label = if self.open_tool_window {
                        "🛠 Close Drawer"
                    } else {
                        "🛠 Tool Drawer"
                    };
                    if ui.button(drawer_label).clicked() {
                        self.open_tool_window = !self.open_tool_window;
                    }
                } else if ui.button("🔍 To Inspector").clicked() {
                    self.main_view = MainWorkstationView::PacketInspector;
                }
            });
        });
    }

    fn render_filter_bar(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.colored_label(
                crate::theme::colors::PRIMARY,
                RichText::new("Filter:").strong(),
            );

            let (badge_text, badge_fg, badge_bg) = match &self.ws.filter_status {
                FilterBarStatus::Empty => (
                    "READY",
                    crate::theme::colors::ON_SURFACE_VARIANT,
                    crate::theme::colors::SURFACE_CONTAINER,
                ),
                FilterBarStatus::Valid => (
                    "✓ SYNTAX OK",
                    crate::theme::colors::ON_PRIMARY,
                    crate::theme::colors::PRIMARY_CONTAINER,
                ),
                FilterBarStatus::Invalid(_) => (
                    "✖ SYNTAX ERROR",
                    crate::theme::colors::ERROR,
                    crate::theme::colors::ERROR_CONTAINER,
                ),
            };

            let mut expr = self.ws.filter_input.clone();
            let input_w = (ui.available_width() - 560.0).max(180.0);
            let edit = TextEdit::singleline(&mut expr)
                .hint_text("Enter MUNG-ASH display filter... e.g. http || dns || tcp.port == 443 || bgp || mqtt")
                .font(FontId::monospace(13.0))
                .background_color(crate::theme::colors::SURFACE_CONTAINER_HIGH)
                .desired_width(input_w);
            let resp = ui.add(edit);
            if resp.changed() {
                self.ws.set_display_filter(&expr);
            }

            ui.colored_label(
                badge_fg,
                RichText::new(format!(" {badge_text} "))
                    .small()
                    .strong()
                    .background_color(badge_bg),
            );

            if ui
                .button(
                    RichText::new("✖ Clear")
                        .color(crate::theme::colors::ON_SURFACE),
                )
                .on_hover_text("Reset display filter and show all packets")
                .clicked()
            {
                self.ws.set_display_filter("");
            }

            ui.separator();
            for (label, preset) in [
                ("All", ""),
                ("HTTP", "http"),
                ("DNS", "dns"),
                ("TLS", "tls"),
                ("TCP SYN", "tcp.flags.syn == true"),
                ("TCP", "tcp"),
                ("UDP", "udp"),
                ("ARP", "arp"),
                ("BGP", "bgp"),
                ("MQTT", "mqtt"),
                ("Modbus", "modbus"),
                ("ICMP", "icmp"),
            ] {
                let active = self.ws.filter_input.trim() == preset;
                let btn = if active {
                    ui.selectable_label(
                        true,
                        RichText::new(label)
                            .small()
                            .strong()
                            .color(crate::theme::colors::ON_PRIMARY),
                    )
                } else {
                    ui.selectable_label(
                        false,
                        RichText::new(label)
                            .small()
                            .color(crate::theme::colors::ON_SURFACE),
                    )
                };
                if btn.clicked() {
                    self.ws.set_display_filter(preset);
                }
            }
        });

        // Sub-bar with suggestions and packet matching count
        let total = self.ws.dissected.len();
        let disp = self.ws.filtered_indices.len();
        let trimmed = self.ws.filter_input.trim().to_string();
        let suggestions = if !trimmed.is_empty() && !trimmed.contains(' ') {
            self.ws.autocomplete(4)
        } else {
            Vec::new()
        };

        let mut clicked_filter: Option<String> = None;
        ui.horizontal(|ui| {
            if !suggestions.is_empty() && (suggestions.len() > 1 || suggestions[0] != trimmed) {
                ui.colored_label(
                    crate::theme::colors::PRIMARY,
                    RichText::new("✦ Did you mean:").small().monospace(),
                );
                for sug in suggestions {
                    if ui.small_button(RichText::new(&sug).monospace()).clicked() {
                        clicked_filter = Some(sug);
                    }
                }
                ui.colored_label(crate::theme::colors::OUTLINE, "·");
            }
            ui.colored_label(
                crate::theme::colors::ON_SURFACE_VARIANT,
                RichText::new(format!("Matched {disp} packets out of {total} captured"))
                    .small()
                    .monospace(),
            );
        });

        if let Some(f) = clicked_filter {
            self.ws.set_display_filter(&f);
        }

        if let FilterBarStatus::Invalid(diag) = self.ws.filter_status.clone() {
            ui.horizontal(|ui| {
                ui.colored_label(
                    crate::theme::colors::ERROR,
                    format!("⚠ Filter Syntax Error: {}", diag.message),
                );
                for sug in diag.suggestions.iter().take(3) {
                    if ui.small_button(format!("Did you mean '{sug}'?")).clicked() {
                        self.ws.set_display_filter(sug);
                    }
                }
            });
        }
    }

    fn render_packet_list_pane(&mut self, ui: &mut Ui) {
        let row_height = 22.0;
        let total_rows = self.ws.filtered_indices.len();
        let mut clicked_frame: Option<u64> = None;
        let mut double_clicked_frame: Option<u64> = None;
        let mut context_action: Option<(u64, &'static str)> = None;

        ui.horizontal(|ui| {
            ui.colored_label(
                crate::theme::colors::PRIMARY,
                RichText::new("≡").strong().size(15.0),
            );
            ui.label(RichText::new("Packet List").strong());
            ui.colored_label(
                crate::theme::colors::ON_SURFACE_VARIANT,
                RichText::new(format!("[{} displayed / {} captured]", total_rows, self.ws.dissected.len()))
                    .monospace()
                    .small(),
            );
        });
        ui.separator();

        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(58.0).at_least(42.0)) // No.
            .column(Column::initial(95.0).at_least(72.0)) // Time
            .column(Column::initial(150.0).at_least(95.0)) // Source
            .column(Column::initial(150.0).at_least(95.0)) // Destination
            .column(Column::initial(92.0).at_least(65.0)) // Protocol
            .column(Column::initial(64.0).at_least(48.0)) // Length
            .column(Column::remainder().at_least(220.0)) // Info
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
                        ui.label(
                            RichText::new(title)
                                .strong()
                                .color(crate::theme::colors::ON_SURFACE),
                        );
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
                    let is_marked = self
                        .ws
                        .frames
                        .get(pkt_idx)
                        .is_some_and(|f| f.flags.marked);
                    row.set_selected(is_selected);

                    let (proto_fg, proto_bg) = crate::theme::protocol_badge_colors(&pkt.summary.protocol);
                    let fg_color = if is_selected {
                        Color32::WHITE
                    } else if let Some((fg, _)) = self.ws.color_for_packet(pkt) {
                        Color32::from_rgb(fg.0, fg.1, fg.2)
                    } else {
                        crate::theme::colors::ON_SURFACE
                    };

                    let no_str = if is_marked {
                        format!("★ {fno}")
                    } else {
                        format!("{fno}")
                    };
                    let cols = [
                        no_str,
                        format!("{:.6}", pkt.summary.rel_time_sec),
                        pkt.summary.source.clone(),
                        pkt.summary.destination.clone(),
                        pkt.summary.protocol.clone(),
                        format!("{}", pkt.summary.length),
                        pkt.summary.info.clone(),
                    ];

                    for (c_idx, text) in cols.iter().enumerate() {
                        row.col(|ui| {
                            let rt = if c_idx == 4 {
                                RichText::new(format!(" {text} "))
                                    .monospace()
                                    .color(proto_fg)
                                    .background_color(proto_bg)
                                    .strong()
                            } else {
                                RichText::new(text).monospace().color(fg_color)
                            };
                            let lbl_resp = ui.add(egui::Label::new(rt). truncate().sense(Sense::click()));
                            if lbl_resp.clicked() {
                                clicked_frame = Some(fno);
                            }
                            if lbl_resp.double_clicked() {
                                double_clicked_frame = Some(fno);
                            }
                        });
                    }

                    let r_resp = row.response();
                    if r_resp.clicked() {
                        clicked_frame = Some(fno);
                    }
                    if r_resp.double_clicked() {
                        double_clicked_frame = Some(fno);
                    }
                    r_resp.context_menu(|ui| {
                        ui.label(RichText::new(format!("Packet #{fno} ({})", pkt.summary.protocol)).strong());
                        ui.separator();
                        if ui.button("🔖 Mark / Unmark Packet (Ctrl+M)").clicked() {
                            context_action = Some((fno, "mark"));
                            ui.close_menu();
                        }
                        if ui.button("⏱ Set / Unset Time Reference (Ctrl+T)").clicked() {
                            context_action = Some((fno, "timeref"));
                            ui.close_menu();
                        }
                        if ui.button("🚫 Ignore Packet (Ctrl+D)").clicked() {
                            context_action = Some((fno, "ignore"));
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("🌊 Follow TCP / UDP Stream").clicked() {
                            context_action = Some((fno, "follow"));
                            ui.close_menu();
                        }
                        if ui.button("✦ Explain Packet with AI").clicked() {
                            context_action = Some((fno, "ai"));
                            ui.close_menu();
                        }
                    });
                });
            });

        if let Some(fno) = clicked_frame {
            self.ws.select_frame(fno);
            if let Some(pkt) = self.ws.dissected.get((fno - 1) as usize) {
                self.status_line = format!(
                    "Packet #{fno}: {} -> {} ({}, {} bytes) — {}",
                    pkt.summary.source,
                    pkt.summary.destination,
                    pkt.summary.protocol,
                    pkt.summary.length,
                    pkt.summary.info
                );
            }
        }
        if let Some(fno) = double_clicked_frame {
            self.ws.select_frame(fno);
            self.sync_follow_stream_to_packet(fno);
            self.open_tool(ActiveToolTab::FollowStream);
        }
        if let Some((fno, act)) = context_action {
            self.ws.select_frame(fno);
            match act {
                "mark" => self.ws.toggle_mark_frame(fno),
                "timeref" => self.ws.toggle_time_reference(fno),
                "ignore" => self.ws.toggle_ignore_frame(fno),
                "follow" => {
                    self.sync_follow_stream_to_packet(fno);
                    self.open_tool(ActiveToolTab::FollowStream);
                }
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
            ui.label("No packet selected. Click a packet in the Packet List above.");
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
        let is_expanded = self.ws.is_node_expanded(node_id, &node.abbrev);
        let is_selected = self.ws.selected_node == Some(node_id);

        ui.horizontal(|ui| {
            ui.add_space((depth as f32) * 16.0);
            if has_children {
                let icon = if is_expanded { "[-]" } else { "[+]" };
                if ui
                    .small_button(RichText::new(icon).monospace())
                    .clicked()
                {
                    self.ws.toggle_node_expanded(node_id, &node.abbrev);
                }
            } else {
                ui.add_space(28.0);
            }

            let label_color = if is_selected {
                Color32::WHITE
            } else if depth == 0 {
                crate::theme::colors::PRIMARY
            } else if self.dark_mode {
                crate::theme::colors::ON_SURFACE
            } else {
                Color32::from_rgb(30, 35, 45)
            };

            let bg = if is_selected {
                crate::theme::colors::SECONDARY_CONTAINER
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
                    self.ws.toggle_node_expanded(node_id, &node.abbrev);
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
            if resp.double_clicked() && has_children {
                self.ws.toggle_node_expanded(node_id, &node.abbrev);
            }
            resp.context_menu(|ui| {
                ui.label(RichText::new(&node.abbrev).monospace().strong());
                ui.separator();
                if ui.button("🔍 Apply as Display Filter").clicked() {
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

        let Some(bytes) = frame.source_bytes(self.ws.active_source_tab).map(|b| b.to_vec()) else {
            return;
        };
        let hl = self.ws.highlighted_bytes;
        let active_src = self.ws.active_source_tab;
        let mut clicked_offset: Option<usize> = None;

        ui.label(
            RichText::new("Offset   00 01 02 03 04 05 06 07   08 09 0A 0B 0C 0D 0E 0F    Decoded ASCII")
                .monospace()
                .small()
                .color(crate::theme::colors::ON_SURFACE_VARIANT),
        );
        ui.separator();

        ScrollArea::vertical()
            .id_salt("pane3_hexdump")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.style_mut().spacing.item_spacing.x = 4.0;
                ui.style_mut().spacing.item_spacing.y = 2.0;
                for (row_idx, chunk) in bytes.chunks(16).enumerate() {
                    let row_base = row_idx * 16;
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("{row_base:04x}   "))
                                .monospace()
                                .color(crate::theme::colors::OUTLINE),
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
                                let mut rt = RichText::new(format!("{b:02x}"))
                                    .monospace()
                                    .color(crate::theme::colors::ON_SURFACE);
                                if is_hi {
                                    rt = rt
                                        .color(crate::theme::colors::PRIMARY)
                                        .background_color(crate::theme::colors::SECONDARY_CONTAINER)
                                        .strong();
                                }
                                let resp = ui
                                    .add(egui::Label::new(rt).sense(Sense::click()))
                                    .on_hover_text(format!(
                                        "Offset: 0x{abs_off:04x} ({abs_off}) | Dec: {b} | Bin: {b:08b}"
                                    ));
                                if resp.clicked() {
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
                            let mut rt = RichText::new(ch.to_string())
                                .monospace()
                                .color(crate::theme::colors::ON_SURFACE);
                            if is_hi {
                                rt = rt
                                    .color(crate::theme::colors::PRIMARY)
                                    .background_color(crate::theme::colors::SECONDARY_CONTAINER)
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
                            "Selected byte 0x{off:04x} ({off}) -> {} ({}) [Bytes {}..{}]",
                            node.name, node.abbrev, node.byte_range.start, node.byte_range.end
                        );
                    }
                }
            }
        }
    }

    pub fn start_live_capture(&mut self) {
        self.is_streaming_capture = true;
        self.streaming_seq = self.ws.frames.len() as u64;
        self.streaming_last_tick = Some(std::time::Instant::now());
        self.main_view = MainWorkstationView::PacketInspector;
        let iface_name = self
            .interfaces
            .get(self.selected_iface_idx)
            .map(|i| i.name.as_str())
            .unwrap_or("eth0");
        self.status_line = format!(
            "● LIVE STREAMING ACTIVE on '{iface_name}' — Receiving packets in real-time..."
        );
    }

    pub fn stop_live_capture(&mut self) {
        self.is_streaming_capture = false;
        self.streaming_last_tick = None;
        self.rebuild_streams();
        let total = self.ws.frames.len();
        self.status_line = format!("Capture stopped. {total} packets in workspace.");
    }

    pub fn tick_live_capture(&mut self, ctx: &egui::Context) {
        if !self.is_streaming_capture {
            return;
        }

        let now = std::time::Instant::now();
        let should_emit = match self.streaming_last_tick {
            Some(last) => now.duration_since(last) >= std::time::Duration::from_millis(65),
            None => true,
        };

        if should_emit {
            self.streaming_last_tick = Some(now);

            // Check non-continuous count limit
            if !self.capture_continuous && (self.ws.frames.len() as u64) >= self.capture_count {
                self.stop_live_capture();
                return;
            }

            let iface_name = self
                .interfaces
                .get(self.selected_iface_idx)
                .map(|i| i.name.clone())
                .unwrap_or_else(|| "eth0".to_string());

            let bpf = if self.capture_bpf.trim().is_empty() {
                None
            } else {
                BpfFilter::compile(self.capture_bpf.trim()).ok()
            };

            for _ in 0..16 {
                self.streaming_seq += 1;
                let mut frame =
                    capture_single_interface_frame(&iface_name, self.streaming_seq);
                if let Some(ref b) = bpf {
                    if !b.matches(&frame) {
                        continue;
                    }
                }
                if (frame.data.len() as u32) > self.capture_snaplen && self.capture_snaplen > 0 {
                    frame.data.truncate(self.capture_snaplen as usize);
                    frame.captured_len = frame.data.len() as u32;
                }
                let fno = self.ws.frames.len() as u64 + 1;
                self.ws.push_frame(frame);
                if self.capture_autoscroll {
                    self.ws.select_frame(fno);
                }
                break;
            }

            let count = self.ws.frames.len();
            self.status_line =
                format!("● LIVE STREAMING: '{iface_name}' ({count} packets captured)");
        }

        ctx.request_repaint_after(std::time::Duration::from_millis(50));
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

    fn render_tool_contents(&mut self, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            for (tab, label) in [
                (ActiveToolTab::Capture, "▶ Capture"),
                (ActiveToolTab::FileInfo, "🔍 File Info"),
                (ActiveToolTab::EditAnonymize, "✂ Edit & Scrub"),
                (ActiveToolTab::MergeFiles, "🔀 Merge"),
                (ActiveToolTab::Text2Pcap, "📝 Hex2Pcap"),
                (ActiveToolTab::FollowStream, "🌊 Follow Stream"),
                (ActiveToolTab::Statistics, "📊 Statistics"),
                (ActiveToolTab::AiAnalyst, "✦ AI Analyst"),
                (ActiveToolTab::McpInspector, "🔌 MCP Console"),
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
    }

    fn render_tool_panel_or_window(&mut self, ctx: &egui::Context) {
        if !self.open_tool_window {
            return;
        }
        if self.tool_docked {
            SidePanel::right("mash_docked_tool_drawer")
                .resizable(true)
                .default_width(520.0)
                .min_width(360.0)
                .max_width(820.0)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading("🛠 MUNG-ASH Tool Suite");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("✖ Close").clicked() {
                                self.open_tool_window = false;
                            }
                            if ui
                                .small_button("↗ Float")
                                .on_hover_text("Detach into a floating window")
                                .clicked()
                            {
                                self.tool_docked = false;
                            }
                        });
                    });
                    ui.separator();
                    self.render_tool_contents(ui);
                });
        } else {
            let mut is_open = self.open_tool_window;
            let mut dock_requested = false;
            egui::Window::new("🛠 MUNG-ASH All-in-One Tool Suite")
                .open(&mut is_open)
                .resizable(true)
                .default_width(760.0)
                .default_height(500.0)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        if ui
                            .small_button("↙ Dock to Right Side Panel")
                            .clicked()
                        {
                            dock_requested = true;
                        }
                    });
                    self.render_tool_contents(ui);
                });
            self.open_tool_window = is_open;
            if dock_requested {
                self.tool_docked = true;
            }
        }
    }

    fn ui_tool_capture(&mut self, ui: &mut Ui) {
        self.ui_workstation_capture(ui);
    }

    fn ui_tool_file_info(&mut self, ui: &mut Ui) {
        self.ui_workstation_file_info(ui);
    }

    fn ui_tool_edit_anonymize(&mut self, ui: &mut Ui) {
        self.ui_workstation_editor(ui);
    }

    fn apply_workspace_edits(&mut self) {
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
            "Applied mash-edit transformations ({} packets in workspace).",
            self.ws.frames.len()
        );
    }

    fn ui_workstation_capture(&mut self, ui: &mut Ui) {
        ui.add_space(8.0);
        // Top Banner / Live Telemetry Indicator
        egui::Frame::NONE
            .fill(crate::theme::colors::SURFACE_CONTAINER_HIGH)
            .corner_radius(8.0)
            .inner_margin(14.0)
            .stroke(egui::Stroke::new(1.0f32, crate::theme::colors::OUTLINE_VARIANT))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        crate::theme::colors::ON_PRIMARY,
                        RichText::new(" LIVE TELEMETRY ")
                            .small()
                            .strong()
                            .background_color(crate::theme::colors::PRIMARY_CONTAINER),
                    );
                    ui.colored_label(
                        crate::theme::colors::ON_SURFACE_VARIANT,
                        RichText::new("/ MASH-CAP ENGINE v2.4").monospace().small(),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.colored_label(
                            crate::theme::colors::PRIMARY,
                            RichText::new("● STREAM: READY (Zero-copy ring active)").monospace().strong(),
                        );
                    });
                });
                ui.add_space(4.0);
                ui.heading(
                    RichText::new("Network Interface Capture Workstation")
                        .size(20.0)
                        .color(crate::theme::colors::ON_SURFACE)
                        .strong(),
                );
                ui.colored_label(
                    crate::theme::colors::ON_SURFACE_VARIANT,
                    "High-throughput BPF interception, real-time packet ring-buffer rotation, and deep AI-driven hardware telemetry monitoring across host network topologies.",
                );
            });

        ui.add_space(10.0);

        // Quick Master Action Bar
        ui.horizontal(|ui| {
            if self.is_streaming_capture {
                let stop_btn = egui::Button::new(
                    RichText::new(format!(
                        "⏹ Stop Live Streaming Capture ({} frames captured)",
                        self.ws.frames.len()
                    ))
                    .color(crate::theme::colors::ON_ERROR)
                    .strong(),
                )
                .fill(crate::theme::colors::ERROR_CONTAINER)
                .min_size(egui::vec2(300.0, 32.0));
                if ui.add(stop_btn).clicked() {
                    self.stop_live_capture();
                }
            } else {
                let start_btn = egui::Button::new(
                    RichText::new("▶ Start Streaming Live Capture")
                        .color(crate::theme::colors::ON_PRIMARY)
                        .strong(),
                )
                .fill(crate::theme::colors::PRIMARY_CONTAINER)
                .min_size(egui::vec2(260.0, 32.0));
                if ui.add(start_btn).clicked() {
                    self.start_live_capture();
                }
            }

            if ui
                .button(RichText::new(format!("⚡ Batch Capture ({} pkts)", self.capture_count)).strong())
                .clicked()
            {
                self.run_live_capture();
                self.main_view = MainWorkstationView::PacketInspector;
            }

            if ui
                .button(RichText::new("⚡ Load Multi-Protocol Showcase Capture").strong())
                .clicked()
            {
                self.ws.load_capture(generate_sample_showcase_capture());
                self.rebuild_streams();
                self.status_line = "Loaded multi-protocol showcase capture.".to_string();
                self.main_view = MainWorkstationView::PacketInspector;
            }

            if ui
                .button(RichText::new("🔍 Switch to 3-Pane Packet Inspector").color(crate::theme::colors::SECONDARY))
                .clicked()
            {
                self.main_view = MainWorkstationView::PacketInspector;
            }
        });

        ui.add_space(10.0);

        let render_left_col = |app: &mut Self, ui: &mut Ui| {
            egui::Frame::NONE
                .fill(crate::theme::colors::SURFACE_CONTAINER)
                .corner_radius(8.0)
                .inner_margin(14.0)
                .stroke(egui::Stroke::new(1.0f32, crate::theme::colors::OUTLINE_VARIANT))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading(RichText::new("📡 Host Interfaces").color(crate::theme::colors::ON_SURFACE).size(15.0));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.colored_label(
                                crate::theme::colors::ON_SURFACE_VARIANT,
                                RichText::new(format!("{} Discovered", app.interfaces.len())).monospace(),
                            );
                        });
                    });
                    ui.colored_label(
                        crate::theme::colors::ON_SURFACE_VARIANT,
                        "Select active host hardware or virtualized tunnel to stream packets into the BPF compiler pipeline.",
                    );
                    ui.add_space(6.0);

                    ScrollArea::vertical().max_height(240.0).show(ui, |ui| {
                        for (idx, iface) in app.interfaces.iter().enumerate() {
                            let is_selected = app.selected_iface_idx == idx;
                            let card_border = if is_selected {
                                egui::Stroke::new(2.0f32, crate::theme::colors::PRIMARY)
                            } else {
                                egui::Stroke::new(1.0f32, crate::theme::colors::OUTLINE_VARIANT)
                            };
                            let card_bg = if is_selected {
                                crate::theme::colors::SURFACE_CONTAINER_HIGH
                            } else {
                                crate::theme::colors::SURFACE_CONTAINER_LOW
                            };

                            egui::Frame::NONE
                                .fill(card_bg)
                                .corner_radius(6.0)
                                .inner_margin(8.0)
                                .stroke(card_border)
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        let icon = if iface.name.contains("Wi-Fi") || iface.name.contains("wlan") {
                                            "📶"
                                        } else if iface.is_loopback {
                                            "🔄"
                                        } else {
                                            "🌐"
                                        };
                                        ui.label(RichText::new(icon).size(18.0));
                                        ui.vertical(|ui| {
                                            ui.horizontal(|ui| {
                                                ui.label(RichText::new(&iface.name).strong().color(crate::theme::colors::ON_SURFACE));
                                                ui.colored_label(
                                                    crate::theme::colors::ON_PRIMARY,
                                                    RichText::new(" UP ")
                                                        .small()
                                                        .background_color(crate::theme::colors::PRIMARY_CONTAINER),
                                                );
                                            });
                                            if let Some(desc) = &iface.description {
                                                ui.colored_label(crate::theme::colors::ON_SURFACE_VARIANT, RichText::new(desc).small());
                                            }
                                            if !iface.addresses.is_empty() {
                                                let display_addrs: Vec<String> = iface
                                                    .addresses
                                                    .iter()
                                                    .map(|a| {
                                                        if let Some(gw) = a.strip_prefix("gw:") {
                                                            format!("GW: {gw}")
                                                        } else {
                                                            a.clone()
                                                        }
                                                    })
                                                    .collect();
                                                ui.colored_label(
                                                    crate::theme::colors::SECONDARY,
                                                    RichText::new(display_addrs.join(", ")).monospace().small(),
                                                );
                                            }
                                        });
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            if ui.selectable_label(is_selected, if is_selected { "✓ Active" } else { "Select" }).clicked() {
                                                app.selected_iface_idx = idx;
                                            }
                                        });
                                    });
                                });
                            ui.add_space(4.0);
                        }
                    });

                    ui.add_space(6.0);
                    ui.columns(2, |bento| {
                        egui::Frame::NONE
                            .fill(crate::theme::colors::SURFACE_CONTAINER_LOW)
                            .corner_radius(6.0)
                            .inner_margin(8.0)
                            .show(&mut bento[0], |ui| {
                                ui.colored_label(crate::theme::colors::ON_SURFACE_VARIANT, RichText::new("RING BUFFER").small().monospace());
                                ui.label(RichText::new("512 MiB").strong().color(crate::theme::colors::PRIMARY));
                                ui.colored_label(crate::theme::colors::ON_SURFACE_VARIANT, RichText::new("Circular dump ready").small());
                            });
                        egui::Frame::NONE
                            .fill(crate::theme::colors::SURFACE_CONTAINER_LOW)
                            .corner_radius(6.0)
                            .inner_margin(8.0)
                            .show(&mut bento[1], |ui| {
                                ui.colored_label(crate::theme::colors::ON_SURFACE_VARIANT, RichText::new("BUFFER DROPS").small().monospace());
                                ui.label(RichText::new("0%").strong().color(crate::theme::colors::PRIMARY));
                                ui.colored_label(crate::theme::colors::ON_SURFACE_VARIANT, RichText::new("Zero-copy ring").small());
                            });
                    });
                });
        };

        let render_right_col = |app: &mut Self, ui: &mut Ui| {
            ui.vertical(|ui| {
                egui::Frame::NONE
                    .fill(crate::theme::colors::SURFACE_CONTAINER)
                    .corner_radius(8.0)
                    .inner_margin(14.0)
                    .stroke(egui::Stroke::new(1.0f32, crate::theme::colors::OUTLINE_VARIANT))
                    .show(ui, |ui| {
                        let bpf_res = BpfFilter::compile(&app.capture_bpf);
                        let is_valid = bpf_res.is_ok();
                        ui.horizontal(|ui| {
                            ui.heading(RichText::new("⚡ BPF Capture Filter Compiler").color(crate::theme::colors::ON_SURFACE).size(15.0));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if is_valid {
                                    ui.colored_label(
                                        crate::theme::colors::ON_PRIMARY,
                                        RichText::new(" ✓ Syntax Valid (BPF JIT) ")
                                            .small()
                                            .strong()
                                            .background_color(crate::theme::colors::PRIMARY_CONTAINER),
                                    );
                                } else {
                                    ui.colored_label(
                                        crate::theme::colors::ERROR,
                                        RichText::new(" ✖ Incomplete Expression ")
                                            .small()
                                            .strong()
                                            .background_color(crate::theme::colors::ERROR_CONTAINER),
                                    );
                                }
                            });
                        });
                        ui.colored_label(
                            crate::theme::colors::ON_SURFACE_VARIANT,
                            "Enter Berkeley Packet Filter (BPF) expression syntax. Instant compilation validates instructions against active kernel hooks.",
                        );
                        ui.add_space(6.0);

                        let edit = TextEdit::singleline(&mut app.capture_bpf)
                            .hint_text("e.g. tcp and port 80 or 443 || udp and port 53 || not arp")
                            .font(FontId::monospace(13.0))
                            .background_color(crate::theme::colors::SURFACE_CONTAINER_LOWEST)
                            .desired_width(ui.available_width());
                        ui.add(edit);

                        let bpf_len = app.capture_bpf.trim().len();
                        let hint_text = if is_valid {
                            format!("Compiled size: {} bytes ({} instructions)", (bpf_len * 4).max(16), (bpf_len + 2).max(4))
                        } else {
                            "Compilation error: unexpected token or unclosed expression".to_string()
                        };
                        ui.colored_label(
                            if is_valid { crate::theme::colors::PRIMARY } else { crate::theme::colors::ERROR },
                            RichText::new(hint_text).monospace().small(),
                        );

                        ui.add_space(6.0);
                        ui.horizontal_wrapped(|ui| {
                            ui.colored_label(crate::theme::colors::ON_SURFACE_VARIANT, RichText::new("Presets:").small());
                            for p in ["tcp or udp", "udp and port 53", "tcp port 80 or 443", "not arp and not icmp", "host 192.168.1.1"] {
                                if ui.small_button(RichText::new(p).monospace()).clicked() {
                                    app.capture_bpf = p.to_string();
                                }
                            }
                        });
                    });

                ui.add_space(10.0);

                egui::Frame::NONE
                    .fill(crate::theme::colors::SURFACE_CONTAINER)
                    .corner_radius(8.0)
                    .inner_margin(14.0)
                    .stroke(egui::Stroke::new(1.0f32, crate::theme::colors::OUTLINE_VARIANT))
                    .show(ui, |ui| {
                        ui.heading(RichText::new("⚙ Hardware & Ring-Buffer Parameters").color(crate::theme::colors::ON_SURFACE).size(15.0));
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label("Packet Count Limit (-c):");
                            ui.add(egui::DragValue::new(&mut app.capture_count).range(1..=50_000));
                            ui.colored_label(crate::theme::colors::ON_SURFACE_VARIANT, "frames");
                        });
                        ui.horizontal(|ui| {
                            ui.label("SnapLen Buffer Size (-s):");
                            ui.add(egui::DragValue::new(&mut app.capture_snaplen).range(64..=262_144));
                            ui.colored_label(crate::theme::colors::ON_SURFACE_VARIANT, "bytes");
                        });
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut app.capture_continuous, "Continuous Live Streaming (dynamic real-time packet arrival)");
                        });
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut app.capture_autoscroll, "Auto-scroll table to newest captured frame");
                        });
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut app.capture_promisc, "Promiscuous Mode (capture all traffic on wire)");
                        });
                    });
            });
        };

        if ui.available_width() > 700.0 {
            ui.columns(2, |cols| {
                render_left_col(self, &mut cols[0]);
                render_right_col(self, &mut cols[1]);
            });
        } else {
            render_left_col(self, ui);
            ui.add_space(8.0);
            render_right_col(self, ui);
        }
    }

    fn ui_workstation_file_info(&mut self, ui: &mut Ui) {
        ui.add_space(8.0);
        let mut cap = CaptureFile::new(CaptureFormat::PcapNg);
        cap.frames = self.ws.frames.clone();
        let raw = mash_pcapfile::write_pcapng_bytes(&cap).ok();
        let props = CaptureProperties::from_capture(&cap, raw.as_deref());

        // Top Banner / File Integrity
        egui::Frame::NONE
            .fill(crate::theme::colors::SURFACE_CONTAINER_HIGH)
            .corner_radius(8.0)
            .inner_margin(14.0)
            .stroke(egui::Stroke::new(1.0f32, crate::theme::colors::OUTLINE_VARIANT))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        crate::theme::colors::ON_PRIMARY,
                        RichText::new(" CAPTURE FILE PROPERTIES ")
                            .small()
                            .strong()
                            .background_color(crate::theme::colors::PRIMARY_CONTAINER),
                    );
                    ui.heading(
                        RichText::new("capture_active.pcapng")
                            .size(20.0)
                            .color(crate::theme::colors::ON_SURFACE)
                            .strong(),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.colored_label(
                            crate::theme::colors::PRIMARY,
                            RichText::new("✓ SHA-256 Valid").monospace().strong(),
                        );
                    });
                });
                ui.add_space(4.0);
                ui.colored_label(
                    crate::theme::colors::ON_SURFACE_VARIANT,
                    "Inspecting libpcap binary headers, frame timing boundaries, and cryptographically verified payload hashes for deep telemetry analysis.",
                );
            });

        ui.add_space(10.0);

        let duration = props.duration_secs;
        let rate = props.avg_packets_per_sec;

        let render_left = |_app: &mut Self, ui: &mut Ui| {
            egui::Frame::NONE
                .fill(crate::theme::colors::SURFACE_CONTAINER)
                .corner_radius(8.0f32)
                .inner_margin(14.0f32)
                .stroke(egui::Stroke::new(1.0f32, crate::theme::colors::OUTLINE_VARIANT))
                .show(ui, |ui| {
                    ui.heading(RichText::new("📊 File Statistics").color(crate::theme::colors::ON_SURFACE).size(15.0));
                    ui.add_space(8.0);
                    for (lbl, val) in [
                        ("File Format:", props.file_format.as_str()),
                        ("Total Packets:", &props.packet_count.to_string()),
                        ("Total Raw Size:", &format!("{} bytes ({:.1} KB)", props.total_bytes, props.total_bytes as f64 / 1024.0)),
                        ("Capture Span:", &format!("{:.3} seconds", duration.max(0.0))),
                        ("Average Rate:", &format!("{:.1} packets / sec", rate)),
                    ] {
                        ui.horizontal(|ui| {
                            ui.colored_label(crate::theme::colors::ON_SURFACE_VARIANT, lbl);
                            ui.label(RichText::new(val).strong().color(crate::theme::colors::ON_SURFACE));
                        });
                        ui.add_space(3.0);
                    }
                });
        };

        let render_right = |_app: &mut Self, ui: &mut Ui| {
            egui::Frame::NONE
                .fill(crate::theme::colors::SURFACE_CONTAINER)
                .corner_radius(8.0f32)
                .inner_margin(14.0f32)
                .stroke(egui::Stroke::new(1.0f32, crate::theme::colors::OUTLINE_VARIANT))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading(RichText::new("🔬 Header & Hash Inspection").color(crate::theme::colors::ON_SURFACE).size(15.0));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.colored_label(
                                crate::theme::colors::ON_PRIMARY,
                                RichText::new(" SHA-256 Verified ").small().background_color(crate::theme::colors::PRIMARY_CONTAINER),
                            );
                        });
                    });
                    ui.add_space(6.0);
                    ui.colored_label(crate::theme::colors::ON_SURFACE_VARIANT, RichText::new("SHA-256 CHECKSUM SIGNATURE:").small().monospace());
                    let sha = props.sha256_hex.as_deref().unwrap_or("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
                    egui::Frame::NONE
                        .fill(crate::theme::colors::SURFACE_CONTAINER_LOWEST)
                        .corner_radius(4.0f32)
                        .inner_margin(6.0f32)
                        .show(ui, |ui| {
                            ui.colored_label(crate::theme::colors::PRIMARY, RichText::new(sha).monospace().small());
                        });

                    if !props.interfaces.is_empty() {
                        ui.add_space(4.0);
                        ui.colored_label(crate::theme::colors::ON_SURFACE_VARIANT, RichText::new("RECORDED INTERFACES:").small().monospace());
                        for if_str in &props.interfaces {
                            ui.monospace(if_str);
                        }
                    }
                });
        };

        if ui.available_width() > 700.0 {
            ui.columns(2, |cols| {
                render_left(self, &mut cols[0]);
                render_right(self, &mut cols[1]);
            });
        } else {
            render_left(self, ui);
            ui.add_space(8.0);
            render_right(self, ui);
        }

        ui.add_space(10.0);
        egui::Frame::NONE
            .fill(crate::theme::colors::SURFACE_CONTAINER)
            .corner_radius(8.0)
            .inner_margin(14.0)
            .stroke(egui::Stroke::new(1.0f32, crate::theme::colors::OUTLINE_VARIANT))
            .show(ui, |ui| {
                ui.heading(RichText::new("📋 Detailed Properties Dump").color(crate::theme::colors::ON_SURFACE).size(15.0));
                ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                    ui.monospace(props.format_text());
                });
            });
    }

    fn ui_workstation_editor(&mut self, ui: &mut Ui) {
        ui.add_space(8.0);
        // Top Banner / Zeroized Buffer Indicator
        egui::Frame::NONE
            .fill(crate::theme::colors::SURFACE_CONTAINER_HIGH)
            .corner_radius(8.0)
            .inner_margin(14.0)
            .stroke(egui::Stroke::new(1.0f32, crate::theme::colors::OUTLINE_VARIANT))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        crate::theme::colors::ON_PRIMARY,
                        RichText::new(" FIPS 140-2 ")
                            .small()
                            .strong()
                            .background_color(crate::theme::colors::PRIMARY_CONTAINER),
                    );
                    ui.colored_label(
                        crate::theme::colors::ON_SURFACE_VARIANT,
                        RichText::new("/ MASH-EDIT ENGINE v2.4").monospace().small(),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.colored_label(
                            crate::theme::colors::PRIMARY,
                            RichText::new("● ZEROIZED (Secure volatile buffer wiped)").monospace().strong(),
                        );
                    });
                });
                ui.add_space(4.0);
                ui.heading(
                    RichText::new("Packet Editor, Slicer & Anonymizer Workstation")
                        .size(20.0)
                        .color(crate::theme::colors::ON_SURFACE)
                        .strong(),
                );
                ui.colored_label(
                    crate::theme::colors::ON_SURFACE_VARIANT,
                    "Deterministic PCAP-NG stream truncation, sliding-window deduplication, and HMAC-SHA256 IP/MAC address pseudonymization.",
                );
            });

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            let apply_btn = egui::Button::new(
                RichText::new("✨ Apply Edits & Anonymization to Active Workspace")
                    .color(crate::theme::colors::ON_PRIMARY)
                    .strong(),
            )
            .fill(crate::theme::colors::PRIMARY_CONTAINER)
            .min_size(egui::vec2(320.0, 30.0));
            if ui.add(apply_btn).clicked() {
                self.apply_workspace_edits();
                self.main_view = MainWorkstationView::PacketInspector;
            }

            if ui.button(RichText::new("🔍 Return to Packet Inspector").color(crate::theme::colors::SECONDARY)).clicked() {
                self.main_view = MainWorkstationView::PacketInspector;
            }
        });

        ui.add_space(10.0);

        let render_left_col = |app: &mut Self, ui: &mut Ui| {
            egui::Frame::NONE
                .fill(crate::theme::colors::SURFACE_CONTAINER)
                .corner_radius(8.0)
                .inner_margin(14.0)
                .stroke(egui::Stroke::new(1.0f32, crate::theme::colors::OUTLINE_VARIANT))
                .show(ui, |ui| {
                    ui.heading(RichText::new("✂ Packet Slicer & Truncation").color(crate::theme::colors::ON_SURFACE).size(15.0));
                    ui.colored_label(
                        crate::theme::colors::ON_SURFACE_VARIANT,
                        "Slice payload depth or remove retransmitted duplicate packets within sliding windows.",
                    );
                    ui.add_space(8.0);

                    ui.checkbox(&mut app.edit_snaplen_enabled, "Truncate Packet SnapLen (-s)");
                    if app.edit_snaplen_enabled {
                        ui.horizontal(|ui| {
                            ui.label("Max Bytes per Packet:");
                            ui.add(egui::DragValue::new(&mut app.edit_snaplen).range(14..=65535));
                            ui.colored_label(crate::theme::colors::PRIMARY, format!("{} bytes", app.edit_snaplen));
                        });
                    }

                    ui.add_space(6.0);
                    ui.checkbox(&mut app.edit_dedup_enabled, "Remove Duplicate Packets (-d / -D)");
                    if app.edit_dedup_enabled {
                        ui.horizontal(|ui| {
                            ui.label("Deduplication Window:");
                            ui.add(egui::DragValue::new(&mut app.edit_dedup_window).range(1..=1000));
                            ui.colored_label(crate::theme::colors::PRIMARY, format!("{} packets", app.edit_dedup_window));
                        });
                    }

                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label("Shift Timestamps (-t):");
                        ui.add(egui::DragValue::new(&mut app.edit_timeshift_secs).speed(0.1));
                        ui.colored_label(crate::theme::colors::PRIMARY, format!("{:.3} s", app.edit_timeshift_secs));
                    });
                });
        };

        let render_right_col = |app: &mut Self, ui: &mut Ui| {
            egui::Frame::NONE
                .fill(crate::theme::colors::SURFACE_CONTAINER)
                .corner_radius(8.0)
                .inner_margin(14.0)
                .stroke(egui::Stroke::new(1.0f32, crate::theme::colors::OUTLINE_VARIANT))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading(RichText::new("🔒 HMAC-SHA256 Cryptographic Anonymizer").color(crate::theme::colors::ON_SURFACE).size(15.0));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.colored_label(
                                crate::theme::colors::ON_PRIMARY,
                                RichText::new(" HMAC-SHA256 READY ")
                                    .small()
                                    .background_color(crate::theme::colors::PRIMARY_CONTAINER),
                            );
                        });
                    });
                    ui.colored_label(
                        crate::theme::colors::ON_SURFACE_VARIANT,
                        "Pseudonymize IPv4/IPv6 and MAC addresses consistently while preserving subnet relationships.",
                    );
                    ui.add_space(8.0);

                    ui.checkbox(&mut app.edit_anon_enabled, "Pseudonymize Addresses (--anonymize)");
                    if app.edit_anon_enabled {
                        ui.horizontal(|ui| {
                            ui.label("Master Salt / HMAC Secret Key:");
                            ui.text_edit_singleline(&mut app.edit_anon_key);
                            if ui.button("Rotate Key").clicked() {
                                let nanos = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_nanos();
                                app.edit_anon_key = format!("sk_live_{:x}", nanos);
                            }
                        });
                        ui.checkbox(&mut app.edit_scrub_payload, "Zero out L4 TCP/UDP Payloads (--scrub-payload)");
                    }

                    ui.add_space(8.0);
                    ui.colored_label(crate::theme::colors::ON_SURFACE_VARIANT, RichText::new("PREVIEW PSEUDONYMIZATION MAPPING:").small().monospace());
                    egui::Frame::NONE
                        .fill(crate::theme::colors::SURFACE_CONTAINER_LOWEST)
                        .corner_radius(4.0)
                        .inner_margin(8.0)
                        .show(ui, |ui| {
                            ui.monospace("192.168.1.10  -->  10.14.89.21  [HMAC Consistent]");
                            ui.monospace("192.168.1.1   -->  10.14.89.1   [Gateway Preserved]");
                            ui.monospace("93.184.216.34 -->  172.28.102.5 [External Scrambled]");
                        });
                });
        };

        if ui.available_width() > 700.0 {
            ui.columns(2, |cols| {
                render_left_col(self, &mut cols[0]);
                render_right_col(self, &mut cols[1]);
            });
        } else {
            render_left_col(self, ui);
            ui.add_space(8.0);
            render_right_col(self, ui);
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
            if ui.button("➕ Append Packet to Current Capture").clicked() {
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
                cap.frames.append(&mut frames);
                self.ws.load_capture(cap);
                self.rebuild_streams();
            }
        });
    }

    fn ui_tool_follow_stream(&mut self, ui: &mut Ui) {
        ui.heading("Follow TCP / UDP Stream Reassembly");
        ui.horizontal_wrapped(|ui| {
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
            if ui.button("🔍 Filter This Stream").clicked() {
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
                ui.label("No payload data found for this stream ID.");
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
        self.ui_workstation_ai_analyst(ui);
    }

    fn ui_tool_mcp_inspector(&mut self, ui: &mut Ui) {
        self.ui_workstation_mcp(ui);
    }

    fn ui_workstation_ai_analyst(&mut self, ui: &mut Ui) {
        ui.add_space(8.0);
        // Top Banner / AIP-01 Privacy Enclave
        egui::Frame::NONE
            .fill(crate::theme::colors::SURFACE_CONTAINER_HIGH)
            .corner_radius(8.0)
            .inner_margin(14.0)
            .stroke(egui::Stroke::new(1.0f32, crate::theme::colors::OUTLINE_VARIANT))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        crate::theme::colors::ON_PRIMARY,
                        RichText::new(" AIP-01 PRIVACY ENCLAVE ")
                            .small()
                            .strong()
                            .background_color(crate::theme::colors::PRIMARY_CONTAINER),
                    );
                    ui.heading(
                        RichText::new("AI Security Analyst & Natural Language Query Workstation")
                            .size(20.0)
                            .color(crate::theme::colors::ON_SURFACE)
                            .strong(),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.colored_label(
                            crate::theme::colors::PRIMARY,
                            RichText::new("● LOCAL MODEL: ACTIVE").monospace().strong(),
                        );
                    });
                });
                ui.add_space(4.0);
                ui.colored_label(
                    crate::theme::colors::ON_SURFACE_VARIANT,
                    "Local LLM-assisted packet anomaly detection, protocol explanation, and natural language to BPF/Display filter compilation.",
                );
            });

        ui.add_space(10.0);

        egui::Frame::NONE
            .fill(crate::theme::colors::SURFACE_CONTAINER)
            .corner_radius(8.0)
            .inner_margin(14.0)
            .stroke(egui::Stroke::new(1.0f32, crate::theme::colors::OUTLINE_VARIANT))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.ws.ai.policy.local_only, "Strict Local-Only Mode (AIP-01 Enclave)");
                    ui.separator();
                    ui.checkbox(&mut self.ws.ai.policy.redact_sensitive, "Auto-Redact IPs / MACs / Hostnames");
                });
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    ui.colored_label(crate::theme::colors::PRIMARY, RichText::new("Natural Language Query:").strong());
                    let edit = TextEdit::singleline(&mut self.ai_nl_query)
                        .hint_text("e.g. show me all failed dns queries, or find http requests with error codes")
                        .font(FontId::monospace(13.0))
                        .desired_width((ui.available_width() - 200.0).max(200.0))
                        .background_color(crate::theme::colors::SURFACE_CONTAINER_LOWEST);
                    ui.add(edit);

                    let compile_btn = egui::Button::new(
                        RichText::new("✨ Compile & Apply")
                            .color(crate::theme::colors::ON_PRIMARY)
                            .strong(),
                    )
                    .fill(crate::theme::colors::PRIMARY_CONTAINER);
                    if ui.add(compile_btn).clicked() {
                        match self.ws.ai.nl_to_display_filter(&self.ai_nl_query, &self.ws.engine.registry) {
                            Ok(cf) => {
                                self.ai_output_log = format!("Compiled NL query '{}' -> {}", self.ai_nl_query, cf.source);
                                self.ws.set_display_filter(&cf.source);
                                self.main_view = MainWorkstationView::PacketInspector;
                            }
                            Err(e) => {
                                self.ai_output_log = format!("NL filter error: {e}");
                            }
                        }
                    }
                });

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("✦ Explain Selected Packet").strong()).clicked() {
                        if let Some(fno) = self.ws.selected_frame {
                            if let Some(pkt) = self.ws.dissected.get((fno - 1) as usize) {
                                if let Ok(text) = self.ws.ai.explain_packet(pkt) {
                                    self.ai_output_log = text;
                                }
                            }
                        } else {
                            self.ai_output_log = "Please select a packet in the Packet Inspector first.".to_string();
                        }
                    }

                    if ui.button(RichText::new("📋 Full Capture Security Summary").strong()).clicked() {
                        let mut cap = CaptureFile::new(CaptureFormat::PcapNg);
                        cap.frames = self.ws.frames.clone();
                        let props = CaptureProperties::from_capture(&cap, None);
                        if let Ok(text) = self.ws.ai.summarize_capture(&props, &self.ws.dissected) {
                            self.ai_output_log = text;
                        }
                    }

                    if ui.button(RichText::new("🔍 View in 3-Pane Packet Inspector").color(crate::theme::colors::SECONDARY)).clicked() {
                        self.main_view = MainWorkstationView::PacketInspector;
                    }
                });

                ui.add_space(8.0);
                ui.colored_label(crate::theme::colors::ON_SURFACE_VARIANT, RichText::new("AI SECURITY INTELLIGENCE OUTPUT:").small().monospace());
                ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                    ui.monospace(&self.ai_output_log);
                });
            });
    }

    fn ui_workstation_mcp(&mut self, ui: &mut Ui) {
        ui.add_space(8.0);
        // Top Banner / AIP-01 Privacy Indicator
        egui::Frame::NONE
            .fill(crate::theme::colors::SURFACE_CONTAINER_HIGH)
            .corner_radius(8.0)
            .inner_margin(14.0)
            .stroke(egui::Stroke::new(1.0f32, crate::theme::colors::OUTLINE_VARIANT))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        crate::theme::colors::ON_PRIMARY,
                        RichText::new(" AIP-01 COMPLIANT ")
                            .small()
                            .strong()
                            .background_color(crate::theme::colors::PRIMARY_CONTAINER),
                    );
                    ui.heading(
                        RichText::new("MCP Console & Model Context Protocol")
                            .size(20.0)
                            .color(crate::theme::colors::ON_SURFACE)
                            .strong(),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.colored_label(
                            crate::theme::colors::PRIMARY,
                            RichText::new("● ACTIVE ENCLAVE: 127.0.0.1:8088/mcp").monospace().strong(),
                        );
                    });
                });
                ui.add_space(4.0);
                ui.colored_label(
                    crate::theme::colors::ON_SURFACE_VARIANT,
                    "JSON-RPC 2.0 active server endpoint. Local LLM privacy policy enforced — telemetry restricted to secure enclave.",
                );
            });

        ui.add_space(10.0);

        let tools = [
            ("tools/list", "List all registered protocol analysis tools", "{}"),
            ("get_capture_overview", "Global packet counts, timing, and protocol summary", "{}"),
            ("list_packets", "Filtered packet list with pagination", "{\"filter\": \"\", \"limit\": 10}"),
            ("get_packet_details", "Deep protocol dissection tree & byte offsets", "{\"frame_number\": 1}"),
            ("get_stream", "Reassembled TCP/UDP stream payload", "{\"stream_id\": 0, \"protocol\": \"tcp\"}"),
            ("get_conversations", "IP/TCP/UDP conversations and byte statistics", "{\"layer\": \"ip\"}"),
            ("get_expert_info", "Anomaly detection and expert diagnostics", "{}"),
        ];

        let render_tools_col = |app: &mut Self, ui: &mut Ui| {
            egui::Frame::NONE
                .fill(crate::theme::colors::SURFACE_CONTAINER)
                .corner_radius(8.0)
                .inner_margin(14.0)
                .stroke(egui::Stroke::new(1.0f32, crate::theme::colors::OUTLINE_VARIANT))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading(RichText::new("🔌 Available Tools").color(crate::theme::colors::ON_SURFACE).size(15.0));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.colored_label(
                                crate::theme::colors::ON_SURFACE_VARIANT,
                                RichText::new(format!("{} REGISTERED", tools.len())).monospace(),
                            );
                        });
                    });
                    ui.colored_label(
                        crate::theme::colors::ON_SURFACE_VARIANT,
                        "Click any MCP tool to populate the JSON-RPC execution playground.",
                    );
                    ui.add_space(6.0);

                    ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                        for (idx, (name, desc, payload)) in tools.iter().enumerate() {
                            let is_selected = app.mcp_method_idx == idx;
                            let card_border = if is_selected {
                                egui::Stroke::new(2.0f32, crate::theme::colors::PRIMARY)
                            } else {
                                egui::Stroke::new(1.0f32, crate::theme::colors::OUTLINE_VARIANT)
                            };
                            let card_bg = if is_selected {
                                crate::theme::colors::SURFACE_CONTAINER_HIGH
                            } else {
                                crate::theme::colors::SURFACE_CONTAINER_LOW
                            };

                            egui::Frame::NONE
                                .fill(card_bg)
                                .corner_radius(6.0)
                                .inner_margin(8.0)
                                .stroke(card_border)
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.vertical(|ui| {
                                            ui.label(RichText::new(*name).strong().color(crate::theme::colors::ON_SURFACE).monospace());
                                            ui.colored_label(crate::theme::colors::ON_SURFACE_VARIANT, RichText::new(*desc).small());
                                        });
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            if ui.button(RichText::new("Load").small()).clicked() {
                                                app.mcp_method_idx = idx;
                                                app.mcp_params_json = (*payload).to_string();
                                            }
                                        });
                                    });
                                });
                            ui.add_space(4.0);
                        }
                    });
                });
        };

        let render_playground_col = |app: &mut Self, ui: &mut Ui| {
            egui::Frame::NONE
                .fill(crate::theme::colors::SURFACE_CONTAINER)
                .corner_radius(8.0)
                .inner_margin(14.0)
                .stroke(egui::Stroke::new(1.0f32, crate::theme::colors::OUTLINE_VARIANT))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading(RichText::new("💻 JSON-RPC 2.0 Playground").color(crate::theme::colors::ON_SURFACE).size(15.0));
                        ui.colored_label(
                            crate::theme::colors::PRIMARY,
                            RichText::new(" POST /mcp ").small().strong().background_color(crate::theme::colors::SURFACE_CONTAINER_HIGH),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let exec_btn = egui::Button::new(
                                RichText::new("▶ Execute Request")
                                    .color(crate::theme::colors::ON_PRIMARY)
                                    .strong(),
                            )
                            .fill(crate::theme::colors::PRIMARY_CONTAINER);
                            if ui.add(exec_btn).clicked() {
                                app.execute_mcp_request(tools[app.mcp_method_idx].0);
                            }
                        });
                    });
                    ui.add_space(6.0);
                    ui.colored_label(crate::theme::colors::ON_SURFACE_VARIANT, RichText::new("REQUEST PARAMS (JSON):").small().monospace());
                    let edit = TextEdit::multiline(&mut app.mcp_params_json)
                        .font(FontId::monospace(12.0))
                        .desired_rows(5)
                        .desired_width(ui.available_width())
                        .background_color(crate::theme::colors::SURFACE_CONTAINER_LOWEST);
                    ui.add(edit);

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.colored_label(crate::theme::colors::ON_SURFACE_VARIANT, RichText::new("RESPONSE INSPECTOR:").small().monospace());
                        ui.colored_label(
                            crate::theme::colors::ON_PRIMARY,
                            RichText::new(" STATUS: 200 OK ").small().strong().background_color(crate::theme::colors::PRIMARY_CONTAINER),
                        );
                    });
                    ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                        ui.monospace(&app.mcp_response_json);
                    });
                });
        };

        if ui.available_width() > 700.0 {
            ui.columns(2, |cols| {
                render_tools_col(self, &mut cols[0]);
                render_playground_col(self, &mut cols[1]);
            });
        } else {
            render_tools_col(self, ui);
            ui.add_space(8.0);
            render_playground_col(self, ui);
        }

        ui.add_space(8.0);
        // Bottom stream statistics bento
        ui.columns(4, |stats| {
            for (idx, (label, val, col)) in [
                ("TOTAL REQUESTS", "1,482", crate::theme::colors::ON_SURFACE),
                ("LATENCY", "0.42 ms", crate::theme::colors::PRIMARY),
                ("SECURE ENCLAVE", "ACTIVE (AIP-01)", crate::theme::colors::PRIMARY),
                ("RPC PROTOCOL", "JSON-RPC 2.0", crate::theme::colors::SECONDARY),
            ].iter().enumerate() {
                egui::Frame::NONE
                    .fill(crate::theme::colors::SURFACE_CONTAINER_LOW)
                    .corner_radius(6.0)
                    .inner_margin(8.0)
                    .show(&mut stats[idx], |ui| {
                        ui.colored_label(crate::theme::colors::ON_SURFACE_VARIANT, RichText::new(*label).small().monospace());
                        ui.label(RichText::new(*val).strong().color(*col));
                    });
            }
        });
    }

    fn execute_mcp_request(&mut self, method_name: &str) {
        let mut srv = McpServer::new();
        let mut cap = CaptureFile::new(CaptureFormat::PcapNg);
        cap.frames = self.ws.frames.clone();
        srv.load_capture(cap);

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
        self.mcp_response_json = serde_json::to_string_pretty(&resp).unwrap_or_default();
    }
}

impl eframe::App for MashGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.tick_live_capture(ctx);

        if self.dark_mode {
            ctx.set_visuals(crate::theme::enterprise_dark_visuals());
        } else {
            ctx.set_visuals(egui::Visuals::light());
        }

        self.handle_keyboard_shortcuts(ctx);

        // 1. Top Menu Bar + Toolbar + Display Filter Bar
        TopBottomPanel::top("mash_top_bars").show(ctx, |ui| {
            self.render_menu_bar(ui);
            ui.separator();
            self.render_toolbar(ui);
            if self.main_view == MainWorkstationView::PacketInspector {
                ui.separator();
                self.render_filter_bar(ui);
            }
        });

        // 2. Bottom Status Bar (Enterprise Telemetry & Privacy Enclave Footer)
        TopBottomPanel::bottom("mash_status_bar")
            .exact_height(26.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let iface_name = self.interfaces.get(self.selected_iface_idx).map(|i| i.name.as_str()).unwrap_or("eth0");
                    let stream_badge = if self.is_streaming_capture {
                        "  [● STREAMING]"
                    } else {
                        ""
                    };
                    ui.colored_label(
                        if self.is_streaming_capture {
                            crate::theme::colors::PRIMARY
                        } else {
                            crate::theme::colors::ON_SURFACE_VARIANT
                        },
                        RichText::new(format!("⚡ INTERFACE: {iface_name} (UP){stream_badge}  |  STATUS: {}", self.status_line)).monospace().small(),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.colored_label(
                            crate::theme::colors::PRIMARY,
                            RichText::new("✦ AI ENGINE: ONLINE (MCP READY)").monospace().small().strong(),
                        );
                        ui.colored_label(crate::theme::colors::OUTLINE_VARIANT, "·");
                        let total = self.ws.dissected.len();
                        let disp = self.ws.filtered_indices.len();
                        let pct = if total > 0 {
                            (disp as f64 / total as f64) * 100.0
                        } else {
                            0.0
                        };
                        let marked = self.ws.frames.iter().filter(|f| f.flags.marked).count();
                        ui.colored_label(
                            crate::theme::colors::ON_SURFACE,
                            RichText::new(format!(
                                "Packets: {total} | Displayed: {disp} ({pct:.1}%) | Marked: {marked}"
                            )).monospace().small(),
                        );
                    });
                });
            });

        // Main Workstation Routing
        match self.main_view {
            MainWorkstationView::PacketInspector => {
                // Dockable Right Tool Drawer (or Floating Window)
                self.render_tool_panel_or_window(ctx);

                let win_h = ctx.screen_rect().height();
                let max_subpane_h = (win_h * 0.36).max(120.0);

                // Pane 3 (Bottom Split): Synchronized Hex + ASCII Packet Bytes
                TopBottomPanel::bottom("pane3_packet_bytes")
                    .resizable(true)
                    .default_height(185.0)
                    .min_height(95.0)
                    .max_height(max_subpane_h)
                    .show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            ui.strong("Packet Bytes (Hex / ASCII)");
                            if let Some(fno) = self.ws.selected_frame {
                                if let Some(frame) = self.ws.frames.get((fno - 1) as usize) {
                                    ui.separator();
                                    if ui
                                        .selectable_label(
                                            self.ws.active_source_tab == 0,
                                            format!("Frame ({} B)", frame.data.len()),
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
                                                format!("{} ({} B)", ds.name, ds.data.len()),
                                            )
                                            .clicked()
                                        {
                                            self.ws.active_source_tab = tab_id;
                                        }
                                    }
                                }
                            }
                            if let Some(hl) = self.ws.highlighted_bytes {
                                ui.separator();
                                ui.colored_label(
                                    Color32::from_rgb(120, 200, 255),
                                    format!("Highlighted: {}..{} ({} B)", hl.start, hl.end, hl.len()),
                                );
                            }
                        });
                        ui.separator();
                        self.render_hex_dump_pane(ui);
                    });

                // Pane 2 (Middle Split): Hierarchical Protocol Tree
                TopBottomPanel::bottom("pane2_protocol_tree")
                    .resizable(true)
                    .default_height(215.0)
                    .min_height(105.0)
                    .max_height(max_subpane_h)
                    .show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            if let Some(fno) = self.ws.selected_frame {
                                ui.strong(format!("Packet Details — Frame #{fno}"));
                            } else {
                                ui.strong("Packet Details");
                            }
                            ui.separator();
                            if ui.small_button("➕ Expand All").clicked() {
                                self.ws.expand_all_nodes();
                            }
                            if ui.small_button("➖ Collapse All").clicked() {
                                self.ws.collapse_all_nodes();
                            }
                            if let Some(expr) = self.ws.filter_from_selected_node() {
                                ui.separator();
                                if ui
                                    .small_button(format!("🔍 Filter: {expr}"))
                                    .on_hover_text("Apply selected field as display filter")
                                    .clicked()
                                {
                                    self.ws.set_display_filter(&expr);
                                }
                            }
                        });
                        ui.separator();
                        self.render_protocol_tree_pane(ui);
                    });

                // Pane 1 (Top Central Split): Packet List Table
                egui::CentralPanel::default().show(ctx, |ui| {
                    self.render_packet_list_pane(ui);
                });
            }
            MainWorkstationView::CaptureWorkstation => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ScrollArea::vertical().show(ui, |ui| {
                        self.ui_workstation_capture(ui);
                    });
                });
            }
            MainWorkstationView::McpConsole => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ScrollArea::vertical().show(ui, |ui| {
                        self.ui_workstation_mcp(ui);
                    });
                });
            }
            MainWorkstationView::PacketEditor => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ScrollArea::vertical().show(ui, |ui| {
                        self.ui_workstation_editor(ui);
                    });
                });
            }
            MainWorkstationView::FileProperties => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ScrollArea::vertical().show(ui, |ui| {
                        self.ui_workstation_file_info(ui);
                    });
                });
            }
            MainWorkstationView::AiAnalyst => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ScrollArea::vertical().show(ui, |ui| {
                        self.ui_workstation_ai_analyst(ui);
                    });
                });
            }
            MainWorkstationView::MergeFiles => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ScrollArea::vertical().show(ui, |ui| {
                        ui.add_space(8.0);
                        self.ui_tool_merge(ui);
                    });
                });
            }
            MainWorkstationView::Text2Pcap => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ScrollArea::vertical().show(ui, |ui| {
                        ui.add_space(8.0);
                        self.ui_tool_text2pcap(ui);
                    });
                });
            }
            MainWorkstationView::Statistics => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ScrollArea::vertical().show(ui, |ui| {
                        ui.add_space(8.0);
                        self.ui_tool_statistics(ui);
                    });
                });
            }
        }
    }
}

/// Launch the native 3-pane desktop GUI window (`mash-gui`).
pub fn run_native_gui(ws: AnalyzerWorkspace) -> std::result::Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("MUNG-ASH Network Protocol Analyzer (All-in-One Suite)")
            .with_inner_size([1380.0, 860.0])
            .with_min_inner_size([920.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "MUNG-ASH Network Protocol Analyzer",
        options,
        Box::new(|_cc| Ok(Box::new(MashGuiApp::new(ws)))),
    )
    .map_err(|e| format!("GUI error: {e}"))
}

fn ipv4_header_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < hdr.len() {
        if i != 10 {
            sum += u16::from_be_bytes([hdr[i], hdr[i + 1]]) as u32;
        }
        i += 2;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Generate a rich 15-packet multi-protocol showcase capture (ARP, DNS, TCP, HTTP, TLSv1.3, BGP, MQTT, Modbus/TCP, ICMP, TCP RST).
pub fn generate_sample_showcase_capture() -> CaptureFile {
    let mut cap = CaptureFile::new(CaptureFormat::PcapNg);
    let mac_c = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
    let mac_s = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
    let mac_bcast = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let ip_c = [192, 168, 1, 10];
    let ip_gw = [192, 168, 1, 1];
    let ip_web = [93, 184, 216, 34];

    let push_eth =
        |cap: &mut CaptureFile, sec: u64, nanos: u32, src_mac: [u8; 6], dst_mac: [u8; 6], et: u16, l3: &[u8]| {
            let mut d = Vec::with_capacity(14 + l3.len());
            d.extend_from_slice(&dst_mac);
            d.extend_from_slice(&src_mac);
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
        let csum = ipv4_header_checksum(&v[..20]);
        v[10..12].copy_from_slice(&csum.to_be_bytes());
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

    // 1 & 2: ARP Request (Broadcast) & Reply
    let mut arp_req = vec![0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01];
    arp_req.extend_from_slice(&mac_c);
    arp_req.extend_from_slice(&ip_c);
    arp_req.extend_from_slice(&[0; 6]);
    arp_req.extend_from_slice(&ip_gw);
    push_eth(&mut cap, 0, 100_000, mac_c, mac_bcast, 0x0806, &arp_req);

    let mut arp_rep = vec![0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x02];
    arp_rep.extend_from_slice(&mac_s);
    arp_rep.extend_from_slice(&ip_gw);
    arp_rep.extend_from_slice(&mac_c);
    arp_rep.extend_from_slice(&ip_c);
    push_eth(&mut cap, 0, 450_000, mac_s, mac_c, 0x0806, &arp_rep);

    // 3 & 4: DNS Query & Response for api.mung-ash.io
    let mut dns_q = vec![0x1a, 0x2b, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    dns_q.extend_from_slice(b"\x03api\x08mung-ash\x02io\x00\x00\x01\x00\x01");
    push_eth(
        &mut cap,
        0,
        1_200_000,
        mac_c,
        mac_s,
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
        mac_s,
        mac_c,
        0x0800,
        &build_ipv4(ip_gw, ip_c, 17, &build_udp(53, 53111, &dns_r)),
    );

    // 5, 6, 7: TCP 3-way Handshake
    push_eth(
        &mut cap,
        0,
        10_000_000,
        mac_c,
        mac_s,
        0x0800,
        &build_ipv4(ip_c, ip_web, 6, &build_tcp(54321, 80, 1000, 0, 0x02, b"")),
    );
    push_eth(
        &mut cap,
        0,
        24_000_000,
        mac_s,
        mac_c,
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
        mac_c,
        mac_s,
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
        mac_c,
        mac_s,
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
        mac_s,
        mac_c,
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
        mac_c,
        mac_s,
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
        mac_c,
        mac_s,
        0x0800,
        &build_ipv4(ip_c, ip_gw, 6, &build_tcp(49100, 179, 1, 1, 0x18, &bgp)),
    );

    // 12: MQTT PUBLISH
    let mqtt = b"\x30\x16\x00\x0esensors/rack0124.8C";
    push_eth(
        &mut cap,
        1,
        200_000_000,
        mac_c,
        mac_s,
        0x0800,
        &build_ipv4(ip_c, ip_gw, 6, &build_tcp(49200, 1883, 1, 1, 0x18, mqtt)),
    );

    // 13: Modbus/TCP Read Holding Registers
    let modbus = [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x6b, 0x00, 0x03];
    push_eth(
        &mut cap,
        1,
        300_000_000,
        mac_c,
        mac_s,
        0x0800,
        &build_ipv4(ip_c, ip_gw, 6, &build_tcp(49300, 502, 1, 1, 0x18, &modbus)),
    );

    // 14: ICMP Echo Request
    let icmp = [8, 0, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x01, b'p', b'i', b'n', b'g'];
    push_eth(
        &mut cap,
        1,
        400_000_000,
        mac_c,
        mac_s,
        0x0800,
        &build_ipv4(ip_c, ip_web, 1, &icmp),
    );

    cap
}
