use mash_ai::{
    AiEngine, AiPrivacyPolicy, BuiltInHeuristicProvider, ConfigurableProvider, LlmProvider,
    PayloadScope,
};
use mash_capture::{capture_frames, list_capture_interfaces, CaptureOptions};
use mash_cli::tui::TuiApp;
use mash_cli::{
    export_ek_lines, export_pdml, export_psml, format_fields_row, format_hexdump,
    format_summary_line, format_tree_text,
};
use mash_core::{
    ByteRange, FieldId, FieldType, FieldValue, NameResolver, ProtocolId, ResolutionConfig,
};
use mash_crypto::{TlsKeyStore, TlsStreamDecryptor};
use mash_dissect::ConversationTracker;
use mash_filter::CompiledFilter;
use mash_pcapfile::{write_capture_file, CaptureFile, CaptureFormat};
use mash_protocols::build_default_engine;
use mash_reassembly::{ReassembledStream, StreamDisplayFormat};
use mash_stats::{
    analyze_tcp_flows, build_protocol_hierarchy, compute_conversations, compute_endpoints,
    compute_io_graph, compute_packet_length_distribution, extract_http_objects,
    summarize_expert_info, CaptureProperties, ConversationLayer,
};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use std::sync::Arc;

fn print_help() {
    println!("mash {} — Memory-Safe Network Protocol Analyzer CLI", env!("CARGO_PKG_VERSION"));
    println!("Usage: mash [OPTIONS]");
    println!("Capture & File I/O:");
    println!("  -D                              List available capture interfaces");
    println!("  -i <interface>                  Capture live packets from interface (or udp://host:port)");
    println!("  -f <bpf-filter>                 Capture-time BPF filter expression");
    println!("  -c <count>                      Stop after capturing <count> packets");
    println!("  -r <infile>                     Read packets from capture file (.pcap/.pcapng/.gz/.lz4)");
    println!("  -w <outfile>                    Write filtered packets to output file");
    println!("  -F <pcap|pcapng>                Output capture file format (default: pcapng)");
    println!("  --gui                           Launch unified 3-pane Desktop GUI (mash-gui)");
    println!("  --tui                           Launch interactive 3-pane terminal UI");
    println!("  --tui-once                      Render single 3-pane TUI frame to stdout and exit");
    println!("Filtering & Dissection:");
    println!("  -Y, -R <display-filter>         Apply display/read filter expression");
    println!("  -d <selector>,<proto>           Decode As override (e.g. tcp.port==8443,http)");
    println!("  -n                              Disable network/port name resolution");
    println!("  -N <flags>                      Enable specific resolution flags (m=MAC, n=IP, t=Port, d=DNS)");
    println!("  -o tls.keylog_file:<path>       Load TLS key log file for decryption");
    println!("Output & Export:");
    println!("  -V                              Verbose output (full dissected protocol tree)");
    println!("  -x                              Print hex and ASCII packet dump");
    println!("  -q                              Quiet (suppress per-packet output)");
    println!("  -T <fields|json|ek|pdml|psml|csv|tabs>  Structured output format");
    println!("  -e <field>                      Field to extract with -T fields (repeatable)");
    println!("  -E <header=y|separator=,|quote=d>       Formatting options for -T fields");
    println!("  -z <stat>                       Statistics report (io,phs | io,stat | conv,ip | conv,tcp | endpoints,ip | plen | expert | follow,tcp,ascii,0)");
    println!("  --export-objects http,<dir>     Export reconstructed HTTP objects to <dir>");
    println!("  -G <fields|protocols>           Dump registered protocol or field catalog");
    println!("AI Assistant:");
    println!("  --ai-explain <frame_no>         Explain a specific packet using the configured AI provider");
    println!("  --ai-filter <natural_query>     Compile a natural-language query into a validated display filter");
    println!("  --ai-summary                    Generate an AI capture summary and anomaly report");
    println!("  --ai-provider <local|ollama|gemini|anthropic|openai>  Select AI provider");
    println!("  --ai-model <model>              Model name for AI requests");
    println!("  --ai-local-only                 Strictly block non-local AI endpoints (AIP-01)");
    println!("  --ai-no-redact                  Disable automatic IP/MAC/hostname redaction");
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        print_help();
        return;
    }

    let mut engine = build_default_engine();
    let mut read_path: Option<String> = None;
    let mut live_iface: Option<String> = None;
    let mut live_bpf: Option<String> = None;
    let mut live_count: Option<u64> = None;
    let mut tui_mode = false;
    let mut tui_once = false;
    let mut write_path: Option<String> = None;
    let mut out_format: Option<CaptureFormat> = None;
    let mut filter_str: Option<String> = None;
    let mut verbose = false;
    let mut hexdump = false;
    let mut quiet = false;
    let mut out_type: Option<String> = None;
    let mut extract_fields: Vec<String> = Vec::new();
    let mut field_header = false;
    let mut field_sep = "\t".to_string();
    let mut field_quote: Option<char> = None;
    let mut stats_specs: Vec<String> = Vec::new();
    let mut export_objects_spec: Option<String> = None;
    let mut res_cfg = ResolutionConfig::default();
    let mut tls_keys = TlsKeyStore::new();

    let mut ai_explain_frame: Option<u64> = None;
    let mut ai_filter_query: Option<String> = None;
    let mut ai_summary = false;
    let mut ai_provider_name = "local".to_string();
    let mut ai_model = "mash-local-v1".to_string();
    let mut ai_local_only = false;
    let mut ai_redact = true;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "-D" => {
                for (idx, iface) in list_capture_interfaces().iter().enumerate() {
                    println!(
                        "{}. {} ({})",
                        idx + 1,
                        iface.name,
                        iface.description.as_deref().unwrap_or(iface.link_type.name())
                    );
                }
                return;
            }
            "-G" => {
                let kind = args.get(i + 1).map(|s| s.as_str()).unwrap_or("protocols");
                if kind == "fields" {
                    for f in engine.registry.fields() {
                        println!("F\t{}\t{}\t{:?}", f.name, f.abbrev, f.field_type);
                    }
                } else {
                    for p in engine.registry.protocols() {
                        println!("{}\t{}\t{}", p.name, p.short_name, p.filter_name);
                    }
                }
                return;
            }
            "-r" => {
                if let Some(p) = args.get(i + 1) {
                    read_path = Some(p.clone());
                    i += 2;
                    continue;
                }
            }
            "-i" => {
                if let Some(ifc) = args.get(i + 1) {
                    live_iface = Some(ifc.clone());
                    i += 2;
                    continue;
                }
            }
            "-f" => {
                if let Some(bpf) = args.get(i + 1) {
                    live_bpf = Some(bpf.clone());
                    i += 2;
                    continue;
                }
            }
            "-c" => {
                if let Some(cnt) = args.get(i + 1).and_then(|s| s.parse::<u64>().ok()) {
                    live_count = Some(cnt);
                    i += 2;
                    continue;
                }
            }
            "--gui" => {
                let fwd: Vec<String> = args.iter().filter(|a| a.as_str() != "--gui").cloned().collect();
                let gui_exe = env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(|d| d.join(if cfg!(windows) { "mash-gui.exe" } else { "mash-gui" })))
                    .filter(|p| p.exists())
                    .unwrap_or_else(|| std::path::PathBuf::from("mash-gui"));
                let status = std::process::Command::new(gui_exe).args(&fwd).status();
                if let Err(e) = status {
                    eprintln!("mash: failed to launch mash-gui: {e}");
                    std::process::exit(1);
                }
                return;
            }
            "--tui" => tui_mode = true,
            "--tui-once" => tui_once = true,
            "-w" => {
                if let Some(p) = args.get(i + 1) {
                    write_path = Some(p.clone());
                    i += 2;
                    continue;
                }
            }
            "-F" => {
                if let Some(fmt) = args.get(i + 1) {
                    out_format = match fmt.as_str() {
                        "pcap" => Some(CaptureFormat::PcapMicros),
                        "nsec" | "pcap-ns" => Some(CaptureFormat::PcapNanos),
                        _ => Some(CaptureFormat::PcapNg),
                    };
                    i += 2;
                    continue;
                }
            }
            "-Y" | "-R" => {
                if let Some(f) = args.get(i + 1) {
                    filter_str = Some(f.clone());
                    i += 2;
                    continue;
                }
            }
            "-d" => {
                if let Some(spec) = args.get(i + 1) {
                    if let Err(e) = engine.decode_as.parse_and_insert(spec) {
                        eprintln!("mash: {e}");
                        std::process::exit(2);
                    }
                    i += 2;
                    continue;
                }
            }
            "-n" => {
                res_cfg = ResolutionConfig::disabled();
            }
            "-N" => {
                if let Some(flags) = args.get(i + 1) {
                    res_cfg.resolve_mac = flags.contains('m');
                    res_cfg.resolve_network = flags.contains('n');
                    res_cfg.resolve_transport = flags.contains('t');
                    res_cfg.use_captured_dns = flags.contains('d');
                    i += 2;
                    continue;
                }
            }
            "-o" => {
                if let Some(opt) = args.get(i + 1) {
                    if let Some(path) = opt.strip_prefix("tls.keylog_file:") {
                        if let Err(e) = tls_keys.load_keylog_file(path) {
                            eprintln!("mash: failed to load TLS keylog '{path}': {e}");
                            std::process::exit(1);
                        }
                    }
                    i += 2;
                    continue;
                }
            }
            "-V" => verbose = true,
            "-x" => hexdump = true,
            "-q" => quiet = true,
            "-T" => {
                if let Some(t) = args.get(i + 1) {
                    out_type = Some(t.to_ascii_lowercase());
                    i += 2;
                    continue;
                }
            }
            "-e" => {
                if let Some(f) = args.get(i + 1) {
                    extract_fields.push(f.clone());
                    i += 2;
                    continue;
                }
            }
            "-E" => {
                if let Some(spec) = args.get(i + 1) {
                    if let Some((k, v)) = spec.split_once('=') {
                        match k {
                            "header" => field_header = v == "y" || v == "yes" || v == "true",
                            "separator" => {
                                field_sep = match v {
                                    "/t" | "\\t" => "\t".to_string(),
                                    "/s" => " ".to_string(),
                                    other => other.to_string(),
                                }
                            }
                            "quote" => {
                                field_quote = match v {
                                    "d" => Some('"'),
                                    "s" => Some('\''),
                                    _ => None,
                                }
                            }
                            _ => {}
                        }
                    }
                    i += 2;
                    continue;
                }
            }
            "-z" => {
                if let Some(s) = args.get(i + 1) {
                    stats_specs.push(s.clone());
                    i += 2;
                    continue;
                }
            }
            "--export-objects" => {
                if let Some(s) = args.get(i + 1) {
                    export_objects_spec = Some(s.clone());
                    i += 2;
                    continue;
                }
            }
            "--ai-explain" => {
                if let Some(n) = args.get(i + 1).and_then(|s| s.parse::<u64>().ok()) {
                    ai_explain_frame = Some(n);
                    i += 2;
                    continue;
                }
            }
            "--ai-filter" => {
                if let Some(q) = args.get(i + 1) {
                    ai_filter_query = Some(q.clone());
                    i += 2;
                    continue;
                }
            }
            "--ai-summary" => ai_summary = true,
            "--ai-provider" => {
                if let Some(p) = args.get(i + 1) {
                    ai_provider_name = p.to_ascii_lowercase();
                    i += 2;
                    continue;
                }
            }
            "--ai-model" => {
                if let Some(m) = args.get(i + 1) {
                    ai_model = m.clone();
                    i += 2;
                    continue;
                }
            }
            "--ai-local-only" => ai_local_only = true,
            "--ai-no-redact" => ai_redact = false,
            _ => {}
        }
        i += 1;
    }

    // Build AI Engine
    let provider: Arc<dyn LlmProvider> = match ai_provider_name.as_str() {
        "ollama" => Arc::new(ConfigurableProvider::local_ollama("http://127.0.0.1:11434")),
        "gemini" => Arc::new(ConfigurableProvider::gemini(
            env::var("GEMINI_API_KEY").unwrap_or_default(),
        )),
        "anthropic" => Arc::new(ConfigurableProvider::anthropic(
            env::var("ANTHROPIC_API_KEY").unwrap_or_default(),
        )),
        "openai" => Arc::new(ConfigurableProvider::openai_compatible(
            "https://api.openai.com/v1",
            env::var("OPENAI_API_KEY").ok(),
        )),
        _ => Arc::new(BuiltInHeuristicProvider::new()),
    };
    let mut ai_engine = AiEngine::new(
        provider,
        ai_model,
        AiPrivacyPolicy {
            local_only: ai_local_only,
            redact_sensitive: ai_redact,
            payload_scope: PayloadScope::HeadersOnly,
        },
    );

    // Handle standalone `--ai-filter` if no capture file was given
    if let Some(nl_q) = &ai_filter_query {
        match ai_engine.nl_to_display_filter(nl_q, &engine.registry) {
            Ok(compiled) => {
                if read_path.is_none() {
                    println!("{}", compiled.source);
                    return;
                }
                filter_str = Some(compiled.source);
            }
            Err(e) => {
                eprintln!("mash: AI filter compilation error: {e}");
                std::process::exit(2);
            }
        }
    }

    let compiled_filter = match &filter_str {
        Some(f) => match CompiledFilter::compile(f, Some(&engine.registry)) {
            Ok(c) => c,
            Err(diag) => {
                eprintln!("mash: {diag}");
                std::process::exit(2);
            }
        },
        None => CompiledFilter::compile("", None).unwrap(),
    };

    let (cap, raw_bytes_opt, source_title) = if let Some(infile) = read_path {
        let raw_bytes = match fs::read(&infile) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("mash: failed to read '{infile}': {e}");
                std::process::exit(1);
            }
        };
        let c = match mash_pcapfile::read_capture_bytes(&raw_bytes) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("mash: invalid capture file '{infile}': {e}");
                std::process::exit(1);
            }
        };
        (c, Some(raw_bytes), infile)
    } else if let Some(iface) = live_iface {
        let opts = CaptureOptions {
            interfaces: vec![iface.clone()],
            bpf_filter: live_bpf,
            max_packets: Some(live_count.unwrap_or(10)),
            ..CaptureOptions::default()
        };
        let frames = match capture_frames(&opts) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("mash: live capture failed on '{iface}': {e}");
                std::process::exit(1);
            }
        };
        let mut c = CaptureFile::new(CaptureFormat::PcapNg);
        c.frames = frames;
        (c, None, format!("live:{iface}"))
    } else {
        eprintln!("mash: no input file or interface specified (use -r <file>, -i <iface>, or --help)");
        std::process::exit(1);
    };

    for warn in &cap.warnings {
        eprintln!(
            "mash: warning at byte offset {}: {}",
            warn.byte_offset, warn.message
        );
    }
    for dsb in &cap.decryption_secrets {
        if let Ok(s) = std::str::from_utf8(&dsb.data) {
            tls_keys.parse_keylog_str(s);
        }
    }

    let mut resolver = NameResolver::new(res_cfg);
    cap.populate_name_resolver(&mut resolver);
    let mut conv = ConversationTracker::new();

    let first_ts = cap.frames.first().map(|f| f.timestamp);
    let mut prev_ts = None;
    let mut all_dissected = Vec::with_capacity(cap.frames.len());
    let mut tcp_streams: BTreeMap<u32, ReassembledStream> = BTreeMap::new();
    let mut udp_streams: BTreeMap<u32, ReassembledStream> = BTreeMap::new();
    let mut tls_decryptors: BTreeMap<u32, TlsStreamDecryptor> = BTreeMap::new();

    for frame in &cap.frames {
        let mut pkt = engine.dissect_frame(frame, first_ts, prev_ts, &mut resolver, &mut conv);
        prev_ts = Some(frame.timestamp);

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
            let tcp_node = pkt.tree.by_abbrev("tcp").next();
            let payload_start = tcp_node.map(|n| n.byte_range.end).unwrap_or(frame.data.len());
            let payload = frame.data.get(payload_start..).unwrap_or(&[]);
            tcp_streams
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

            if !tls_keys.is_empty() && !payload.is_empty() {
                let dec_records = tls_decryptors
                    .entry(sid)
                    .or_default()
                    .process_tcp_payload(&pkt.summary.source, sport, payload, &tls_keys);
                for rec in dec_records {
                    let preview = String::from_utf8_lossy(&rec.plaintext)
                        .lines()
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    let label = format!(
                        "Decrypted TLS Record #{} (type={}, {} bytes): {}",
                        rec.record_index,
                        rec.inner_content_type,
                        rec.plaintext.len(),
                        preview
                    );
                    let (tls_root, tls_pid) = pkt
                        .tree
                        .by_abbrev("tls")
                        .next()
                        .map(|n| (Some(n.id), n.protocol_id))
                        .unwrap_or((None, ProtocolId(0)));
                    let _ = pkt.tree.add_node(
                        tls_root,
                        FieldId(0),
                        tls_pid,
                        "tls.decrypted.data",
                        "Decrypted TLS Data",
                        label,
                        FieldType::Bytes,
                        FieldValue::Bytes(rec.plaintext),
                        ByteRange::new(payload_start, frame.data.len()),
                        true,
                    );
                    if !preview.is_empty() {
                        pkt.summary.info = format!("{} [Decrypted: {preview}]", pkt.summary.info);
                    }
                }
            }
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
            let udp_node = pkt.tree.by_abbrev("udp").next();
            let payload_start = udp_node.map(|n| n.byte_range.end).unwrap_or(frame.data.len());
            let payload = frame.data.get(payload_start..).unwrap_or(&[]);
            udp_streams
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

        all_dissected.push(pkt);
    }

    let _ = analyze_tcp_flows(&mut all_dissected);

    let mut matched_packets = Vec::new();
    let mut matched_frames = Vec::new();
    for (frame, pkt) in cap.frames.iter().zip(all_dissected) {
        if compiled_filter.matches(&pkt) {
            matched_frames.push(frame.clone());
            matched_packets.push(pkt);
        }
    }

    // Write filtered capture if `-w` specified
    if let Some(out_file) = &write_path {
        let mut out_cap = CaptureFile::new(out_format.unwrap_or(cap.format));
        out_cap.interfaces = cap.interfaces.clone();
        out_cap.frames = matched_frames.clone();
        if let Err(e) = write_capture_file(out_file, &out_cap) {
            eprintln!("mash: failed to write '{out_file}': {e}");
            std::process::exit(1);
        }
    }

    // Export HTTP objects if `--export-objects http,<dir>` specified
    if let Some(spec) = &export_objects_spec {
        if let Some((proto, dir_str)) = spec.split_once(',') {
            if proto.eq_ignore_ascii_case("http") {
                let dir = Path::new(dir_str);
                let _ = fs::create_dir_all(dir);
                let objs = extract_http_objects(&cap.frames, &matched_packets);
                for obj in objs {
                    let target = dir.join(&obj.filename);
                    let _ = fs::write(target, &obj.data);
                }
            }
        }
    }

    // Handle `--ai-explain <frame_no>`
    if let Some(fno) = ai_explain_frame {
        if let Some(pkt) = matched_packets.iter().find(|p| p.summary.number == fno) {
            match ai_engine.explain_packet(pkt) {
                Ok(text) => println!("{text}"),
                Err(e) => {
                    eprintln!("mash: AI error: {e}");
                    std::process::exit(1);
                }
            }
            return;
        }
    }

    // Handle `--ai-summary`
    if ai_summary {
        let props = CaptureProperties::from_capture(&cap, raw_bytes_opt.as_deref());
        match ai_engine.summarize_capture(&props, &matched_packets) {
            Ok(text) => println!("{text}"),
            Err(e) => {
                eprintln!("mash: AI error: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // Handle `--tui` / `--tui-once`
    if tui_once || tui_mode {
        let mut app = TuiApp::new(
            source_title,
            matched_frames,
            matched_packets,
            filter_str.clone(),
        );
        if tui_once {
            print!("{}", app.render_snapshot(100));
        } else {
            app.run_interactive(&engine.registry);
        }
        return;
    }

    // Render per-packet output unless `-q` or `-w` (without `-V`/`-T`)
    if !quiet && write_path.is_none() {
        match out_type.as_deref() {
            Some("json") => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&matched_packets).unwrap_or_default()
                );
            }
            Some("ek") => {
                for pkt in &matched_packets {
                    print!("{}", export_ek_lines(pkt));
                }
            }
            Some("pdml") => {
                print!("{}", export_pdml(&matched_packets));
            }
            Some("psml") => {
                print!("{}", export_psml(&matched_packets));
            }
            Some("fields") => {
                if field_header {
                    println!("{}", extract_fields.join(&field_sep));
                }
                for pkt in &matched_packets {
                    println!(
                        "{}",
                        format_fields_row(pkt, &extract_fields, &field_sep, field_quote)
                    );
                }
            }
            Some("csv") => {
                println!("No.,Time,Source,Destination,Protocol,Length,Info");
                for pkt in &matched_packets {
                    let s = &pkt.summary;
                    println!(
                        "{},{:.6},\"{}\",\"{}\",\"{}\",{},\"{}\"",
                        s.number,
                        s.rel_time_sec,
                        s.source,
                        s.destination,
                        s.protocol,
                        s.length,
                        s.info.replace('"', "\"\"")
                    );
                }
            }
            _ => {
                for pkt in &matched_packets {
                    println!("{}", format_summary_line(pkt));
                    if verbose {
                        print!("{}", format_tree_text(&pkt.tree));
                    }
                    if hexdump {
                        if let Some(f) = cap
                            .frames
                            .get((pkt.summary.number.saturating_sub(1)) as usize)
                        {
                            print!("{}", format_hexdump(&f.data));
                        }
                    }
                }
            }
        }
    }

    // Execute `-z <stat>` reports
    for stat in &stats_specs {
        let s = stat.as_str();
        if s == "io,phs" {
            let phs = build_protocol_hierarchy(&matched_packets);
            print!("{}", phs.format_table());
        } else if s.starts_with("io,stat") {
            let interval = s
                .split(',')
                .nth(2)
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(1.0);
            let buckets = compute_io_graph(&matched_packets, interval);
            println!("=== I/O Statistics (interval: {interval:.3}s) ===");
            for b in buckets {
                println!(
                    "{:>8.3} - {:>8.3}s  {:>7} pkts  {:>10} bytes  {:>12.2} bits/s",
                    b.start_sec, b.end_sec, b.packets, b.bytes, b.bits_per_sec
                );
            }
        } else if let Some(layer_name) = s.strip_prefix("conv,") {
            let layer = match layer_name {
                "eth" => ConversationLayer::Ethernet,
                "ipv6" => ConversationLayer::Ipv6,
                "tcp" => ConversationLayer::Tcp,
                "udp" => ConversationLayer::Udp,
                _ => ConversationLayer::Ipv4,
            };
            let rows = compute_conversations(&matched_packets, layer);
            println!("=== Conversations ({layer_name}) ===");
            for r in rows {
                println!(
                    "{:<22} <-> {:<22}  {:>6} pkts  {:>10} bytes  ({:.3}s)",
                    r.addr_a,
                    r.addr_b,
                    r.total_packets,
                    r.total_bytes,
                    r.duration_sec()
                );
            }
        } else if let Some(layer_name) = s.strip_prefix("endpoints,") {
            let layer = match layer_name {
                "eth" => ConversationLayer::Ethernet,
                "ipv6" => ConversationLayer::Ipv6,
                "tcp" => ConversationLayer::Tcp,
                "udp" => ConversationLayer::Udp,
                _ => ConversationLayer::Ipv4,
            };
            let rows = compute_endpoints(&matched_packets, layer);
            println!("=== Endpoints ({layer_name}) ===");
            for r in rows {
                println!(
                    "{:<24} TX: {:>6} pkts ({:>9} B)  RX: {:>6} pkts ({:>9} B)",
                    r.address, r.tx_packets, r.tx_bytes, r.rx_packets, r.rx_bytes
                );
            }
        } else if s == "plen" {
            let buckets = compute_packet_length_distribution(&matched_packets);
            println!("=== Packet Lengths ===");
            for b in buckets {
                println!("{:<12} {:>8} ({:>6.2}%)", b.label, b.count, b.percentage);
            }
        } else if s == "expert" {
            let rows = summarize_expert_info(&matched_packets);
            println!("=== Expert Information ===");
            for r in rows {
                println!(
                    "[{:<7} / {:<10}] {:<8} {:>5}x  {}",
                    r.severity.as_str(),
                    r.group.as_str(),
                    r.protocol,
                    r.count,
                    r.summary
                );
            }
        } else if let Some(rest) = s.strip_prefix("follow,") {
            let parts: Vec<&str> = rest.split(',').collect();
            let proto = parts.first().copied().unwrap_or("tcp");
            let mode_str = parts.get(1).copied().unwrap_or("ascii");
            let sid = parts
                .get(2)
                .and_then(|x| x.parse::<u32>().ok())
                .unwrap_or(0);
            let fmt = match mode_str {
                "hex" => StreamDisplayFormat::HexDump,
                "raw" => StreamDisplayFormat::RawHex,
                _ => StreamDisplayFormat::Ascii,
            };
            let stream = if proto == "udp" {
                udp_streams.get(&sid)
            } else {
                tcp_streams.get(&sid)
            };
            if let Some(st) = stream {
                println!("=== Follow {} Stream #{} ===", proto.to_ascii_uppercase(), sid);
                print!("{}", st.format_stream(fmt));
            }
        }
    }
}
