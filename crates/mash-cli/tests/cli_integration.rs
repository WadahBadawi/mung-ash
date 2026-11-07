use mash_cli::tui::TuiApp;
use mash_cli::{
    apply_capture_edits, export_ek_lines, export_pdml, export_psml, format_fields_row, EditOptions,
};
use mash_core::{Frame, LinkType, NameResolver, ResolutionConfig, Timestamp};
use mash_dissect::ConversationTracker;
use mash_pcapfile::text2pcap::{parse_hexdump_packets, Text2PcapOptions};
use mash_pcapfile::{merge_captures, write_pcapng_bytes, CaptureFile, CaptureFormat, MergeMode};
use mash_protocols::build_default_engine;
use mash_stats::{analyze_tcp_flows, TcpAnomaly};

#[test]
fn end_to_end_text2pcap_edit_merge_dissect_and_export() {
    // 1. Convert an ASCII hex dump of an HTTP GET payload into synthetic Ethernet+IPv4+TCP frames via text2pcap
    let hexdump = "0000  47 45 54 20 2f 68 65 61 6c 74 68 20 48 54 54 50  GET /health HTTP\n\
                   0010  2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 74 65 73 74  /1.1..Host: test\n\
                   0020  2e 6c 6f 63 61 6c 0d 0a 0d 0a                    .local....\n";
    let t2p_opts = Text2PcapOptions {
        prepend_tcp_ports: Some((50123, 80)),
        ..Text2PcapOptions::default()
    };
    let frames = parse_hexdump_packets(hexdump, &t2p_opts);
    assert_eq!(frames.len(), 1);

    let mut cap1 = CaptureFile::new(CaptureFormat::PcapNg);
    cap1.frames = frames.clone();
    // Duplicate the frame and verify mash-edit deduplication removes the duplicate
    cap1.frames.push(frames[0].clone());
    cap1.frames[1].number = 2;

    let edit_opts = EditOptions {
        deduplicate_window: Some(5),
        time_shift_secs: Some(10.0),
        comments: vec![(1, "Annotated by mash-edit".to_string())],
        ..EditOptions::default()
    };
    apply_capture_edits(&mut cap1, &edit_opts);
    assert_eq!(cap1.frames.len(), 1);
    assert_eq!(cap1.frames[0].timestamp.secs(), 10);
    assert_eq!(cap1.frames[0].comments, vec!["Annotated by mash-edit"]);

    // 2. Merge with a second capture chronologically
    let mut cap2 = CaptureFile::new(CaptureFormat::PcapNg);
    let mut earlier_frame = frames[0].clone();
    earlier_frame.timestamp = Timestamp::from_secs_nanos(5, 0);
    cap2.frames.push(earlier_frame);

    let merged = merge_captures(&[cap1, cap2], MergeMode::Chronological, CaptureFormat::PcapNg);
    assert_eq!(merged.frames.len(), 2);
    assert_eq!(merged.frames[0].timestamp.secs(), 5);
    assert_eq!(merged.frames[1].timestamp.secs(), 10);

    // Roundtrip through pcapng bytes
    let raw_ng = write_pcapng_bytes(&merged).unwrap();
    let reparsed = mash_pcapfile::read_capture_bytes(&raw_ng).unwrap();
    assert_eq!(reparsed.frames.len(), 2);

    // 3. Dissect and verify structured exports (Fields, PDML, PSML, EK)
    let engine = build_default_engine();
    let mut resolver = NameResolver::new(ResolutionConfig::default());
    let mut conv = ConversationTracker::new();
    let dissected: Vec<_> = reparsed
        .frames
        .iter()
        .map(|f| engine.dissect_frame(f, None, None, &mut resolver, &mut conv))
        .collect();

    let fields = vec!["ip.src".to_string(), "http.request.uri".to_string()];
    let row = format_fields_row(&dissected[0], &fields, "\t", None);
    assert_eq!(row, "10.1.1.1\t/health");

    let pdml = export_pdml(&dissected);
    assert!(pdml.contains("<proto name=\"http\""));
    let psml = export_psml(&dissected);
    assert!(psml.contains("<section>HTTP</section>"));
    let ek = export_ek_lines(&dissected[0]);
    assert!(ek.contains("\"http_request_uri\":\"/health\""));
}

#[test]
fn stateful_tcp_analyzer_detects_retransmission_dup_ack_and_zero_window() {
    let engine = build_default_engine();
    let mut resolver = NameResolver::new(ResolutionConfig::default());
    let mut conv = ConversationTracker::new();

    let build_tcp_frame = |no: u64,
                           src: [u8; 4],
                           dst: [u8; 4],
                           sport: u16,
                           dport: u16,
                           seq: u32,
                           ack: u32,
                           flags: u16,
                           win: u16,
                           payload: &[u8]|
     -> Frame {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        let ip_len = (20 + 20 + payload.len()) as u16;
        pkt.extend_from_slice(&[0x45, 0x00]);
        pkt.extend_from_slice(&ip_len.to_be_bytes());
        pkt.extend_from_slice(&[0, 1, 0, 0, 64, 6, 0, 0]);
        pkt.extend_from_slice(&src);
        pkt.extend_from_slice(&dst);
        pkt.extend_from_slice(&sport.to_be_bytes());
        pkt.extend_from_slice(&dport.to_be_bytes());
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&ack.to_be_bytes());
        pkt.extend_from_slice(&(0x5000u16 | flags).to_be_bytes());
        pkt.extend_from_slice(&win.to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0, 0]);
        pkt.extend_from_slice(payload);
        Frame::new(no, Timestamp::from_secs_nanos(no, 0), LinkType::Ethernet, pkt)
    };

    let c = [10, 0, 0, 1];
    let s = [10, 0, 0, 2];
    let frames = [
        // Frame 1: data segment seq=100 len=10
        build_tcp_frame(1, c, s, 10000, 80, 100, 1, 0x18, 4096, b"0123456789"),
        // Frame 2: Retransmission of seq=100 len=10
        build_tcp_frame(2, c, s, 10000, 80, 100, 1, 0x18, 4096, b"0123456789"),
        // Frame 3: Server ACKs 110
        build_tcp_frame(3, s, c, 80, 10000, 1, 110, 0x10, 4096, b""),
        // Frame 4: Server Duplicate ACK #1 for 110
        build_tcp_frame(4, s, c, 80, 10000, 1, 110, 0x10, 4096, b""),
        // Frame 5: Server ZeroWindow
        build_tcp_frame(5, s, c, 80, 10000, 1, 110, 0x10, 0, b""),
    ];

    let mut dissected: Vec<_> = frames
        .iter()
        .map(|f| engine.dissect_frame(f, None, None, &mut resolver, &mut conv))
        .collect();
    let flows = analyze_tcp_flows(&mut dissected);
    let flow = flows.get(&0).unwrap();

    assert_eq!(flow.retransmissions, 1);
    assert_eq!(flow.duplicate_acks, 1);
    assert_eq!(flow.zero_windows, 1);
    assert_eq!(
        flow.frame_anomalies.get(&2),
        Some(&vec![TcpAnomaly::Retransmission])
    );
    assert_eq!(
        flow.frame_anomalies.get(&4),
        Some(&vec![TcpAnomaly::DuplicateAck(1)])
    );
    assert_eq!(
        flow.frame_anomalies.get(&5),
        Some(&vec![TcpAnomaly::ZeroWindow])
    );
}

#[test]
fn tui_snapshot_and_anonymizer_edit_roundtrip() {
    let hexdump = "0000  47 45 54 20 2f 73 65 63 72 65 74 20 48 54 54 50  GET /secret HTTP\n\
                   0010  2f 31 2e 31 0d 0a 0d 0a                          /1.1....\n";
    let t2p_opts = Text2PcapOptions {
        prepend_tcp_ports: Some((54321, 80)),
        ..Text2PcapOptions::default()
    };
    let frames = parse_hexdump_packets(hexdump, &t2p_opts);
    let mut cap = CaptureFile::new(CaptureFormat::PcapNg);
    cap.frames = frames;

    let engine = build_default_engine();
    let mut resolver = NameResolver::new(ResolutionConfig::default());
    let mut conv = ConversationTracker::new();
    let dissected: Vec<_> = cap
        .frames
        .iter()
        .map(|f| engine.dissect_frame(f, None, None, &mut resolver, &mut conv))
        .collect();

    let mut tui = TuiApp::new("test.pcapng", cap.frames.clone(), dissected, None);
    let snap = tui.render_snapshot(100);
    assert!(snap.contains("MUNG-ASH TUI"));
    assert!(snap.contains("GET /secret HTTP/1.1"));

    tui.apply_filter("http", Some(&engine.registry));
    assert_eq!(tui.filtered_indices.len(), 1);

    // Anonymize IP/MAC and scrub payload
    let edit_opts = EditOptions {
        anonymize_key: Some("corp-key-123".to_string()),
        scrub_payload: true,
        ..EditOptions::default()
    };
    apply_capture_edits(&mut cap, &edit_opts);
    let d_anon = engine.dissect_frame(&cap.frames[0], None, None, &mut resolver, &mut conv);
    assert_ne!(d_anon.summary.source, "10.1.1.1");
    assert!(d_anon.summary.source.starts_with("10."));
}
