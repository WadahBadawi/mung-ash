use mash_capture::{capture_frames, list_capture_interfaces, CaptureOptions, RingBufferWriter};
use mash_pcapfile::CaptureFormat;
use std::env;

fn print_help() {
    println!("mash-cap {} — Minimal Isolated Packet Capture Helper", env!("CARGO_PKG_VERSION"));
    println!("Usage: mash-cap [OPTIONS]");
    println!("Options:");
    println!("  -D                    List available capture interfaces and exit");
    println!("  -i <interface>        Interface name or index to capture from");
    println!("  -f <bpf-filter>       Capture BPF filter expression");
    println!("  -p                    Do not put interface into promiscuous mode");
    println!("  -I                    Capture in 802.11 monitor mode");
    println!("  -s <snaplen>          Snapshot length in bytes (default: 262144)");
    println!("  -B <buffer-mib>       Kernel capture buffer size in MiB (default: 16)");
    println!("  -c <count>            Stop after capturing <count> packets");
    println!("  -a <cond:val>         Autostop condition (duration:<sec> | filesize:<kb>)");
    println!("  -b <ring:val>         Ring buffer option (filesize:<kb> | files:<n>)");
    println!("  -P                    Write classic libpcap format instead of pcapng");
    println!("  -w <outfile>          Write captured packets to file");
    println!("  -h, --help            Print this help message");
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut opts = CaptureOptions::default();
    opts.interfaces.clear();
    let mut out_path: Option<String> = None;

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
            "-i" => {
                if let Some(iface) = args.get(i + 1) {
                    opts.interfaces.push(iface.clone());
                    i += 2;
                    continue;
                }
            }
            "-f" => {
                if let Some(bpf) = args.get(i + 1) {
                    opts.bpf_filter = Some(bpf.clone());
                    i += 2;
                    continue;
                }
            }
            "-p" => opts.promiscuous = false,
            "-I" => opts.monitor_mode = true,
            "-P" => opts.format = CaptureFormat::PcapMicros,
            "-s" => {
                if let Some(v) = args.get(i + 1).and_then(|s| s.parse::<u32>().ok()) {
                    opts.snap_len = v;
                    i += 2;
                    continue;
                }
            }
            "-B" => {
                if let Some(v) = args.get(i + 1).and_then(|s| s.parse::<u32>().ok()) {
                    opts.buffer_size_mib = v;
                    i += 2;
                    continue;
                }
            }
            "-c" => {
                if let Some(v) = args.get(i + 1).and_then(|s| s.parse::<u64>().ok()) {
                    opts.max_packets = Some(v);
                    i += 2;
                    continue;
                }
            }
            "-a" => {
                if let Some(spec) = args.get(i + 1) {
                    if let Some((k, v)) = spec.split_once(':') {
                        if let Ok(num) = v.parse::<u64>() {
                            match k {
                                "duration" => opts.max_duration_secs = Some(num),
                                "filesize" => opts.max_file_size_kb = Some(num),
                                _ => {}
                            }
                        }
                    }
                    i += 2;
                    continue;
                }
            }
            "-b" => {
                if let Some(spec) = args.get(i + 1) {
                    if let Some((k, v)) = spec.split_once(':') {
                        match k {
                            "filesize" => opts.ring_file_size_kb = v.parse::<u64>().ok(),
                            "files" => opts.ring_max_files = v.parse::<usize>().ok(),
                            _ => {}
                        }
                    }
                    i += 2;
                    continue;
                }
            }
            "-w" => {
                if let Some(p) = args.get(i + 1) {
                    out_path = Some(p.clone());
                    i += 2;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }

    if opts.interfaces.is_empty() {
        opts.interfaces.push("eth0".to_string());
    }
    let frames = match capture_frames(&opts) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("mash-cap: capture error: {e}");
            std::process::exit(1);
        }
    };
    let count = frames.len();
    if let Some(path) = out_path {
        let mut writer = RingBufferWriter::new(
            &path,
            opts.format,
            opts.ring_file_size_kb.or(opts.max_file_size_kb),
            opts.ring_max_files,
        );
        for frame in frames {
            if let Err(e) = writer.push_frame(frame) {
                eprintln!("mash-cap: write error: {e}");
                std::process::exit(1);
            }
        }
        match writer.finish() {
            Ok(files) => {
                eprintln!(
                    "mash-cap: captured {count} packets on {:?} into {} file(s)",
                    opts.interfaces,
                    files.len()
                );
            }
            Err(e) => {
                eprintln!("mash-cap: failed to finalize capture: {e}");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!(
            "mash-cap: captured {count} packets on {:?} (use -w <file> to save)",
            opts.interfaces
        );
    }
}

