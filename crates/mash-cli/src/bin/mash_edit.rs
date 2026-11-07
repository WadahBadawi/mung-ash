use mash_cli::{apply_capture_edits, EditOptions};
use mash_pcapfile::{read_capture_file, write_capture_file, CaptureFile, CaptureFormat};
use std::env;
use std::path::Path;

fn print_help() {
    println!("mash-edit {} — Capture File Editor & Converter", env!("CARGO_PKG_VERSION"));
    println!("Usage: mash-edit [OPTIONS] <infile> <outfile> [packet-ranges...]");
    println!("Options:");
    println!("  -s <snaplen>          Truncate packets to <snaplen> bytes");
    println!("  -t <seconds>          Shift packet timestamps by <seconds> (float)");
    println!("  -d                    Remove duplicate packets (window of 5)");
    println!("  -D <window>           Remove duplicate packets within <window> frames");
    println!("  -c <pkts-per-file>    Split output into files of <pkts-per-file> packets");
    println!("  -a <frame>:<comment>  Attach a comment to <frame>");
    println!("  --anonymize <key>     Pseudonymize MAC and IPv4/IPv6 addresses using HMAC key");
    println!("  --scrub-payload       Zero out L4 payloads during anonymization");
    println!("  -F <pcap|pcapng>      Output file format");
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return;
    }

    let mut opts = EditOptions::default();
    let mut out_format: Option<CaptureFormat> = None;
    let mut split_count: Option<usize> = None;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-s" => {
                if let Some(v) = args.get(i + 1).and_then(|s| s.parse::<u32>().ok()) {
                    opts.snap_len = Some(v);
                    i += 2;
                    continue;
                }
            }
            "-t" => {
                if let Some(v) = args.get(i + 1).and_then(|s| s.parse::<f64>().ok()) {
                    opts.time_shift_secs = Some(v);
                    i += 2;
                    continue;
                }
            }
            "-d" => opts.deduplicate_window = Some(5),
            "-D" => {
                if let Some(v) = args.get(i + 1).and_then(|s| s.parse::<usize>().ok()) {
                    opts.deduplicate_window = Some(v);
                    i += 2;
                    continue;
                }
            }
            "-c" => {
                if let Some(v) = args.get(i + 1).and_then(|s| s.parse::<usize>().ok()) {
                    split_count = Some(v.max(1));
                    i += 2;
                    continue;
                }
            }
            "-a" => {
                if let Some(spec) = args.get(i + 1) {
                    if let Some((fno_s, comment)) = spec.split_once(':') {
                        if let Ok(fno) = fno_s.parse::<u64>() {
                            opts.comments.push((fno, comment.to_string()));
                        }
                    }
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
            "--anonymize" => {
                if let Some(k) = args.get(i + 1) {
                    opts.anonymize_key = Some(k.clone());
                    i += 2;
                    continue;
                }
            }
            "--scrub-payload" => {
                opts.scrub_payload = true;
            }
            other => positional.push(other.to_string()),
        }
        i += 1;
    }

    if positional.len() < 2 {
        eprintln!("mash-edit: expected <infile> and <outfile>");
        std::process::exit(1);
    }
    let infile = &positional[0];
    let outfile = &positional[1];
    for range_str in &positional[2..] {
        if let Some((a, b)) = range_str.split_once('-') {
            if let (Ok(lo), Ok(hi)) = (a.parse::<u64>(), b.parse::<u64>()) {
                opts.frame_ranges.push((lo, hi));
            }
        } else if let Ok(single) = range_str.parse::<u64>() {
            opts.frame_ranges.push((single, single));
        }
    }

    let mut cap = match read_capture_file(infile) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("mash-edit: failed to read '{infile}': {e}");
            std::process::exit(1);
        }
    };
    if let Some(fmt) = out_format {
        cap.format = fmt;
    }
    apply_capture_edits(&mut cap, &opts);

    if let Some(chunk_sz) = split_count {
        let base = Path::new(outfile);
        let stem = base.file_stem().and_then(|s| s.to_str()).unwrap_or("split");
        let ext = base.extension().and_then(|s| s.to_str()).unwrap_or("pcapng");
        let parent = base.parent().unwrap_or_else(|| Path::new("."));
        for (idx, chunk) in cap.frames.chunks(chunk_sz).enumerate() {
            let mut part = CaptureFile::new(cap.format);
            part.interfaces = cap.interfaces.clone();
            part.frames = chunk.to_vec();
            let part_path = parent.join(format!("{stem}_{idx:05}.{ext}"));
            if let Err(e) = write_capture_file(&part_path, &part) {
                eprintln!("mash-edit: failed to write '{}': {e}", part_path.display());
                std::process::exit(1);
            }
        }
    } else if let Err(e) = write_capture_file(outfile, &cap) {
        eprintln!("mash-edit: failed to write '{outfile}': {e}");
        std::process::exit(1);
    }
}

