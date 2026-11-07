use mash_pcapfile::{
    merge_captures, read_capture_file, write_capture_file, CaptureFormat, MergeMode,
};
use std::env;

fn print_help() {
    println!("mash-merge {} — Multi-Capture File Merger", env!("CARGO_PKG_VERSION"));
    println!("Usage: mash-merge [-a] [-F <pcap|pcapng>] -w <outfile> <infile1> <infile2>...");
    println!("Options:");
    println!("  -a                Concatenate files sequentially instead of sorting chronologically");
    println!("  -F <pcap|pcapng>  Output file format (default: pcapng)");
    println!("  -w <outfile>      Output capture file path");
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return;
    }

    let mut mode = MergeMode::Chronological;
    let mut format = CaptureFormat::PcapNg;
    let mut out_path: Option<String> = None;
    let mut in_files: Vec<String> = Vec::new();

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-a" => mode = MergeMode::Concatenate,
            "-F" => {
                if let Some(fmt) = args.get(i + 1) {
                    format = match fmt.as_str() {
                        "pcap" => CaptureFormat::PcapMicros,
                        "nsec" | "pcap-ns" => CaptureFormat::PcapNanos,
                        _ => CaptureFormat::PcapNg,
                    };
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
            other if !other.starts_with('-') => in_files.push(other.to_string()),
            _ => {}
        }
        i += 1;
    }

    let Some(outfile) = out_path else {
        eprintln!("mash-merge: missing -w <outfile>");
        std::process::exit(1);
    };
    if in_files.is_empty() {
        eprintln!("mash-merge: no input files provided");
        std::process::exit(1);
    }

    let mut captures = Vec::with_capacity(in_files.len());
    for path in &in_files {
        match read_capture_file(path) {
            Ok(c) => captures.push(c),
            Err(e) => {
                eprintln!("mash-merge: failed to read '{path}': {e}");
                std::process::exit(1);
            }
        }
    }

    let merged = merge_captures(&captures, mode, format);
    if let Err(e) = write_capture_file(&outfile, &merged) {
        eprintln!("mash-merge: failed to write '{outfile}': {e}");
        std::process::exit(1);
    }
}

