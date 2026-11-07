use mash_pcapfile::read_capture_bytes;
use mash_stats::CaptureProperties;
use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("mash-info {} — Capture File Metadata Inspector", env!("CARGO_PKG_VERSION"));
        println!("Usage: mash-info [--json] <capture-file>...");
        return;
    }

    let as_json = args.iter().any(|a| a == "--json" || a == "-j");
    for arg in args.iter().filter(|a| !a.starts_with('-')) {
        let raw = match fs::read(arg) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("mash-info: failed to read '{arg}': {e}");
                std::process::exit(1);
            }
        };
        let cap = match read_capture_bytes(&raw) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("mash-info: invalid capture '{arg}': {e}");
                std::process::exit(1);
            }
        };
        let props = CaptureProperties::from_capture(&cap, Some(&raw));
        if as_json {
            println!("{}", serde_json::to_string_pretty(&props).unwrap_or_default());
        } else {
            println!("File name:         {arg}");
            print!("{}", props.format_text());
        }
    }
}

