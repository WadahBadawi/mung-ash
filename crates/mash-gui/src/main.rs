use mash_gui::AnalyzerWorkspace;
use std::env;
use std::io::{self, BufRead, Write};

fn print_help() {
    println!("mash-gui {} — MUNG-ASH Three-Pane Interactive Protocol Analyzer", env!("CARGO_PKG_VERSION"));
    println!("Usage: mash-gui [OPTIONS] [capture-file]");
    println!("Options:");
    println!("  -r <infile>       Load capture file (.pcap/.pcapng/.gz/.lz4)");
    println!("  -Y <filter>       Initial display filter expression");
    println!("  -g <frame_no>     Jump to 1-based packet number");
    println!("  --snapshot        Print 3-pane workspace view and exit");
    println!("  -h, --help        Show this help message");
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut ws = AnalyzerWorkspace::new();
    let mut infile: Option<String> = None;
    let mut initial_filter: Option<String> = None;
    let mut goto_frame: Option<u64> = None;
    let mut snapshot_only = false;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "-r" => {
                if let Some(p) = args.get(i + 1) {
                    infile = Some(p.clone());
                    i += 2;
                    continue;
                }
            }
            "-Y" => {
                if let Some(f) = args.get(i + 1) {
                    initial_filter = Some(f.clone());
                    i += 2;
                    continue;
                }
            }
            "-g" => {
                if let Some(n) = args.get(i + 1).and_then(|s| s.parse::<u64>().ok()) {
                    goto_frame = Some(n);
                    i += 2;
                    continue;
                }
            }
            "--snapshot" => snapshot_only = true,
            other if !other.starts_with('-') && infile.is_none() => {
                infile = Some(other.to_string());
            }
            _ => {}
        }
        i += 1;
    }

    if let Some(path) = infile {
        if let Err(e) = ws.load_file(&path) {
            eprintln!("mash-gui: failed to open '{path}': {e}");
            std::process::exit(1);
        }
    }
    if let Some(f) = initial_filter {
        ws.set_display_filter(&f);
    }
    if let Some(fno) = goto_frame {
        ws.select_frame(fno);
    }

    print!("{}", ws.render_three_pane_snapshot(20));
    if snapshot_only || ws.frames.is_empty() {
        return;
    }

    println!("Interactive commands: [f <filter>] [g <frame_no>] [b <byte_offset>] [m <frame_no>] [ai] [q]");
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let Ok(cmd) = line else {
            break;
        };
        let trimmed = cmd.trim();
        if trimmed == "q" || trimmed == "quit" || trimmed == "exit" {
            break;
        } else if let Some(f) = trimmed.strip_prefix("f ") {
            ws.set_display_filter(f);
            print!("{}", ws.render_three_pane_snapshot(20));
        } else if let Some(n_str) = trimmed.strip_prefix("g ") {
            if let Ok(n) = n_str.trim().parse::<u64>() {
                ws.select_frame(n);
                print!("{}", ws.render_three_pane_snapshot(20));
            }
        } else if let Some(b_str) = trimmed.strip_prefix("b ") {
            if let Ok(off) = b_str.trim().parse::<usize>() {
                let _ = ws.select_byte_offset(0, off);
                print!("{}", ws.render_three_pane_snapshot(20));
            }
        } else if let Some(m_str) = trimmed.strip_prefix("m ") {
            if let Ok(n) = m_str.trim().parse::<u64>() {
                ws.toggle_mark_frame(n);
                print!("{}", ws.render_three_pane_snapshot(20));
            }
        } else if trimmed == "ai" {
            if let Some(fno) = ws.selected_frame {
                if let Some(pkt) = ws.dissected.get((fno - 1) as usize) {
                    if let Ok(explanation) = ws.ai.explain_packet(pkt) {
                        println!("{explanation}");
                    }
                }
            }
        }
        let _ = stdout.flush();
    }
}

