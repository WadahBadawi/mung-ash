use mash_pcapfile::text2pcap::{parse_hexdump_packets, Text2PcapOptions};
use mash_pcapfile::{write_capture_file, CaptureFile, CaptureFormat};
use std::env;
use std::fs;
use std::net::Ipv4Addr;

fn print_help() {
    println!("mash-text2pcap {} — ASCII Hex Dump to Capture Converter", env!("CARGO_PKG_VERSION"));
    println!("Usage: mash-text2pcap [OPTIONS] <infile.txt> <outfile.pcapng>");
    println!("Options:");
    println!("  -e <ethertype-hex>      Prepend dummy Ethernet header with given EtherType (e.g. 0x0800)");
    println!("  -4 <src_ip>,<dst_ip>    Prepend dummy IPv4 header");
    println!("  -u <srcport>,<dstport>  Prepend dummy UDP header");
    println!("  -T <srcport>,<dport>    Prepend dummy TCP header");
    println!("  -F <pcap|pcapng>        Output file format (default: pcapng)");
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return;
    }

    let mut opts = Text2PcapOptions::default();
    let mut format = CaptureFormat::PcapNg;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-e" => {
                if let Some(et_s) = args.get(i + 1) {
                    let hex = et_s.trim_start_matches("0x").trim_start_matches("0X");
                    if let Ok(et) = u16::from_str_radix(hex, 16) {
                        opts.prepend_ethernet = Some(et);
                    }
                    i += 2;
                    continue;
                }
            }
            "-4" => {
                if let Some(pair) = args.get(i + 1) {
                    if let Some((s, d)) = pair.split_once(',') {
                        if let (Ok(sip), Ok(dip)) = (s.parse::<Ipv4Addr>(), d.parse::<Ipv4Addr>()) {
                            opts.src_ip = sip.octets();
                            opts.dst_ip = dip.octets();
                            if opts.prepend_ipv4_proto.is_none() {
                                opts.prepend_ipv4_proto = Some(254);
                            }
                        }
                    }
                    i += 2;
                    continue;
                }
            }
            "-u" => {
                if let Some(pair) = args.get(i + 1) {
                    if let Some((s, d)) = pair.split_once(',') {
                        if let (Ok(sp), Ok(dp)) = (s.parse::<u16>(), d.parse::<u16>()) {
                            opts.prepend_udp_ports = Some((sp, dp));
                        }
                    }
                    i += 2;
                    continue;
                }
            }
            "-T" => {
                if let Some(pair) = args.get(i + 1) {
                    if let Some((s, d)) = pair.split_once(',') {
                        if let (Ok(sp), Ok(dp)) = (s.parse::<u16>(), d.parse::<u16>()) {
                            opts.prepend_tcp_ports = Some((sp, dp));
                        }
                    }
                    i += 2;
                    continue;
                }
            }
            "-F" => {
                if let Some(fmt) = args.get(i + 1) {
                    format = match fmt.as_str() {
                        "pcap" => CaptureFormat::PcapMicros,
                        _ => CaptureFormat::PcapNg,
                    };
                    i += 2;
                    continue;
                }
            }
            other if !other.starts_with('-') => positional.push(other.to_string()),
            _ => {}
        }
        i += 1;
    }

    if positional.len() < 2 {
        eprintln!("mash-text2pcap: expected <infile> and <outfile>");
        std::process::exit(1);
    }

    let text = match fs::read_to_string(&positional[0]) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("mash-text2pcap: failed to read '{}': {e}", positional[0]);
            std::process::exit(1);
        }
    };

    let frames = parse_hexdump_packets(&text, &opts);
    let mut cap = CaptureFile::new(format);
    cap.frames = frames;
    if let Err(e) = write_capture_file(&positional[1], &cap) {
        eprintln!("mash-text2pcap: failed to write '{}': {e}", positional[1]);
        std::process::exit(1);
    }
}
