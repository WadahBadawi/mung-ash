use mash_mcp::{JsonRpcRequest, JsonRpcResponse, McpServer};
use serde_json::{json, Value};
use std::env;
use std::io::{self, BufRead, Write};

fn main() {
    let mut server = McpServer::new();
    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-r" | "--read-file" => {
                if let Some(path) = args.get(i + 1) {
                    if let Err(e) = server.load_file(path) {
                        eprintln!("mash-mcp: failed to load capture '{path}': {e}");
                        std::process::exit(1);
                    }
                    i += 2;
                    continue;
                }
            }
            "--help" | "-h" => {
                println!("Usage: mash-mcp [-r <capture-file>]");
                println!("Model Context Protocol (MCP) JSON-RPC 2.0 server over stdio.");
                return;
            }
            path if !path.starts_with('-') => {
                if let Err(e) = server.load_file(path) {
                    eprintln!("mash-mcp: failed to load capture '{path}': {e}");
                    std::process::exit(1);
                }
            }
            _ => {}
        }
        i += 1;
    }

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let Ok(raw) = line else {
            break;
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<JsonRpcRequest>(trimmed) {
            Ok(req) => server.handle_request(req),
            Err(e) => JsonRpcResponse {
                jsonrpc: "2.0",
                id: Value::Null,
                result: None,
                error: Some(json!({
                    "code": -32700,
                    "message": format!("Parse error: {e}")
                })),
            },
        };
        if let Ok(serialized) = serde_json::to_string(&response) {
            let _ = writeln!(stdout, "{serialized}");
            let _ = stdout.flush();
        }
    }
}

