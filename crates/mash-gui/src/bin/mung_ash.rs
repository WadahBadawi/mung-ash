#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use mash_gui::AnalyzerWorkspace;
use std::env;

fn main() {
    let mut ws = AnalyzerWorkspace::new();
    if let Some(path) = env::args().nth(1) {
        if !path.starts_with('-') {
            let _ = ws.load_file(&path);
        }
    }
    let _ = mash_gui::app::run_native_gui(ws);
}
