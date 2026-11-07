use egui::{Stroke, Visuals};

pub mod colors {
    use egui::Color32;

    pub const CANVAS: Color32 = Color32::from_rgb(3, 20, 39);                      // #031427
    pub const SURFACE_CONTAINER_LOWEST: Color32 = Color32::from_rgb(0, 15, 33);   // #000f21
    pub const SURFACE_CONTAINER_LOW: Color32 = Color32::from_rgb(11, 28, 48);     // #0b1c30
    pub const SURFACE_CONTAINER: Color32 = Color32::from_rgb(16, 32, 52);         // #102034
    pub const SURFACE_CONTAINER_HIGH: Color32 = Color32::from_rgb(27, 43, 63);    // #1b2b3f
    pub const SURFACE_CONTAINER_HIGHEST: Color32 = Color32::from_rgb(38, 54, 74); // #26364a
    pub const SURFACE_BRIGHT: Color32 = Color32::from_rgb(42, 58, 79);           // #2a3a4f

    pub const ON_SURFACE: Color32 = Color32::from_rgb(211, 228, 254);            // #d3e4fe
    pub const ON_SURFACE_VARIANT: Color32 = Color32::from_rgb(187, 202, 191);    // #bbcabf
    pub const OUTLINE: Color32 = Color32::from_rgb(134, 148, 138);               // #86948a
    pub const OUTLINE_VARIANT: Color32 = Color32::from_rgb(60, 74, 66);          // #3c4a42

    pub const PRIMARY: Color32 = Color32::from_rgb(78, 222, 163);                // #4edea3
    pub const PRIMARY_CONTAINER: Color32 = Color32::from_rgb(16, 185, 129);      // #10b981
    pub const ON_PRIMARY: Color32 = Color32::from_rgb(0, 56, 36);                // #003824

    pub const SECONDARY: Color32 = Color32::from_rgb(173, 198, 255);            // #adc6ff
    pub const SECONDARY_CONTAINER: Color32 = Color32::from_rgb(5, 102, 217);    // #0566d9
    pub const ON_SECONDARY: Color32 = Color32::from_rgb(0, 46, 106);            // #002e6a

    pub const ERROR: Color32 = Color32::from_rgb(255, 180, 171);                // #ffb4ab
    pub const ERROR_CONTAINER: Color32 = Color32::from_rgb(147, 0, 10);          // #93000a
    pub const ON_ERROR: Color32 = Color32::from_rgb(105, 0, 5);                  // #690005

    // Protocol badge accent colors
    pub const BADGE_HTTP_FG: Color32 = Color32::from_rgb(0, 56, 36);
    pub const BADGE_HTTP_BG: Color32 = Color32::from_rgb(16, 185, 129);
    pub const BADGE_TLS_FG: Color32 = Color32::from_rgb(216, 226, 255);
    pub const BADGE_TLS_BG: Color32 = Color32::from_rgb(5, 102, 217);
    pub const BADGE_DNS_FG: Color32 = Color32::from_rgb(210, 255, 250);
    pub const BADGE_DNS_BG: Color32 = Color32::from_rgb(15, 120, 140);
    pub const BADGE_TCP_FG: Color32 = Color32::from_rgb(211, 228, 254);
    pub const BADGE_TCP_BG: Color32 = Color32::from_rgb(27, 43, 63);
    pub const BADGE_UDP_FG: Color32 = Color32::from_rgb(215, 240, 255);
    pub const BADGE_UDP_BG: Color32 = Color32::from_rgb(20, 75, 105);
    pub const BADGE_ARP_FG: Color32 = Color32::from_rgb(255, 240, 180);
    pub const BADGE_ARP_BG: Color32 = Color32::from_rgb(120, 85, 15);
    pub const BADGE_ICMP_FG: Color32 = Color32::from_rgb(255, 225, 255);
    pub const BADGE_ICMP_BG: Color32 = Color32::from_rgb(95, 30, 115);
    pub const BADGE_BGP_FG: Color32 = Color32::from_rgb(230, 230, 255);
    pub const BADGE_BGP_BG: Color32 = Color32::from_rgb(60, 50, 130);
    pub const BADGE_MQTT_FG: Color32 = Color32::from_rgb(200, 255, 240);
    pub const BADGE_MQTT_BG: Color32 = Color32::from_rgb(20, 95, 90);
    pub const BADGE_MODBUS_FG: Color32 = Color32::from_rgb(255, 235, 210);
    pub const BADGE_MODBUS_BG: Color32 = Color32::from_rgb(130, 70, 20);
    pub const BADGE_ERR_FG: Color32 = Color32::from_rgb(255, 218, 214);
    pub const BADGE_ERR_BG: Color32 = Color32::from_rgb(147, 0, 10);
}

/// Return the (foreground, background) badge color for a protocol name (`DESIGN.md`).
pub fn protocol_badge_colors(proto: &str) -> (egui::Color32, egui::Color32) {
    let p = proto.trim();
    if p.eq_ignore_ascii_case("HTTP") || p.eq_ignore_ascii_case("HTTP/JSON") {
        (colors::BADGE_HTTP_FG, colors::BADGE_HTTP_BG)
    } else if p.eq_ignore_ascii_case("TLS") || p.eq_ignore_ascii_case("TLSv1.3") {
        (colors::BADGE_TLS_FG, colors::BADGE_TLS_BG)
    } else if p.eq_ignore_ascii_case("DNS") {
        (colors::BADGE_DNS_FG, colors::BADGE_DNS_BG)
    } else if p.eq_ignore_ascii_case("TCP") {
        (colors::BADGE_TCP_FG, colors::BADGE_TCP_BG)
    } else if p.eq_ignore_ascii_case("UDP") {
        (colors::BADGE_UDP_FG, colors::BADGE_UDP_BG)
    } else if p.eq_ignore_ascii_case("ARP") {
        (colors::BADGE_ARP_FG, colors::BADGE_ARP_BG)
    } else if p.eq_ignore_ascii_case("ICMP") || p.eq_ignore_ascii_case("ICMPv6") {
        (colors::BADGE_ICMP_FG, colors::BADGE_ICMP_BG)
    } else if p.eq_ignore_ascii_case("BGP") {
        (colors::BADGE_BGP_FG, colors::BADGE_BGP_BG)
    } else if p.eq_ignore_ascii_case("MQTT") {
        (colors::BADGE_MQTT_FG, colors::BADGE_MQTT_BG)
    } else if p.eq_ignore_ascii_case("Modbus") || p.eq_ignore_ascii_case("Modbus/TCP") {
        (colors::BADGE_MODBUS_FG, colors::BADGE_MODBUS_BG)
    } else if p.contains("RST") || p.contains("Malformed") || p.contains("Error") {
        (colors::BADGE_ERR_FG, colors::BADGE_ERR_BG)
    } else {
        (colors::ON_SURFACE, colors::SURFACE_CONTAINER_HIGH)
    }
}

/// Build the Enterprise Analytics Suite dark visuals (`DESIGN.md`).
pub fn enterprise_dark_visuals() -> Visuals {
    let mut vis = Visuals::dark();
    vis.panel_fill = colors::CANVAS;
    vis.window_fill = colors::SURFACE_CONTAINER;
    vis.extreme_bg_color = colors::SURFACE_CONTAINER_LOWEST;
    vis.faint_bg_color = colors::SURFACE_CONTAINER_LOW;
    vis.code_bg_color = colors::SURFACE_CONTAINER_LOWEST;

    vis.widgets.noninteractive.bg_fill = colors::SURFACE_CONTAINER;
    vis.widgets.noninteractive.fg_stroke = Stroke::new(1.0f32, colors::ON_SURFACE);
    vis.widgets.noninteractive.bg_stroke = Stroke::new(1.0f32, colors::OUTLINE_VARIANT);

    vis.widgets.inactive.bg_fill = colors::SURFACE_CONTAINER_HIGH;
    vis.widgets.inactive.fg_stroke = Stroke::new(1.0f32, colors::ON_SURFACE);
    vis.widgets.inactive.bg_stroke = Stroke::new(1.0f32, colors::OUTLINE_VARIANT);

    vis.widgets.hovered.bg_fill = colors::SURFACE_CONTAINER_HIGHEST;
    vis.widgets.hovered.fg_stroke = Stroke::new(1.0f32, colors::PRIMARY);
    vis.widgets.hovered.bg_stroke = Stroke::new(1.0f32, colors::PRIMARY);

    vis.widgets.active.bg_fill = colors::PRIMARY_CONTAINER;
    vis.widgets.active.fg_stroke = Stroke::new(1.0f32, colors::ON_PRIMARY);
    vis.widgets.active.bg_stroke = Stroke::new(1.0f32, colors::PRIMARY);

    vis.widgets.open.bg_fill = colors::SURFACE_CONTAINER_HIGHEST;
    vis.widgets.open.fg_stroke = Stroke::new(1.0f32, colors::PRIMARY);
    vis.widgets.open.bg_stroke = Stroke::new(1.0f32, colors::PRIMARY);

    vis.selection.bg_fill = colors::SECONDARY_CONTAINER;
    vis.selection.stroke = Stroke::new(1.0f32, colors::SECONDARY);

    vis
}
