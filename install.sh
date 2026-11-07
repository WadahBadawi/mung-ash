#!/usr/bin/env sh
# MUNG-ASH (mash) Installer & Uninstaller for Linux and macOS
set -eu

PREFIX="${PREFIX:-$HOME/.local}"
BINDIR="$PREFIX/bin"
UNINSTALL=0
SETCAP=0
SKIP_BUILD=0

for arg in "$@"; do
    case "$arg" in
        --prefix=*) PREFIX="${arg#*=}"; BINDIR="$PREFIX/bin" ;;
        --uninstall) UNINSTALL=1 ;;
        --setcap) SETCAP=1 ;;
        --skip-build) SKIP_BUILD=1 ;;
        -h|--help)
            echo "Usage: ./install.sh [--prefix=/path] [--setcap] [--skip-build] [--uninstall]"
            exit 0
            ;;
    esac
done

BINARIES="mash mash-gui mash-cap mash-info mash-edit mash-merge mash-text2pcap mash-mcp"

if [ "$UNINSTALL" -eq 1 ]; then
    echo "=== Uninstalling MUNG-ASH from $BINDIR ==="
    for bin in $BINARIES; do
        if [ -f "$BINDIR/$bin" ]; then
            rm -f "$BINDIR/$bin"
            echo "  Removed $BINDIR/$bin"
        fi
    done
    rm -f "$HOME/.local/share/applications/mung-ash.desktop" 2>/dev/null || true
    echo "Uninstall complete."
    exit 0
fi

echo "=== MUNG-ASH Installer (Linux / macOS) ==="
if [ "$SKIP_BUILD" -eq 0 ]; then
    echo "[1/3] Building release workspace..."
    cargo build --release --workspace
fi

mkdir -p "$BINDIR"
echo "[2/3] Installing binaries to $BINDIR..."
for bin in $BINARIES; do
    if [ -f "target/release/$bin" ]; then
        cp -f "target/release/$bin" "$BINDIR/$bin"
    elif [ -f "./$bin" ]; then
        cp -f "./$bin" "$BINDIR/$bin"
    else
        echo "Error: binary '$bin' not found" >&2
        exit 1
    fi
    chmod 0755 "$BINDIR/$bin"
    echo "  + Installed $BINDIR/$bin"
done

if [ "$SETCAP" -eq 1 ] && command -v setcap >/dev/null 2>&1; then
    echo "Applying Linux packet capture capabilities to $BINDIR/mash-cap..."
    sudo setcap cap_net_raw,cap_net_admin=eip "$BINDIR/mash-cap"
fi

if [ "$(uname -s)" = "Linux" ]; then
    APPS_DIR="$HOME/.local/share/applications"
    mkdir -p "$APPS_DIR"
    cat > "$APPS_DIR/mung-ash.desktop" <<EOF
[Desktop Entry]
Name=MUNG-ASH Network Analyzer
Comment=Memory-Safe Network Protocol Analyzer & AI Packet Suite
Exec=$BINDIR/mash-gui %f
Terminal=false
Type=Application
Categories=Network;Security;System;Monitor;
MimeType=application/vnd.tcpdump.pcap;application/x-pcapng;
EOF
fi

echo "[3/3] Installation complete! Ensure '$BINDIR' is in your PATH."
"$BINDIR/mash" --help | head -n 3
