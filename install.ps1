<#
.SYNOPSIS
    MUNG-ASH (mash) Installer & Uninstaller for Windows.
.DESCRIPTION
    Builds (or copies pre-built) release binaries for all 8 MUNG-ASH tools:
      - mash.exe           (Primary CLI & 3-pane TUI protocol analyzer)
      - mash-gui.exe       (Desktop graphical analyzer)
      - mash-cap.exe       (Isolated packet capture helper)
      - mash-info.exe      (Capture file metadata & SHA-256 inspector)
      - mash-edit.exe      (Packet editor, slicer, deduplicator & anonymizer)
      - mash-merge.exe     (Chronological / concatenated multi-file merger)
      - mash-text2pcap.exe (ASCII hex dump to PCAP/PCAPNG converter)
      - mash-mcp.exe       (Model Context Protocol JSON-RPC 2.0 AI server)
#>

param(
    [string]$InstallDir = "$env:USERPROFILE\.cargo\bin",
    [switch]$SkipBuild,
    [switch]$CreateZip,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

$Binaries = @(
    "mash.exe",
    "mash-gui.exe",
    "mash-cap.exe",
    "mash-info.exe",
    "mash-edit.exe",
    "mash-merge.exe",
    "mash-text2pcap.exe",
    "mash-mcp.exe"
)

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($Uninstall) {
    Write-Host "=== Uninstalling MUNG-ASH from $InstallDir ===" -ForegroundColor Yellow
    foreach ($bin in $Binaries) {
        $target = Join-Path $InstallDir $bin
        if (Test-Path $target) {
            Remove-Item -Force $target
            Write-Host "  Removed $target"
        }
    }
    Write-Host "MUNG-ASH uninstall complete." -ForegroundColor Green
    exit 0
}

Write-Host "=== MUNG-ASH Installer (Windows) ===" -ForegroundColor Cyan

if (-not $SkipBuild) {
    Write-Host "[1/3] Building release binaries (cargo build --release --workspace)..." -ForegroundColor Cyan
    Push-Location $RepoRoot
    try {
        cargo build --release --workspace
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build --release failed with exit code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }
} else {
    Write-Host "[1/3] Skipping cargo build (-SkipBuild specified)..." -ForegroundColor DarkGray
}

$ReleaseDir = Join-Path $RepoRoot "target\release"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

Write-Host "[2/3] Installing 8 binaries into $InstallDir ..." -ForegroundColor Cyan
foreach ($bin in $Binaries) {
    $src = Join-Path $ReleaseDir $bin
    if (-not (Test-Path $src)) {
        # Fallback if running from an extracted pre-built release archive
        $src = Join-Path $RepoRoot $bin
    }
    if (-not (Test-Path $src)) {
        throw "Binary not found: $src"
    }
    $dst = Join-Path $InstallDir $bin
    Copy-Item -Force $src $dst
    Write-Host ("  + Installed {0,-20} -> {1}" -f $bin, $dst) -ForegroundColor Green
}

if ($CreateZip) {
    $DistDir = Join-Path $RepoRoot "dist"
    $StageDir = Join-Path $DistDir "mung-ash-v0.1.0-windows-x86_64"
    $ZipPath = Join-Path $DistDir "mung-ash-v0.1.0-windows-x86_64.zip"
    if (Test-Path $StageDir) { Remove-Item -Recurse -Force $StageDir }
    New-Item -ItemType Directory -Force -Path $StageDir | Out-Null

    foreach ($bin in $Binaries) {
        Copy-Item -Force (Join-Path $InstallDir $bin) (Join-Path $StageDir $bin)
    }
    Copy-Item -Force (Join-Path $RepoRoot "README.md") (Join-Path $StageDir "README.md")
    Copy-Item -Force (Join-Path $RepoRoot "install.ps1") (Join-Path $StageDir "install.ps1")

    if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }
    Compress-Archive -Path "$StageDir\*" -DestinationPath $ZipPath -Force
    Write-Host "  + Packaged portable archive -> $ZipPath" -ForegroundColor Cyan
}

Write-Host "[3/3] Verifying installation..." -ForegroundColor Cyan
& (Join-Path $InstallDir "mash.exe") --help | Select-Object -First 3

Write-Host "`nMUNG-ASH is installed and ready! Run 'mash --help' or 'mash-gui' from your terminal." -ForegroundColor Green
