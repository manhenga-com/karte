$ErrorActionPreference = "Stop"

$startup = [Environment]::GetFolderPath("Startup")
$shortcutPath = Join-Path $startup "MikroTik Hotspot Vouchers Server.lnk"

if (Test-Path $shortcutPath) {
    Remove-Item -LiteralPath $shortcutPath -Force
    Write-Host "Removed auto-start shortcut:"
    Write-Host " - $shortcutPath"
} else {
    Write-Host "Auto-start shortcut was not found."
}
