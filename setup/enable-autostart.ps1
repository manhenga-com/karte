$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$target = Join-Path $root "AUTO_START_SERVER.bat"
$startup = [Environment]::GetFolderPath("Startup")
$shortcutPath = Join-Path $startup "MikroTik Hotspot Vouchers Server.lnk"
$icon = "$env:SystemRoot\System32\shell32.dll,220"

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $target
$shortcut.WorkingDirectory = $root
$shortcut.Description = "Start the local MikroTik Hotspot Voucher server"
$shortcut.IconLocation = $icon
$shortcut.Save()

Write-Host "Auto-start enabled:"
Write-Host " - $shortcutPath"
