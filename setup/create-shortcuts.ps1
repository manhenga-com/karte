$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$target = Join-Path $root "START_APP.bat"
$icon = "$env:SystemRoot\System32\shell32.dll,220"
$name = "MikroTik Hotspot Vouchers.lnk"

function New-AppShortcut {
    param (
        [string] $Path
    )

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($Path)
    $shortcut.TargetPath = $target
    $shortcut.WorkingDirectory = $root
    $shortcut.Description = "Open the local MikroTik Hotspot Voucher app"
    $shortcut.IconLocation = $icon
    $shortcut.Save()
}

$desktop = [Environment]::GetFolderPath("Desktop")
New-AppShortcut -Path (Join-Path $desktop $name)

$programs = [Environment]::GetFolderPath("Programs")
$startFolder = Join-Path $programs "MikroTik Hotspot Vouchers"
New-Item -ItemType Directory -Force -Path $startFolder | Out-Null
New-AppShortcut -Path (Join-Path $startFolder $name)

Write-Host "Created shortcuts:"
Write-Host " - Desktop\$name"
Write-Host " - Start Menu\MikroTik Hotspot Vouchers\$name"
