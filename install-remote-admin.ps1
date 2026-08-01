#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\WindowsLoginGuardRemoteAdmin",
    [string]$PythonExe = ""
)
$ErrorActionPreference = "Stop"
Write-Warning "This is a legacy compatibility installer. Normal deployments use install-remote-server.ps1, which installs and links Remote Administration automatically."
Set-StrictMode -Version Latest

function Resolve-Python {
    param([string]$RequestedPath)
    if ($RequestedPath) {
        $candidate = (Get-Command $RequestedPath -ErrorAction Stop).Source
    }
    else {
        $candidate = $null
        $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
        if ($launcher) {
            $output = & $launcher.Source -3 -c "import sys; print(sys.executable)" 2>&1
            if (($LASTEXITCODE -eq 0) -and $output) {
                $candidate = ($output | Select-Object -Last 1).ToString().Trim()
            }
        }
        if (-not $candidate) {
            $command = Get-Command python.exe -ErrorAction SilentlyContinue
            if ($command) { $candidate = $command.Source }
        }
    }
    if (-not $candidate -or -not (Test-Path $candidate)) {
        throw "Install 64-bit Python 3.11+ for all users, then rerun."
    }
    return $candidate
}

$PythonExe = Resolve-Python -RequestedPath $PythonExe
$PythonwExe = Join-Path (Split-Path -Parent $PythonExe) "pythonw.exe"
if (-not (Test-Path $PythonwExe)) { $PythonwExe = $PythonExe }
$SourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
foreach ($name in @(
    "remote_admin.pyw",
    "remote_admin_launcher.pyw",
    "remote_notifier.pyw",
    "open-remote-admin.ps1",
    "configure-approval-notifier.ps1",
    "remote_common.py",
    "requirements-remote-admin.txt",
    "REMOTE_MANAGEMENT.md",
    "VERSION",
    "reset-remote-admin-workstation.ps1",
    "uninstall-remote-admin.ps1"
)) {
    Copy-Item (Join-Path $SourceDir $name) $InstallDir -Force
}
Get-ChildItem $InstallDir -Filter "*.ps1" -File -ErrorAction SilentlyContinue |
    Unblock-File -ErrorAction SilentlyContinue
& $PythonExe -m pip install --upgrade -r (Join-Path $InstallDir "requirements-remote-admin.txt")
if ($LASTEXITCODE -ne 0) { throw "Remote Admin dependency installation failed." }

$LaunchConfig = [ordered]@{
    python_path = $PythonExe
    pythonw_path = $PythonwExe
}
$LaunchConfig |
    ConvertTo-Json -Depth 4 |
    Set-Content `
        -LiteralPath (Join-Path $InstallDir "launch-config.json") `
        -Encoding UTF8 `
        -Force

& (Join-Path $InstallDir "configure-approval-notifier.ps1")

$Desktop = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::CommonDesktopDirectory
)
if ([string]::IsNullOrWhiteSpace($Desktop)) {
    $Desktop = Join-Path $env:PUBLIC "Desktop"
}
$ShortcutPath = Join-Path $Desktop "Windows Login Guard Remote Administration.lnk"
$Shell = New-Object -ComObject WScript.Shell
$Shortcut = $Shell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $PythonwExe
$Shortcut.Arguments = '"' + (Join-Path $InstallDir "remote_admin.pyw") + '"'
$Shortcut.WorkingDirectory = $InstallDir
$Shortcut.Description = "Manage Windows Login Guard protected devices remotely"
$Shortcut.IconLocation = "$PythonwExe,0"
$Shortcut.Save()
[Runtime.InteropServices.Marshal]::ReleaseComObject($Shortcut) | Out-Null
[Runtime.InteropServices.Marshal]::ReleaseComObject($Shell) | Out-Null

Write-Host "Remote Administration app installed." -ForegroundColor Green
Write-Host "Shortcut: $ShortcutPath"
Write-Host "On first launch, enter the server URL, server certificate, and single-use admin-computer registration code."
