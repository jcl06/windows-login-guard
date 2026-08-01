[CmdletBinding()]
param(
    [switch]$ShowLog,

    [switch]$Console
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LaunchConfigPath = Join-Path $InstallDir "launch-config.json"
$AppPath = Join-Path $InstallDir "remote_admin_launcher.pyw"
$ClientDataDir = Join-Path `
    $env:APPDATA `
    "WindowsLoginGuardRemoteAdmin"
$ClientConfigPath = Join-Path $ClientDataDir "client.json"
$ClientTokenPath = Join-Path `
    $ClientDataDir `
    "workstation-token.dpapi"
$LogPath = Join-Path `
    $env:LOCALAPPDATA `
    "WindowsLoginGuardRemoteAdmin\remote-admin.log"

function Show-LaunchError {
    param([Parameter(Mandatory = $true)][string]$Message)

    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show(
        $Message,
        "Windows Login Guard Remote Administration",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Error
    ) | Out-Null
}

if ($ShowLog) {
    if (Test-Path $LogPath) {
        Invoke-Item $LogPath
    }
    else {
        Show-LaunchError "No Remote Administration log exists yet."
    }
    return
}

try {
    if (-not (Test-Path $LaunchConfigPath)) {
        throw (
            "Remote Administration launch configuration is missing. " +
            "Rerun install-remote-server.ps1."
        )
    }

    $LaunchConfig = Get-Content `
        -LiteralPath $LaunchConfigPath `
        -Raw |
        ConvertFrom-Json

    $PythonwExe = [string]$LaunchConfig.pythonw_path
    if (
        [string]::IsNullOrWhiteSpace($PythonwExe) -or
        -not (Test-Path $PythonwExe)
    ) {
        throw (
            "The configured Python GUI executable was not found. " +
            "Rerun install-remote-server.ps1."
        )
    }

    if (-not (Test-Path $AppPath)) {
        throw "Remote Administration application files are missing."
    }

    $PythonExe = [string]$LaunchConfig.python_path
    if (
        [string]::IsNullOrWhiteSpace($PythonExe) -or
        -not (Test-Path $PythonExe)
    ) {
        throw (
            "The configured Python executable was not found. " +
            "Rerun install-remote-server.ps1."
        )
    }

    if ($Console) {
        Push-Location $InstallDir
        try {
            & $PythonExe $AppPath
            if ($LASTEXITCODE -ne 0) {
                throw (
                    "Remote Administration exited with code " +
                    "$LASTEXITCODE."
                )
            }
        }
        finally {
            Pop-Location
        }
        return
    }

    $process = Start-Process `
        -FilePath $PythonwExe `
        -ArgumentList @('"' + $AppPath + '"') `
        -WorkingDirectory $InstallDir `
        -PassThru

    Start-Sleep -Seconds 2
    if ($process.HasExited -and $process.ExitCode -ne 0) {
        $details = ""
        if (Test-Path $LogPath) {
            $details = Get-Content `
                -LiteralPath $LogPath `
                -Tail 30 `
                -ErrorAction SilentlyContinue |
                Out-String
        }
        throw (
            "Remote Administration exited during startup." +
            $(if ($details) { "`n`n$details" } else { "" })
        )
    }
}
catch {
    $message = $_.Exception.Message
    New-Item `
        -ItemType Directory `
        -Path (Split-Path -Parent $LogPath) `
        -Force |
        Out-Null
    Add-Content `
        -LiteralPath $LogPath `
        -Value (
            "$(Get-Date -Format o) Launcher error: $message"
        )
    Show-LaunchError (
        $message +
        "`n`nDiagnostic log:`n" +
        $LogPath
    )
}
