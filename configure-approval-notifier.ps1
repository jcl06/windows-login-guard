[CmdletBinding()]
param(
    [switch]$Disable
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$RunName = "WindowsLoginGuardApprovalNotifier"
$NotifierPath = Join-Path $InstallDir "remote_notifier.pyw"
$LaunchConfigPath = Join-Path $InstallDir "launch-config.json"

function Stop-ExistingNotifier {
    Get-CimInstance Win32_Process `
        -Filter "Name = 'pythonw.exe' OR Name = 'python.exe'" `
        -ErrorAction SilentlyContinue |
        Where-Object {
            [string]$_.CommandLine -like "*remote_notifier.pyw*"
        } |
        ForEach-Object {
            Stop-Process `
                -Id $_.ProcessId `
                -Force `
                -ErrorAction SilentlyContinue
        }
}

New-Item -Path $RunKey -Force | Out-Null

if ($Disable) {
    Stop-ExistingNotifier
    Remove-ItemProperty `
        -Path $RunKey `
        -Name $RunName `
        -ErrorAction SilentlyContinue
    Write-Host "Approval notifier disabled for the current Windows account."
    return
}

if (-not (Test-Path $LaunchConfigPath)) {
    throw "Remote Administration launch configuration is missing."
}
if (-not (Test-Path $NotifierPath)) {
    throw "Approval notifier application is missing."
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
    throw "The configured Python GUI executable was not found."
}

$Command = (
    '"' + $PythonwExe + '" "' + $NotifierPath + '"'
)
New-ItemProperty `
    -Path $RunKey `
    -Name $RunName `
    -PropertyType String `
    -Value $Command `
    -Force |
    Out-Null

Stop-ExistingNotifier
Start-Process `
    -FilePath $PythonwExe `
    -ArgumentList @('"' + $NotifierPath + '"') `
    -WorkingDirectory $InstallDir

Write-Host (
    "Approval notifier enabled for the current Windows account. " +
    "It will start automatically at sign-in."
)
