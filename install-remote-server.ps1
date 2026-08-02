#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\WindowsLoginGuardRemoteServer",
    [string]$PythonExe = "",
    [string]$BindAddress = "0.0.0.0",
    [ValidateRange(1, 65535)]
    [int]$Port = 8443,
    [string]$DnsName = $env:COMPUTERNAME,
    [string[]]$AdditionalCertificateNames = @(),
    [bool]$OpenFirewall = $true,
    [switch]$RotateCertificate,
    [string]$RemoteAdminInstallDir = "C:\Program Files\WindowsLoginGuardRemoteAdmin",
    [string]$ProtectedPcInstallDir = "C:\Program Files\WindowsLoginGuard"
)

$ErrorActionPreference = "Stop"
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
    & $candidate -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"
    if ($LASTEXITCODE -ne 0) { throw "Python 3.11 or newer is required." }
    return $candidate
}

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Description
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

function Test-PyWin32Runtime {
    param([Parameter(Mandatory = $true)][string]$PythonPath)

    $probeId = [Guid]::NewGuid().ToString("N")
    $tempRoot = [System.IO.Path]::GetTempPath()
    $probePath = Join-Path $tempRoot (
        "wlg-pywin32-probe-$probeId.py"
    )
    $stdoutPath = Join-Path $tempRoot (
        "wlg-pywin32-probe-$probeId.stdout.txt"
    )
    $stderrPath = Join-Path $tempRoot (
        "wlg-pywin32-probe-$probeId.stderr.txt"
    )

    try {
        @'
import pythoncom
import pywintypes
import win32serviceutil
'@ | Set-Content `
            -LiteralPath $probePath `
            -Encoding Ascii `
            -Force

        $process = Start-Process `
            -FilePath $PythonPath `
            -ArgumentList @($probePath) `
            -Wait `
            -PassThru `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath

        if ($process.ExitCode -eq 0) {
            return $true
        }

        if (Test-Path $stderrPath) {
            $errorText = Get-Content `
                -LiteralPath $stderrPath `
                -Raw `
                -ErrorAction SilentlyContinue
            if ($errorText) {
                Write-Verbose $errorText
            }
        }
        return $false
    }
    finally {
        Remove-Item `
            -LiteralPath $probePath `
            -Force `
            -ErrorAction SilentlyContinue
        Remove-Item `
            -LiteralPath $stdoutPath `
            -Force `
            -ErrorAction SilentlyContinue
        Remove-Item `
            -LiteralPath $stderrPath `
            -Force `
            -ErrorAction SilentlyContinue
    }
}

function Ensure-PyWin32Runtime {
    param([Parameter(Mandatory = $true)][string]$PythonPath)

    if (Test-PyWin32Runtime -PythonPath $PythonPath) {
        Write-Host (
            "pywin32 runtime validation passed; " +
            "machine post-install is not required."
        )
        return
    }

    $pythonRoot = Split-Path -Parent $PythonPath
    $candidates = @(
        (Join-Path $pythonRoot "Scripts\pywin32_postinstall.py"),
        (Join-Path $pythonRoot "Lib\site-packages\pywin32_postinstall.py")
    )
    $script = $candidates |
        Where-Object { Test-Path $_ } |
        Select-Object -First 1

    if (-not $script) {
        Invoke-CheckedNative -FilePath $PythonPath `
            -Arguments @(
                "-m",
                "pip",
                "install",
                "--force-reinstall",
                "--no-cache-dir",
                "pywin32"
            ) `
            -Description "pywin32 repair"

        $script = $candidates |
            Where-Object { Test-Path $_ } |
            Select-Object -First 1
    }

    if ($script) {
        Write-Host "Running pywin32 post-install repair: $script"
        & $PythonPath $script -install
        $postInstallExitCode = $LASTEXITCODE

        if ($postInstallExitCode -ne 0) {
            Write-Warning (
                "pywin32 post-install returned exit code " +
                "$postInstallExitCode. This can occur when an existing " +
                "Python service has a pywin32 DLL open. Runtime imports " +
                "will be checked before deciding whether installation " +
                "must stop."
            )
        }
    }

    if (-not (Test-PyWin32Runtime -PythonPath $PythonPath)) {
        throw (
            "pywin32 runtime validation failed. Close Python-based " +
            "Windows services that use this Python installation, reboot " +
            "if necessary, and rerun the installer."
        )
    }

    Write-Host "pywin32 runtime validation passed."
}

$PythonExe = Resolve-Python -RequestedPath $PythonExe
$SourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VersionPath = Join-Path $SourceDir "VERSION"
if (-not (Test-Path -LiteralPath $VersionPath)) {
    throw "VERSION is missing from the extracted release."
}
$ReleaseVersion = (
    Get-Content -LiteralPath $VersionPath -Raw
).Trim()
if ([string]::IsNullOrWhiteSpace($ReleaseVersion)) {
    throw "VERSION is empty in the extracted release."
}

if ([string]::IsNullOrWhiteSpace($DnsName) -or $DnsName -match '[<>/:]') {
    throw (
        "DnsName must be this server's real hostname or resolvable FQDN. " +
        "Do not enter placeholder text or include https://."
    )
}

$WlgService = Get-CimInstance `
    Win32_Service `
    -Filter "Name='WindowsLoginGuard'" `
    -ErrorAction SilentlyContinue
if (-not $WlgService) {
    throw (
        "This PC must already be protected by Windows Login Guard. " +
        "Run install-protected-pc.ps1, complete OTP enrollment, and then " +
        "rerun install-remote-server.ps1."
    )
}

$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentSid = $CurrentIdentity.User.Value
$CurrentProfilePath = Join-Path `
    $env:ProgramData `
    "WindowsLoginGuard\secure\users\$CurrentSid\profile.json"
$CurrentSecretPath = Join-Path `
    $env:ProgramData `
    "WindowsLoginGuard\secure\users\$CurrentSid\secret.dpapi"
if (-not (Test-Path $CurrentProfilePath) -or -not (Test-Path $CurrentSecretPath)) {
    throw (
        "The current Windows account is not enrolled in Windows Login Guard. " +
        "Sign in, complete OTP enrollment, and rerun this installer."
    )
}
$CurrentProfile = Get-Content -LiteralPath $CurrentProfilePath -Raw |
    ConvertFrom-Json
if (-not [bool]$CurrentProfile.is_administrator) {
    throw (
        "The current Windows Login Guard account is not a Windows " +
        "administrator and cannot install the remote-management server."
    )
}
$LinkedUsername = [string]$CurrentProfile.username
Write-Host "Detected protected administrator: $LinkedUsername"

Write-Host (
    "Updating this PC's Windows Login Guard protection before installing " +
    "the remote-management role."
) -ForegroundColor Cyan

& (Join-Path $SourceDir "upgrade.ps1") `
    -InstallDir $ProtectedPcInstallDir
$ProgramDataDir = Join-Path $env:ProgramData "WindowsLoginGuardRemoteServer"
$SecureDir = Join-Path $ProgramDataDir "secure"
$CertPath = Join-Path $SecureDir "server.crt"
$KeyPath = Join-Path $SecureDir "server.key"
$ServiceScript = Join-Path $InstallDir "remote_server.py"

Write-Host "Installing Windows Login Guard Remote Management Server $ReleaseVersion..."
Write-Host "Using Python: $PythonExe"

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $SecureDir -Force | Out-Null

$files = @(
    "remote_server.py",
    "remote_common.py",
    "remote_cert.py",
    "remote_self_test.py",
    "remote_admin.pyw",
    "remote_admin_launcher.pyw",
    "remote_notifier.pyw",
    "open-remote-admin.ps1",
    "configure-approval-notifier.ps1",
    "requirements-remote-admin.txt",
    "requirements-remote-server.txt",
    "README.md",
    "REMOTE_MANAGEMENT.md",
    "VERSION",
    "new-device-enrollment-token.ps1",
    "new-workstation-enrollment-token.ps1",
    "new-remote-admin.ps1",
    "setup-remote-management.ps1",
    "upgrade.ps1",
    "new-protected-pc-installer.ps1",
    "new-protected-pc-registration.ps1",
    "manage-remote-admins.ps1",
    "revoke-remote-object.ps1",
    "list-remote-registrations.ps1",
    "remote-server-tools.ps1",
    "reset-remote-admin-workstation.ps1",
    "uninstall-remote-admin.ps1",
    "uninstall-remote-server.ps1"
)
foreach ($name in $files) {
    Copy-Item (Join-Path $SourceDir $name) $InstallDir -Force
}
Get-ChildItem $InstallDir -Filter "*.ps1" -File -ErrorAction SilentlyContinue |
    Unblock-File -ErrorAction SilentlyContinue
if (Test-Path (Join-Path $SourceDir "docs")) {
    Copy-Item (Join-Path $SourceDir "docs") $InstallDir -Recurse -Force
}

$ProtectedPcPayloadDir = Join-Path $InstallDir "protected-pc-package"
if (Test-Path $ProtectedPcPayloadDir) {
    Remove-Item `
        -LiteralPath $ProtectedPcPayloadDir `
        -Recurse `
        -Force
}
New-Item `
    -ItemType Directory `
    -Path $ProtectedPcPayloadDir `
    -Force |
    Out-Null

$ProtectedPcPayloadFiles = @(
    "install-protected-pc.ps1",
    "install.ps1",
    "upgrade.ps1",
    "common.py",
    "service.py",
    "lock_session.pyw",
    "ui.pyw",
    "admin.pyw",
    "enroll.py",
    "self_test.py",
    "test_otp.py",
    "scope_helpers.ps1",
    "configure.ps1",
    "open-admin.ps1",
    "authorize-initial-enrollment.ps1",
    "revoke-user.ps1",
    "uninstall.ps1",
    "wlg-recovery.cmd",
    "requirements.txt",
    "config.example.json",
    "README.md",
    "VERSION",
    "remote_agent.py",
    "remote_common.py",
    "configure-remote-endpoint.ps1",
    "test-remote-endpoint.ps1",
    "disable-remote-endpoint.ps1",
    "resume-remote-registration.ps1"
)

foreach ($name in $ProtectedPcPayloadFiles) {
    Copy-Item `
        -LiteralPath (Join-Path $SourceDir $name) `
        -Destination $ProtectedPcPayloadDir `
        -Force
}

if (Test-Path (Join-Path $SourceDir "docs")) {
    Copy-Item `
        (Join-Path $SourceDir "docs") `
        $ProtectedPcPayloadDir `
        -Recurse `
        -Force
}

Invoke-CheckedNative -FilePath $PythonExe `
    -Arguments @("-m", "pip", "install", "--upgrade", "-r", (Join-Path $InstallDir "requirements-remote-server.txt")) `
    -Description "remote-server dependency installation"
Invoke-CheckedNative -FilePath $PythonExe `
    -Arguments @(
        "-m", "pip", "install", "--upgrade", "-r",
        (Join-Path $InstallDir "requirements-remote-admin.txt")
    ) `
    -Description "remote-administration dependency installation"
Ensure-PyWin32Runtime -PythonPath $PythonExe
Invoke-CheckedNative -FilePath $PythonExe `
    -Arguments @("-c", "import pyotp, qrcode, cryptography, win32serviceutil; print('Remote server dependencies passed')") `
    -Description "remote-server dependency validation"
Invoke-CheckedNative -FilePath $PythonExe `
    -Arguments @((Join-Path $InstallDir "remote_self_test.py")) `
    -Description "remote-management API self-test"

if ($RotateCertificate -or -not (Test-Path $CertPath) -or -not (Test-Path $KeyPath)) {
    $names = @($DnsName, $env:COMPUTERNAME, "localhost", "127.0.0.1") + $AdditionalCertificateNames
    $certArgs = @(
        (Join-Path $InstallDir "remote_cert.py"),
        "--output-dir", $SecureDir
    )
    foreach ($name in ($names | Select-Object -Unique)) {
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $certArgs += @("--name", $name)
        }
    }
    Invoke-CheckedNative -FilePath $PythonExe `
        -Arguments $certArgs `
        -Description "TLS certificate generation"
}
else {
    Write-Host "Preserving the existing management-server TLS certificate."
}

icacls $ProgramDataDir /inheritance:r | Out-Null
icacls $ProgramDataDir /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
icacls $SecureDir /inheritance:r | Out-Null
icacls $SecureDir /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

Invoke-CheckedNative -FilePath $PythonExe `
    -Arguments @(
        $ServiceScript,
        "init",
        "--bind", $BindAddress,
        "--port", $Port.ToString(),
        "--cert", $CertPath,
        "--key", $KeyPath
    ) `
    -Description "management-server initialization"

if (Get-Service WindowsLoginGuardManagementServer -ErrorAction SilentlyContinue) {
    Stop-Service WindowsLoginGuardManagementServer -Force -ErrorAction SilentlyContinue
    & $PythonExe $ServiceScript remove | Out-Null
    Start-Sleep -Seconds 1
}
Invoke-CheckedNative -FilePath $PythonExe `
    -Arguments @($ServiceScript, "--startup", "auto", "install") `
    -Description "management-server service installation"
sc.exe failure WindowsLoginGuardManagementServer reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to configure management-server recovery actions." }
sc.exe failureflag WindowsLoginGuardManagementServer 1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to enable management-server failure actions." }

if ($OpenFirewall) {
    $ruleName = "Windows Login Guard Remote Management ($Port)"

    Get-NetFirewallRule `
        -DisplayName $ruleName `
        -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule `
            -ErrorAction SilentlyContinue

    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Description (
            "Allows Windows Login Guard protected devices and administrator " +
            "computers on the local subnet to reach the management server."
        ) `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort $Port `
        -Profile Any `
        -RemoteAddress LocalSubnet |
        Out-Null

    $createdRule = Get-NetFirewallRule `
        -DisplayName $ruleName `
        -ErrorAction Stop
    $portFilter = $createdRule |
        Get-NetFirewallPortFilter
    $addressFilter = $createdRule |
        Get-NetFirewallAddressFilter

    if (
        $createdRule.Enabled -ne "True" -or
        $createdRule.Direction -ne "Inbound" -or
        $createdRule.Action -ne "Allow" -or
        $createdRule.Profile -ne "Any" -or
        $portFilter.LocalPort -notcontains [string]$Port -or
        $addressFilter.RemoteAddress -notcontains "LocalSubnet"
    ) {
        throw (
            "The Windows Firewall rule for remote management could not " +
            "be validated."
        )
    }

    Write-Host (
        "Windows Firewall allows TCP $Port on Domain, Private, and Public " +
        "profiles for LocalSubnet only."
    )
}

Start-Service WindowsLoginGuardManagementServer
(Get-Service WindowsLoginGuardManagementServer).WaitForStatus(
    [System.ServiceProcess.ServiceControllerStatus]::Running,
    [TimeSpan]::FromSeconds(30)
)

$SetupDefaults = [ordered]@{
    server_url = "https://${DnsName}:$Port"
    server_certificate = $CertPath
}
$SetupDefaults |
    ConvertTo-Json -Depth 4 |
    Set-Content `
        -LiteralPath (Join-Path $InstallDir "remote-setup.json") `
        -Encoding UTF8 `
        -Force


$PythonwExe = Join-Path (Split-Path -Parent $PythonExe) "pythonw.exe"
if (-not (Test-Path $PythonwExe)) {
    $PythonwExe = $PythonExe
}
New-Item -ItemType Directory -Path $RemoteAdminInstallDir -Force | Out-Null
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
    Copy-Item (Join-Path $SourceDir $name) $RemoteAdminInstallDir -Force
}
Get-ChildItem $RemoteAdminInstallDir -Filter "*.ps1" -File |
    Unblock-File -ErrorAction SilentlyContinue

$Desktop = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::DesktopDirectory
)
if ([string]::IsNullOrWhiteSpace($Desktop)) {
    $Desktop = Join-Path $env:USERPROFILE "Desktop"
}
$LaunchConfig = [ordered]@{
    python_path = $PythonExe
    pythonw_path = $PythonwExe
}
$LaunchConfig |
    ConvertTo-Json -Depth 4 |
    Set-Content `
        -LiteralPath (
            Join-Path $RemoteAdminInstallDir "launch-config.json"
        ) `
        -Encoding UTF8 `
        -Force

$RemoteAdminImportProbe = @"
import sys
sys.path.insert(0, r'$RemoteAdminInstallDir')
import remote_common
import remote_admin
import remote_admin_launcher
import remote_notifier
print('Remote Administration and notifier startup modules validated')
"@
Invoke-CheckedNative `
    -FilePath $PythonExe `
    -Arguments @("-c", $RemoteAdminImportProbe) `
    -Description "remote-administration startup validation"

$RemoteAdminShortcut = Join-Path `
    $Desktop `
    "Windows Login Guard Remote Administration.lnk"
$Shell = New-Object -ComObject WScript.Shell
$Shortcut = $Shell.CreateShortcut($RemoteAdminShortcut)
$Shortcut.TargetPath = (
    Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
)
$Shortcut.Arguments = (
    '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' +
    (Join-Path $RemoteAdminInstallDir "open-remote-admin.ps1") +
    '"'
)
$Shortcut.WorkingDirectory = $RemoteAdminInstallDir
$Shortcut.Description = "Manage Windows Login Guard protected devices"
$Shortcut.IconLocation = "$PythonwExe,0"
$Shortcut.Save()
[Runtime.InteropServices.Marshal]::ReleaseComObject($Shortcut) | Out-Null
[Runtime.InteropServices.Marshal]::ReleaseComObject($Shell) | Out-Null

Write-Host ""
Write-Host (
    "Linking the detected protected administrator automatically. " +
    "The existing OTP will be requested when Remote Administration opens."
) -ForegroundColor Cyan
Invoke-CheckedNative -FilePath $PythonExe `
    -Arguments @(
        $ServiceScript,
        "link-local-admin",
        "--sid", $CurrentSid,
        "--server-url", "https://localhost:$Port",
        "--cert", $CertPath,
        "--workstation-label", "$env:COMPUTERNAME - $LinkedUsername"
    ) `
    -Description "existing administrator linking"

$WlgInstallDir = $ProtectedPcInstallDir
if (-not (Test-Path $WlgInstallDir)) {
    throw "Windows Login Guard installation directory was not found: $WlgInstallDir"
}
foreach ($name in @("remote_agent.py", "remote_common.py", "VERSION")) {
    Copy-Item (Join-Path $SourceDir $name) $WlgInstallDir -Force
}

$AgentConfigPath = Join-Path `
    $env:ProgramData `
    "WindowsLoginGuard\secure\remote-agent.json"
$RegisterLocalEndpoint = $true
if (Test-Path $AgentConfigPath) {
    try {
        $AgentConfig = Get-Content -LiteralPath $AgentConfigPath -Raw |
            ConvertFrom-Json
        if (
            [string]$AgentConfig.server_url -eq "https://localhost:$Port" -and
            -not [string]::IsNullOrWhiteSpace([string]$AgentConfig.device_id)
        ) {
            $RegisterLocalEndpoint = $false
        }
    }
    catch {
        $RegisterLocalEndpoint = $true
    }
}

if ($RegisterLocalEndpoint) {
    $TokenOutput = & $PythonExe `
        $ServiceScript `
        create-enrollment-token `
        --kind device `
        --label "$env:COMPUTERNAME (management server)" `
        --hours 1 `
        2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create the local protected-device registration code."
    }
    $CodeLine = $TokenOutput |
        ForEach-Object { [string]$_ } |
        Where-Object { $_ -like "Registration code: *" } |
        Select-Object -Last 1
    if (-not $CodeLine) {
        throw "The local protected-device registration code was not returned."
    }
    $LocalRegistrationCode = $CodeLine.Substring(
        "Registration code: ".Length
    ).Trim()

    & (Join-Path $SourceDir "configure-remote-endpoint.ps1") `
        -ServerUrl "https://localhost:$Port" `
        -RegistrationCode $LocalRegistrationCode `
        -ServerCertificate $CertPath `
        -DisplayName "$env:COMPUTERNAME (Management Server)" `
        -InstallDir $WlgInstallDir
}
else {
    Write-Host "This server PC is already registered as a protected device."
}

Write-Host ""
Write-Host "Remote Management Server installation complete." `
    -ForegroundColor Green
Write-Host ""
Write-Host "Protected administrator: $LinkedUsername"
Write-Host "Server URL: https://${DnsName}:$Port"
Write-Host "Remote Administration shortcut: $RemoteAdminShortcut"
Write-Host "This PC is registered as a protected managed device."
Write-Host "No separate remote-administrator OTP was created."
Write-Host ""
& (Join-Path $RemoteAdminInstallDir "configure-approval-notifier.ps1")
Write-Host ""
Write-Host "Opening Remote Administration..."
& (Join-Path $RemoteAdminInstallDir "open-remote-admin.ps1")
Write-Host ""
Write-Host "To add another protected PC, run:"
Write-Host ""
Write-Host (
    "  & '" +
    (Join-Path $InstallDir "new-protected-pc-installer.ps1") +
    "' -Label '<PC name>'"
)
