#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet("ProtectedPc", "ManagementServer", "RemoteAdmin")]
    [string]$Role = "ProtectedPc",

    [string]$PythonExe = "",

    [string]$DnsName = $env:COMPUTERNAME,

    [ValidateRange(1, 65535)]
    [int]$Port = 8443,

    [switch]$SkipPackageIndexCheck
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$script:Results = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("PASS", "WARN", "FAIL")]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [string]$Check,

        [Parameter(Mandatory = $true)]
        [string]$Details
    )

    $script:Results.Add([pscustomobject]@{
        Status = $Status
        Check = $Check
        Details = $Details
    })
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Resolve-WlgPython {
    param([string]$RequestedPath)

    if ($RequestedPath) {
        if (Test-Path -LiteralPath $RequestedPath -PathType Leaf) {
            return (Resolve-Path -LiteralPath $RequestedPath).Path
        }

        $requested = Get-Command `
            $RequestedPath `
            -ErrorAction SilentlyContinue
        if ($requested) {
            return $requested.Source
        }
        return $null
    }

    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            # Windows PowerShell 5.1 converts native stderr to ErrorRecord
            # objects. Do not let a launcher diagnostic terminate preflight.
            $ErrorActionPreference = "Continue"
            $output = @(
                & $launcher.Source `
                    -3 `
                    -c `
                    "import sys; print(sys.executable)" 2>&1
            )
            $launcherExitCode = $LASTEXITCODE
        }
        catch {
            $output = @($_)
            $launcherExitCode = 1
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }

        if (($launcherExitCode -eq 0) -and $output) {
            $candidate = (
                $output |
                Select-Object -Last 1
            ).ToString().Trim()
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                return $candidate
            }
        }
    }

    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($python -and (Test-Path -LiteralPath $python.Source)) {
        return $python.Source
    }

    return $null
}

function Invoke-PythonProbe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonPath,

        [Parameter(Mandatory = $true)]
        [string]$Code
    )

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 turns text written by a native program to
        # stderr into NativeCommandError records. Probes intentionally run
        # commands that may fail, so stderr must be captured rather than
        # treated as a terminating PowerShell error.
        $ErrorActionPreference = "Continue"
        $rawOutput = @(& $PythonPath -c $Code 2>&1)
        $exitCode = $LASTEXITCODE
    }
    catch {
        $rawOutput = @($_)
        $exitCode = 1
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    $outputLines = @(
        $rawOutput |
        ForEach-Object {
            if (
                $_ -is
                [System.Management.Automation.ErrorRecord]
            ) {
                $_.Exception.Message
            }
            else {
                [string]$_
            }
        }
    )

    return [pscustomobject]@{
        ExitCode = $exitCode
        Output = (
            $outputLines -join [Environment]::NewLine
        ).Trim()
    }
}

function Invoke-PythonCommandProbe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonPath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $rawOutput = @(& $PythonPath @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    catch {
        $rawOutput = @($_)
        $exitCode = 1
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    $outputLines = @(
        $rawOutput |
        ForEach-Object {
            if (
                $_ -is
                [System.Management.Automation.ErrorRecord]
            ) {
                $_.Exception.Message
            }
            else {
                [string]$_
            }
        }
    )

    return [pscustomobject]@{
        ExitCode = $exitCode
        Output = (
            $outputLines -join [Environment]::NewLine
        ).Trim()
    }
}


function Test-SourceFiles {
    param([string]$SourceDir)

    $required = @(
        "install-protected-pc.ps1",
        "install.ps1",
        "requirements.txt",
        "common.py",
        "service.py",
        "ui.pyw",
        "admin.pyw"
    )

    if ($Role -eq "ManagementServer") {
        $required += @(
            "install-remote-server.ps1",
            "remote_server.py",
            "remote_admin.pyw",
            "remote_agent.py",
            "remote_cert.py",
            "requirements-remote-server.txt",
            "requirements-remote-admin.txt"
        )
    }
    elseif ($Role -eq "RemoteAdmin") {
        $required += @(
            "install-remote-admin.ps1",
            "remote_admin.pyw",
            "remote_notifier.pyw",
            "requirements-remote-admin.txt"
        )
    }

    $missing = @(
        $required |
        Where-Object {
            -not (Test-Path -LiteralPath (
                Join-Path $SourceDir $_
            ) -PathType Leaf)
        }
    )

    if ($missing.Count -eq 0) {
        Add-Check `
            -Status PASS `
            -Check "Release contents" `
            -Details "All files required for role $Role are present."
    }
    else {
        Add-Check `
            -Status FAIL `
            -Check "Release contents" `
            -Details (
                "Missing required file(s): " +
                ($missing -join ", ")
            )
    }
}

$sourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "Windows Login Guard prerequisite check" `
    -ForegroundColor Cyan
Write-Host "Role: $Role"
Write-Host ""

if ($env:OS -eq "Windows_NT") {
    Add-Check `
        -Status PASS `
        -Check "Operating system" `
        -Details "Windows detected."
}
else {
    Add-Check `
        -Status FAIL `
        -Check "Operating system" `
        -Details "Windows Login Guard requires Windows."
}

try {
    $os = Get-CimInstance `
        -ClassName Win32_OperatingSystem `
        -ErrorAction Stop

    if ([string]$os.OSArchitecture -match "64") {
        Add-Check `
            -Status PASS `
            -Check "OS architecture" `
            -Details "$($os.Caption), $($os.OSArchitecture)."
    }
    else {
        Add-Check `
            -Status FAIL `
            -Check "OS architecture" `
            -Details (
                "64-bit Windows is required; detected " +
                "$($os.OSArchitecture)."
            )
    }

    if ([int]$os.ProductType -eq 1) {
        Add-Check `
            -Status PASS `
            -Check "Windows product type" `
            -Details "Windows client/workstation edition detected."
    }
    else {
        Add-Check `
            -Status WARN `
            -Check "Windows product type" `
            -Details (
                "Windows Server is not validated by this release: " +
                "$($os.Caption)."
            )
    }

    if ([version]$os.Version -ge [version]"10.0") {
        Add-Check `
            -Status PASS `
            -Check "Windows version" `
            -Details "$($os.Version), build $($os.BuildNumber)."
    }
    else {
        Add-Check `
            -Status FAIL `
            -Check "Windows version" `
            -Details "Windows 10 or newer is required."
    }
}
catch {
    Add-Check `
        -Status FAIL `
        -Check "Windows version" `
        -Details $_.Exception.Message
}

if ([Environment]::Is64BitOperatingSystem) {
    Add-Check `
        -Status PASS `
        -Check "64-bit operating system" `
        -Details "The Windows operating system is 64-bit."
}
else {
    Add-Check `
        -Status FAIL `
        -Check "64-bit operating system" `
        -Details "A 64-bit Windows installation is required."
}

if ($PSVersionTable.PSVersion -ge [version]"5.1") {
    Add-Check `
        -Status PASS `
        -Check "PowerShell" `
        -Details "PowerShell $($PSVersionTable.PSVersion)."
}
else {
    Add-Check `
        -Status FAIL `
        -Check "PowerShell" `
        -Details "PowerShell 5.1 or newer is required."
}

if (Test-Administrator) {
    Add-Check `
        -Status PASS `
        -Check "Administrator elevation" `
        -Details "The current PowerShell process is elevated."
}
else {
    Add-Check `
        -Status FAIL `
        -Check "Administrator elevation" `
        -Details (
            "Open PowerShell with Run as administrator before installing."
        )
}

Test-SourceFiles -SourceDir $sourceDir

$systemDriveName = $env:SystemDrive.TrimEnd(":")
$systemDrive = Get-PSDrive `
    -Name $systemDriveName `
    -ErrorAction SilentlyContinue

if ($systemDrive) {
    $freeMb = [math]::Round($systemDrive.Free / 1MB)
    $recommendedMb = switch ($Role) {
        "ManagementServer" { 500 }
        "RemoteAdmin" { 200 }
        default { 300 }
    }

    if ($freeMb -ge $recommendedMb) {
        Add-Check `
            -Status PASS `
            -Check "Free disk space" `
            -Details (
                "$freeMb MB available; " +
                "$recommendedMb MB recommended for $Role."
            )
    }
    else {
        Add-Check `
            -Status WARN `
            -Check "Free disk space" `
            -Details (
                "$freeMb MB available; at least $recommendedMb MB is " +
                "recommended for $Role."
            )
    }
}

$python = Resolve-WlgPython -RequestedPath $PythonExe
if (-not $python) {
    Add-Check `
        -Status FAIL `
        -Check "Python" `
        -Details (
            "64-bit Python 3.11+ was not found. Install CPython for all " +
            "users or supply -PythonExe."
        )
}
else {
    $identityProbe = Invoke-PythonProbe `
        -PythonPath $python `
        -Code (
            "import json, struct, sys; print(json.dumps({" +
            "'executable': sys.executable, " +
            "'version': list(sys.version_info[:3]), " +
            "'bits': struct.calcsize('P') * 8}))"
        )

    if ($identityProbe.ExitCode -ne 0) {
        Add-Check `
            -Status FAIL `
            -Check "Python runtime" `
            -Details $identityProbe.Output
    }
    else {
        try {
            $pythonInfo = $identityProbe.Output | ConvertFrom-Json
            $pythonVersion = [version](
                [string]$pythonInfo.version[0] + "." +
                [string]$pythonInfo.version[1] + "." +
                [string]$pythonInfo.version[2]
            )

            if (
                $pythonVersion -ge [version]"3.11" -and
                [int]$pythonInfo.bits -eq 64
            ) {
                Add-Check `
                    -Status PASS `
                    -Check "Python runtime" `
                    -Details (
                        "Python $pythonVersion, 64-bit: " +
                        "$($pythonInfo.executable). The optional py.exe " +
                        "launcher is not required."
                    )
            }
            else {
                Add-Check `
                    -Status FAIL `
                    -Check "Python runtime" `
                    -Details (
                        "Python 3.11+ 64-bit is required; detected " +
                        "$pythonVersion, $($pythonInfo.bits)-bit."
                    )
            }

            $pythonExecutable = [string]$pythonInfo.executable
            $programFilesRoot = [IO.Path]::GetFullPath(
                $env:ProgramFiles
            ).TrimEnd("\") + "\"
            $userRoots = @(
                $env:USERPROFILE,
                $env:LOCALAPPDATA
            ) |
                Where-Object { $_ } |
                ForEach-Object {
                    [IO.Path]::GetFullPath(
                        [string]$_
                    ).TrimEnd("\") + "\"
                }
            $windowsAppsRoot = [IO.Path]::GetFullPath(
                (Join-Path $env:ProgramFiles "WindowsApps")
            ).TrimEnd("\") + "\"
            $normalizedPython = [IO.Path]::GetFullPath(
                $pythonExecutable
            )

            $blocked = $false
            foreach ($root in $userRoots) {
                if (
                    $normalizedPython.StartsWith(
                        $root,
                        [StringComparison]::OrdinalIgnoreCase
                    )
                ) {
                    $blocked = $true
                    break
                }
            }

            if (
                -not $blocked -and
                $normalizedPython.StartsWith(
                    $windowsAppsRoot,
                    [StringComparison]::OrdinalIgnoreCase
                )
            ) {
                $blocked = $true
            }

            if ($blocked) {
                Add-Check `
                    -Status FAIL `
                    -Check "Python installation scope" `
                    -Details (
                        "Python is installed in a user-specific or Microsoft " +
                        "Store location: $normalizedPython. Install it for all " +
                        "users under Program Files."
                    )
            }
            elseif (
                $normalizedPython.StartsWith(
                    $programFilesRoot,
                    [StringComparison]::OrdinalIgnoreCase
                )
            ) {
                Add-Check `
                    -Status PASS `
                    -Check "Python installation scope" `
                    -Details (
                        "Machine-wide Program Files installation detected: " +
                        $normalizedPython
                    )
            }
            else {
                Add-Check `
                    -Status WARN `
                    -Check "Python installation scope" `
                    -Details (
                        "Python is outside Program Files. Confirm LocalSystem " +
                        "can read and execute: $normalizedPython"
                    )
            }
        }
        catch {
            Add-Check `
                -Status FAIL `
                -Check "Python runtime" `
                -Details (
                    "Python identity output could not be parsed: " +
                    $identityProbe.Output
                )
        }
    }

    $stdlibProbe = Invoke-PythonProbe `
        -PythonPath $python `
        -Code "import pip, tkinter, ssl, sqlite3; print('ok')"

    if ($stdlibProbe.ExitCode -eq 0) {
        Add-Check `
            -Status PASS `
            -Check "Python standard components" `
            -Details "pip, tkinter, SSL, and SQLite imports succeeded."
    }
    else {
        Add-Check `
            -Status FAIL `
            -Check "Python standard components" `
            -Details (
                "pip, tkinter, SSL, or SQLite is unavailable: " +
                $stdlibProbe.Output
            )
    }

    $moduleList = switch ($Role) {
        "ManagementServer" {
            @("win32serviceutil", "pyotp", "qrcode", "PIL", "cryptography")
        }
        "RemoteAdmin" {
            @("win32serviceutil")
        }
        default {
            @("win32serviceutil", "pyotp", "qrcode", "PIL")
        }
    }

    $moduleCode = (
        $moduleList |
        ForEach-Object { "import $_" }
    ) -join "; "

    $dependencyProbe = Invoke-PythonProbe `
        -PythonPath $python `
        -Code ($moduleCode + "; print('ok')")

    if ($dependencyProbe.ExitCode -eq 0) {
        Add-Check `
            -Status PASS `
            -Check "Python dependencies" `
            -Details (
                "Required modules are already importable: " +
                ($moduleList -join ", ")
            )
    }
    else {
        Add-Check `
            -Status WARN `
            -Check "Python dependencies" `
            -Details (
                "Some role dependencies are not installed yet. The installer " +
                "will use pip to install them. Probe output: " +
                $dependencyProbe.Output
            )
    }

    if (-not $SkipPackageIndexCheck) {
        $requirementsFile = switch ($Role) {
            "ManagementServer" {
                Join-Path $sourceDir "requirements-remote-server.txt"
            }
            "RemoteAdmin" {
                Join-Path $sourceDir "requirements-remote-admin.txt"
            }
            default {
                Join-Path $sourceDir "requirements.txt"
            }
        }

        $pipProbe = Invoke-PythonCommandProbe `
            -PythonPath $python `
            -Arguments @(
                "-m",
                "pip",
                "install",
                "--dry-run",
                "--disable-pip-version-check",
                "--no-input",
                "--requirement",
                $requirementsFile
            )

        if ($pipProbe.ExitCode -eq 0) {
            Add-Check `
                -Status PASS `
                -Check "Python package resolution" `
                -Details (
                    "pip successfully resolved the packages required for " +
                    "$Role without installing them."
                )
        }
        else {
            Add-Check `
                -Status FAIL `
                -Check "Python package resolution" `
                -Details (
                    "pip could not resolve the required packages. The " +
                    "installer also uses pip and is likely to fail until " +
                    "certificate, proxy, private-mirror, or connectivity " +
                    "configuration is corrected. Probe output: " +
                    $pipProbe.Output
                )
        }
    }
    else {
        Add-Check `
            -Status WARN `
            -Check "Python package resolution" `
            -Details (
                "The pip resolution test was skipped. Confirm the installer " +
                "can reach its configured package repository."
            )
    }
}

try {
    $shell = New-Object -ComObject WScript.Shell
    [Runtime.InteropServices.Marshal]::ReleaseComObject($shell) |
        Out-Null
    Add-Check `
        -Status PASS `
        -Check "Windows Script Host" `
        -Details "Shortcut creation COM interface is available."
}
catch {
    Add-Check `
        -Status WARN `
        -Check "Windows Script Host" `
        -Details (
            "The installer may be unable to create desktop shortcuts: " +
            $_.Exception.Message
        )
}

$timeService = Get-Service W32Time -ErrorAction SilentlyContinue
if ($timeService) {
    if ($timeService.Status -eq "Running") {
        Add-Check `
            -Status PASS `
            -Check "Windows Time" `
            -Details "Windows Time service is running."
    }
    else {
        Add-Check `
            -Status WARN `
            -Check "Windows Time" `
            -Details (
                "Windows Time service currently reports " +
                "$($timeService.Status). This alone does not prove the " +
                "clock is wrong, but confirm automatic date, time, and time " +
                "zone before TOTP enrollment."
            )
    }
}
else {
    Add-Check `
        -Status WARN `
        -Check "Windows Time" `
        -Details "Windows Time service was not found."
}

if ($Role -eq "ManagementServer") {
    $service = Get-CimInstance `
        -ClassName Win32_Service `
        -Filter "Name='WindowsLoginGuard'" `
        -ErrorAction SilentlyContinue

    if ($service) {
        Add-Check `
            -Status PASS `
            -Check "Local WLG service" `
            -Details (
                "WindowsLoginGuard is installed; state: $($service.State)."
            )
    }
    else {
        Add-Check `
            -Status FAIL `
            -Check "Local WLG service" `
            -Details (
                "Install and enroll the protected-PC role on this PC before " +
                "installing the management server."
            )
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $sid = $identity.User.Value
    $profilePath = Join-Path `
        $env:ProgramData `
        "WindowsLoginGuard\secure\users\$sid\profile.json"
    $secretPath = Join-Path `
        $env:ProgramData `
        "WindowsLoginGuard\secure\users\$sid\secret.dpapi"

    if (
        (Test-Path -LiteralPath $profilePath -PathType Leaf) -and
        (Test-Path -LiteralPath $secretPath -PathType Leaf)
    ) {
        try {
            $profile = Get-Content `
                -LiteralPath $profilePath `
                -Raw |
                ConvertFrom-Json

            if ([bool]$profile.is_administrator) {
                Add-Check `
                    -Status PASS `
                    -Check "Enrolled administrator" `
                    -Details (
                        "The current Windows account is an enrolled WLG " +
                        "administrator."
                    )
            }
            else {
                Add-Check `
                    -Status FAIL `
                    -Check "Enrolled administrator" `
                    -Details (
                        "The current WLG account is not recorded as an " +
                        "administrator."
                    )
            }
        }
        catch {
            Add-Check `
                -Status FAIL `
                -Check "Enrolled administrator" `
                -Details (
                    "The current WLG profile could not be read: " +
                    $_.Exception.Message
                )
        }
    }
    else {
        Add-Check `
            -Status FAIL `
            -Check "Enrolled administrator" `
            -Details (
                "The current Windows account has not completed WLG " +
                "enrollment."
            )
    }

    if (
        [string]::IsNullOrWhiteSpace($DnsName) -or
        $DnsName -match '[<>/:]'
    ) {
        Add-Check `
            -Status FAIL `
            -Check "Server DNS name" `
            -Details (
                "Supply a real hostname or resolvable FQDN without https://."
            )
    }
    else {
        Add-Check `
            -Status PASS `
            -Check "Server DNS name syntax" `
            -Details $DnsName

        $resolver = Get-Command `
            Resolve-DnsName `
            -ErrorAction SilentlyContinue
        if ($resolver) {
            try {
                $resolved = Resolve-DnsName `
                    -Name $DnsName `
                    -ErrorAction Stop |
                    Where-Object {
                        $_.Type -in @("A", "AAAA")
                    }

                if ($resolved) {
                    Add-Check `
                        -Status PASS `
                        -Check "Server DNS resolution" `
                        -Details (
                            "$DnsName resolves on this PC. Confirm protected " +
                            "PCs resolve it to the same server."
                        )
                }
                else {
                    Add-Check `
                        -Status WARN `
                        -Check "Server DNS resolution" `
                        -Details (
                            "$DnsName returned no A or AAAA record. Verify " +
                            "client-side resolution before deployment."
                        )
                }
            }
            catch {
                Add-Check `
                    -Status WARN `
                    -Check "Server DNS resolution" `
                    -Details (
                        "$DnsName did not resolve through DNS on this PC. " +
                        "Computer-name resolution may still work locally, but " +
                        "protected PCs must resolve the certificate name."
                    )
            }
        }
    }

    $existingListener = Get-NetTCPConnection `
        -State Listen `
        -LocalPort $Port `
        -ErrorAction SilentlyContinue

    if ($existingListener) {
        $serverService = Get-Service `
            WindowsLoginGuardManagementServer `
            -ErrorAction SilentlyContinue

        if ($serverService) {
            Add-Check `
                -Status PASS `
                -Check "Management port" `
                -Details (
                    "TCP $Port is already used by the installed WLG " +
                    "management server; an upgrade may continue."
                )
        }
        else {
            Add-Check `
                -Status FAIL `
                -Check "Management port" `
                -Details (
                    "TCP $Port is already listening under another process."
                )
        }
    }
    else {
        Add-Check `
            -Status PASS `
            -Check "Management port" `
            -Details "TCP $Port is not currently listening."
    }

    if (
        (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue) -and
        (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)
    ) {
        Add-Check `
            -Status PASS `
            -Check "Windows Firewall administration" `
            -Details "Firewall management cmdlets are available."
    }
    else {
        Add-Check `
            -Status FAIL `
            -Check "Windows Firewall administration" `
            -Details "Required Windows Firewall cmdlets are unavailable."
    }
}

Add-Check `
    -Status WARN `
    -Check "Manual preparation" `
    -Details (
        "Confirm a TOTP authenticator, correct date/time, and a separate " +
        "storage location for recovery material."
    )

Write-Host ""
foreach ($result in $script:Results) {
    $color = switch ($result.Status) {
        "PASS" { "Green" }
        "WARN" { "Yellow" }
        default { "Red" }
    }

    Write-Host ("[{0}] {1}" -f $result.Status, $result.Check) `
        -ForegroundColor $color
    Write-Host ("       " + $result.Details)
}

$passCount = @(
    $script:Results |
    Where-Object { $_.Status -eq "PASS" }
).Count
$warnCount = @(
    $script:Results |
    Where-Object { $_.Status -eq "WARN" }
).Count
$failCount = @(
    $script:Results |
    Where-Object { $_.Status -eq "FAIL" }
).Count

Write-Host ""
Write-Host (
    "Summary: {0} PASS, {1} WARN, {2} FAIL" -f
    $passCount,
    $warnCount,
    $failCount
)

if ($failCount -gt 0) {
    Write-Host (
        "Prerequisite check failed. Resolve all FAIL results before " +
        "installation."
    ) -ForegroundColor Red
    exit 1
}

Write-Host (
    "Mandatory prerequisite checks passed. Review WARN results before " +
    "installation."
) -ForegroundColor Green
exit 0
