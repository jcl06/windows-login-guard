#Requires -RunAsAdministrator
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SetupDefaultsPath = Join-Path $InstallDir "remote-setup.json"

function Read-RequiredValue {
    param([Parameter(Mandatory = $true)][string]$Prompt)

    while ($true) {
        $value = (Read-Host $Prompt).Trim()
        if ($value) {
            return $value
        }
        Write-Host "A value is required." -ForegroundColor Yellow
    }
}

function Get-SetupDefaults {
    $defaults = @{
        ServerUrl = ""
        ServerCertificate = ""
    }

    if (Test-Path $SetupDefaultsPath) {
        try {
            $stored = Get-Content -LiteralPath $SetupDefaultsPath -Raw |
                ConvertFrom-Json
            $defaults.ServerUrl = [string]$stored.server_url
            $defaults.ServerCertificate = [string]$stored.server_certificate
        }
        catch {
            Write-Warning (
                "Remote setup defaults could not be read: " +
                $_.Exception.Message
            )
        }
    }

    if (-not $defaults.ServerUrl) {
        $defaults.ServerUrl = Read-RequiredValue `
            -Prompt "Remote management server URL"
    }

    return $defaults
}

function Invoke-InstalledScript {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [hashtable]$Parameters = @{}
    )

    $path = Join-Path $InstallDir $Name
    if (-not (Test-Path $path)) {
        throw "Required management script was not found: $path"
    }

    & $path @Parameters
}

function Show-LinkExistingAdministrator {
    Write-Host ""
    Write-Host "Link Existing Windows Login Guard Administrator" `
        -ForegroundColor Cyan
    Write-Host ""
    Write-Host (
        "The protected device will validate the administrator's existing " +
        "OTP and send a signed identity attestation. The OTP secret will " +
        "not be copied to the management server."
    )
    Write-Host ""
    Write-Host (
        "The administrator used during install-remote-server.ps1 is " +
        "already linked automatically."
    ) -ForegroundColor Yellow
    Write-Host (
        "This helper does not link an additional local administrator."
    ) -ForegroundColor Yellow
}

function New-IndependentRemoteAdministrator {
    Write-Host ""
    Write-Host "Create Independent Remote Administrator" `
        -ForegroundColor Cyan
    Write-Host ""
    Write-Host (
        "This creates a separate management-server OTP. Use it only for " +
        "standalone administration or current-console testing."
    ) -ForegroundColor Yellow
    Write-Host ""

    $username = Read-RequiredValue `
        -Prompt "Remote administrator username"
    Invoke-InstalledScript `
        -Name "new-remote-admin.ps1" `
        -Parameters @{ Username = $username }
}

function New-ProtectedDeviceRegistration {
    $label = Read-RequiredValue `
        -Prompt "Protected device name or label"
    Invoke-InstalledScript `
        -Name "new-protected-pc-installer.ps1" `
        -Parameters @{
            Label = $label
            ValidHours = 24
        }
    Write-Host ""
    Write-Host (
        "Transfer the generated ZIP securely to the protected PC, extract " +
        "it, and run install-protected-pc.ps1 as Administrator."
    ) -ForegroundColor Green
    Write-Host (
        "The server URL, public certificate, display name, and single-use " +
        "registration code are already included in the bundle."
    )
}
function New-AdminComputerRegistration {
    param([Parameter(Mandatory = $true)][hashtable]$Defaults)

    $label = Read-RequiredValue `
        -Prompt "Administrator computer name or label"
    $result = Invoke-InstalledScript `
        -Name "new-workstation-enrollment-token.ps1" `
        -Parameters @{ Label = $label; PassThru = $true }

    Write-Host ""
    Write-Host "Admin-computer registration code created." `
        -ForegroundColor Green
    Write-Host ""
    Write-Host "On the administrator computer:"
    Write-Host "  1. Copy the extracted current release and server.crt."
    Write-Host "  2. Run .\install-remote-admin.ps1 as Administrator."
    Write-Host "  3. Open Windows Login Guard Remote Administration."
    Write-Host "  4. Enter these values:"
    Write-Host ""
    Write-Host "     Server URL:         $($Defaults.ServerUrl)"
    Write-Host "     Server certificate: C:\Path\To\server.crt"
    Write-Host "     Registration code:  $($result.RegistrationCode)"
    Write-Host "     Computer label:      $label"
    Write-Host ""
    Write-Host "Copy this certificate to the administrator computer:"
    Write-Host "  $($Defaults.ServerCertificate)"
    Write-Host ""
    Write-Host "The registration code is single-use." `
        -ForegroundColor Yellow
}

function Show-Registrations {
    Invoke-InstalledScript -Name "list-remote-registrations.ps1"
}

function Revoke-Registration {
    Write-Host ""
    Write-Host "1. Protected device"
    Write-Host "2. Administrator computer"
    Write-Host "3. Remote administrator"
    Write-Host ""
    $kind = Read-Host "Select registration type"

    switch ($kind) {
        "1" {
            $id = Read-RequiredValue -Prompt "Protected-device ID"
            Invoke-InstalledScript `
                -Name "revoke-remote-object.ps1" `
                -Parameters @{ Kind = "device"; Id = $id }
        }
        "2" {
            $id = Read-RequiredValue -Prompt "Admin-computer ID"
            Invoke-InstalledScript `
                -Name "revoke-remote-object.ps1" `
                -Parameters @{ Kind = "workstation"; Id = $id }
        }
        "3" {
            $username = Read-RequiredValue `
                -Prompt "Remote administrator username"
            Invoke-InstalledScript `
                -Name "manage-remote-admins.ps1" `
                -Parameters @{
                    Username = $username
                    State = "disabled"
                }
        }
        default {
            Write-Host "No registration was changed."
        }
    }
}

$defaults = Get-SetupDefaults

while ($true) {
    Clear-Host
    Write-Host "Windows Login Guard Remote Management Setup" `
        -ForegroundColor Cyan
    Write-Host ("=" * 47)
    Write-Host ""
    Write-Host "Server: $($defaults.ServerUrl)"
    Write-Host ""
    Write-Host "1. Link an existing Windows Login Guard administrator"
    Write-Host "2. Create an independent remote administrator"
    Write-Host "3. Add a protected Windows device"
    Write-Host "4. Add an administrator computer"
    Write-Host "5. View registrations"
    Write-Host "6. Revoke a registration"
    Write-Host "7. Exit"
    Write-Host ""

    $selection = Read-Host "Select an option"

    try {
        switch ($selection) {
            "1" { Show-LinkExistingAdministrator }
            "2" { New-IndependentRemoteAdministrator }
            "3" { New-ProtectedDeviceRegistration -Defaults $defaults }
            "4" { New-AdminComputerRegistration -Defaults $defaults }
            "5" { Show-Registrations }
            "6" { Revoke-Registration }
            "7" { break }
            default {
                Write-Host "Select a number from 1 to 7." `
                    -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host ""
        Write-Host $_.Exception.Message -ForegroundColor Red
    }

    if ($selection -eq "7") {
        break
    }

    Write-Host ""
    Read-Host "Press Enter to return to the setup menu" | Out-Null
}
