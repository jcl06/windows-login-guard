Set-StrictMode -Version Latest

function Set-WlgJsonProperty {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $false)]$Value
    )
    if ($Object.PSObject.Properties.Name -contains $Name) {
        $Object.$Name = $Value
    }
    else {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }
}

function Write-WlgJsonNoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Object
    )
    $json = $Object | ConvertTo-Json -Depth 12
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, $utf8NoBom)
}

function Stop-WlgUiProcesses {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -in @("pythonw.exe", "python.exe") -and
            $_.CommandLine -match "WindowsLoginGuard.*ui\.pyw"
        } |
        ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        }
}

function Remove-WlgLegacyUiTasks {
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskName -like "Windows Login Guard UI*" } |
        ForEach-Object {
            Stop-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath `
                -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath `
                -Confirm:$false -ErrorAction SilentlyContinue
        }
}


function Get-WlgAdminDesktopShortcutPath {
    $desktop = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::DesktopDirectory
    )
    if ([string]::IsNullOrWhiteSpace($desktop)) {
        $desktop = Join-Path $env:USERPROFILE "Desktop"
    }
    return Join-Path $desktop "Windows Login Guard Administration.lnk"
}

function New-WlgAdminDesktopShortcut {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstallDir
    )

    $adminScript = Join-Path $InstallDir "open-admin.ps1"
    if (-not (Test-Path $adminScript)) {
        throw "Admin launcher was not found at: $adminScript"
    }

    $powershellExe = Join-Path $env:SystemRoot (
        "System32\WindowsPowerShell\v1.0\powershell.exe"
    )
    if (-not (Test-Path $powershellExe)) {
        throw "Windows PowerShell was not found at: $powershellExe"
    }

    $shortcutPath = Get-WlgAdminDesktopShortcutPath
    $shell = New-Object -ComObject WScript.Shell
    try {
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $powershellExe
        $shortcut.Arguments = (
            '-NoProfile -ExecutionPolicy Bypass -File "' +
            $adminScript +
            '"'
        )
        $shortcut.WorkingDirectory = $InstallDir
        $shortcut.Description = (
            "Open Windows Login Guard Administration"
        )
        $shortcut.IconLocation = "$powershellExe,0"
        $shortcut.Save()
    }
    finally {
        if ($null -ne $shortcut) {
            [Runtime.InteropServices.Marshal]::ReleaseComObject(
                $shortcut
            ) | Out-Null
        }
        [Runtime.InteropServices.Marshal]::ReleaseComObject(
            $shell
        ) | Out-Null
    }

    # Set the shortcut's RunAsAdministrator flag so it produces a UAC
    # prompt instead of failing because open-admin.ps1 requires elevation.
    $shortcutBytes = [System.IO.File]::ReadAllBytes($shortcutPath)
    if ($shortcutBytes.Length -le 0x15) {
        throw "The generated Admin shortcut is invalid."
    }
    $shortcutBytes[0x15] = $shortcutBytes[0x15] -bor 0x20
    [System.IO.File]::WriteAllBytes(
        $shortcutPath,
        $shortcutBytes
    )

    return $shortcutPath
}

function Remove-WlgAdminDesktopShortcut {
    $shortcutPath = Get-WlgAdminDesktopShortcutPath
    Remove-Item $shortcutPath -Force -ErrorAction SilentlyContinue
}
