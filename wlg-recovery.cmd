@echo off
setlocal EnableExtensions EnableDelayedExpansion

if /I "%~1"=="enable" goto :begin
if /I "%~1"=="disable" goto :begin
goto :usage

:begin
set "ACTION=%~1"
set "RECOVERY_ENV="

if exist "%SystemRoot%\System32\wpeutil.exe" (
    set "RECOVERY_ENV=Windows Recovery Environment"
)

reg query "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option" /v OptionValue >nul 2>&1
if not errorlevel 1 (
    set "RECOVERY_ENV=Windows Safe Mode"
)

if /I "!ACTION!"=="enable" (
    if not defined RECOVERY_ENV (
        echo Machine-wide maintenance mode can only be enabled from:
        echo   - Windows Safe Mode
        echo   - Windows Recovery Environment
        exit /b 5
    )
)

if not defined RECOVERY_ENV (
    set "RECOVERY_ENV=Local administrator"
)

set "OSDRIVE="

for %%D in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if not defined OSDRIVE (
        if exist "%%D:\ProgramData\WindowsLoginGuard\secure\maintenance-key.sha256" (
            set "OSDRIVE=%%D:"
        )
    )
)

if not defined OSDRIVE (
    echo Windows Login Guard recovery data was not found.
    echo Unlock the Windows volume first if BitLocker is enabled.
    exit /b 2
)

set "SECURE=!OSDRIVE!\ProgramData\WindowsLoginGuard\secure"
set "HASHFILE=!SECURE!\maintenance-key.sha256"
set "STATEFILE=!SECURE!\maintenance.json"
set "AUDITFILE=!SECURE!\admin_audit.jsonl"
set "TEMPKEY=%TEMP%\wlg-recovery-key-%RANDOM%.txt"

echo.
echo Windows Login Guard Machine Recovery
echo Environment: !RECOVERY_ENV!
echo Windows volume: !OSDRIVE!
echo.
echo The recovery key will be visible while entered in this command window.
set /p "RECOVERY_KEY=Maintenance recovery key: "

if not defined RECOVERY_KEY (
    echo Recovery key is required.
    exit /b 3
)

> "!TEMPKEY!" <nul set /p "=!RECOVERY_KEY!"
set "ACTUAL="
for /f "skip=1 delims=" %%H in ('certutil -hashfile "!TEMPKEY!" SHA256 2^>nul') do (
    if not defined ACTUAL set "ACTUAL=%%H"
)
del /q "!TEMPKEY!" >nul 2>&1

set "ACTUAL=!ACTUAL: =!"
set /p "EXPECTED="<"!HASHFILE!"
set "EXPECTED=!EXPECTED: =!"

if /I not "!ACTUAL!"=="!EXPECTED!" (
    echo Invalid maintenance recovery key.
    exit /b 4
)

if /I "!ACTION!"=="enable" (
    > "!STATEFILE!" echo {"enabled":true,"enabled_at_utc":"offline-recovery","enabled_by":"!RECOVERY_ENV!","reason":"Offline machine recovery"}
    >> "!AUDITFILE!" echo {"timestamp_utc":"offline-recovery","action":"break_glass_maintenance_enabled_offline","target_sid":"","target_username":"Windows Login Guard","actor_sid":"","actor_username":"!RECOVERY_ENV!","details":{"reason":"Offline machine recovery"}}
    echo.
    echo Machine-wide maintenance mode enabled.
    echo Restart Windows. OTP enforcement will be bypassed.
    exit /b 0
)

> "!STATEFILE!" echo {"enabled":false,"disabled_at_utc":"offline-recovery","disabled_by":"!RECOVERY_ENV!"}
>> "!AUDITFILE!" echo {"timestamp_utc":"offline-recovery","action":"break_glass_maintenance_disabled_offline","target_sid":"","target_username":"Windows Login Guard","actor_sid":"","actor_username":"!RECOVERY_ENV!","details":{}}
echo.
echo Maintenance mode disabled.
echo Restart Windows. OTP enforcement will be active.
exit /b 0

:usage
echo Usage:
echo   wlg-recovery.cmd enable
echo   wlg-recovery.cmd disable
exit /b 1
