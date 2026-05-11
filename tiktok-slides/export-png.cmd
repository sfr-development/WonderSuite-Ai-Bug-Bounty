@echo off
setlocal enabledelayedexpansion
title WonderSuite TikTok - PNG Export
cd /d "%~dp0"

REM ─── Locate Chrome ──────────────────────────────────────────
set "CHROME="
for %%P in (
    "%ProgramFiles%\Google\Chrome\Application\chrome.exe"
    "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"
    "%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"
    "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"
    "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
) do (
    if exist %%~P (
        set "CHROME=%%~P"
        goto :found
    )
)

echo No Chrome or Edge found. Install Chrome from https://www.google.com/chrome
pause
exit /b 1

:found
echo Using browser: !CHROME!
echo.

REM ─── Output folder ─────────────────────────────────────────
if not exist out mkdir out

REM ─── Export each slide ─────────────────────────────────────
for %%F in (slide-*.html) do (
    set "name=%%~nF"
    echo Exporting !name!.png ...
    "!CHROME!" ^
        --headless=new ^
        --disable-gpu ^
        --hide-scrollbars ^
        --no-pdf-header-footer ^
        --window-size=1080,1920 ^
        --screenshot="%CD%\out\!name!.png" ^
        --virtual-time-budget=2500 ^
        "file:///%CD:\=/%/%%F" >nul 2>&1
)

echo.
echo ============================================================
echo Done. Open the 'out' folder for the PNGs:
echo   %CD%\out
echo.
echo Each file is 1080x1920 - direct TikTok upload ready.
echo ============================================================
pause
