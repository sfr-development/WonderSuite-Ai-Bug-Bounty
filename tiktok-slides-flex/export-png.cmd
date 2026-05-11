@echo off
setlocal enabledelayedexpansion
title WonderSuite Flex Deck - PNG Export
cd /d "%~dp0"

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

echo No Chrome or Edge found.
pause
exit /b 1

:found
echo Using browser: !CHROME!
echo.

if not exist out mkdir out

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
echo Done. PNGs in:  %CD%\out
echo ============================================================
pause
