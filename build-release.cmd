@echo off
title WonderSuite - Release Build
cd /d "%~dp0"
set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"

echo ============================================================
echo  WonderSuite Release Build
echo  Cwd: %CD%
echo  Started: %DATE% %TIME%
echo ============================================================
echo.

npm run tauri build
set BUILD_EXIT=%ERRORLEVEL%

echo.
echo ============================================================
if %BUILD_EXIT%==0 (
    echo  BUILD OK ^(exit %BUILD_EXIT%^) - %DATE% %TIME%
    echo.
    echo  Look for the artifacts under:
    echo    Raw .exe ........ src-tauri\target\release\wondersuite.exe
    echo    NSIS installer .. src-tauri\target\release\bundle\nsis\
    echo    MSI installer ... src-tauri\target\release\bundle\msi\
    echo.
    if exist "src-tauri\target\release\wondersuite.exe" (
        echo  Existing artifacts:
        dir /b "src-tauri\target\release\wondersuite.exe" 2^>nul
        dir /b /s "src-tauri\target\release\bundle\*.exe" 2^>nul
        dir /b /s "src-tauri\target\release\bundle\*.msi" 2^>nul
    )
) else (
    echo  BUILD FAILED ^(exit %BUILD_EXIT%^) - %DATE% %TIME%
    echo  Scroll up to see the first error.
)
echo ============================================================
echo.
echo (Window stays open. Close it manually when done.)
