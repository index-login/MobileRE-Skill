@echo off
setlocal enabledelayedexpansion

set "APK=%~1"
if "%APK%"=="" (
    echo Usage: check-janus.bat ^<apk_path^>
    echo Example: check-janus.bat app.apk
    pause
    exit /b 1
)

set "PY="
where python3 >nul 2>nul
if not errorlevel 1 set "PY=python3"
if not defined PY (
    where python >nul 2>nul
    if not errorlevel 1 set "PY=python"
)
if not defined PY (
    echo [FAIL] Python not found ^(need python 3.9+^)
    pause
    exit /b 1
)

echo ============================================
echo   Janus Check (CVE-2017-13156)
echo   APK: %APK%
echo ============================================
echo.

echo [1/2] GetAPKInfo.jar (APK meta + V1/V2/V3 signature)...
set "JAR=%~dp0GetAPKInfo.jar"
java -jar "%JAR%" "%APK%"
echo.
echo   [INFO] If GetAPKInfo.jar reports FAILED (packer-mangled
echo          AndroidManifest, e.g. ijiami), result below is
echo          authoritative: janus_check.py verifies via apksigner,
echo          which does NOT parse AndroidManifest.
echo.
echo [2/2] Fallback: janus_check.py (apksigner V1/V2/V3 verify)...
%PY% "%~dp0janus_check.py" "%APK%"
echo.

pause