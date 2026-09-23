@echo off
setlocal enabledelayedexpansion

set "PKG=%~1"
if "%PKG%"=="" (
    echo Usage: check-anti-inject.bat ^<package^>
    echo Example: check-anti-inject.bat com.zhiHuiAnJi
    pause
    exit /b 1
)

set "INJECTOR64=/data/local/tmp/AndKittyInjector"
set "INJECTOR32=/data/local/tmp/AndKittyInjector32"
set "INJECTOR="
set "INJECTED_LIB="

:: === SELinux Permissive (test env) ===
adb shell "su -c 'setenforce 0'" 2>nul

echo ============================================
echo   Anti-Injection Test - AndKittyInjector
echo   Target: %PKG%
echo   Library: auto-detect (32/64-bit)
echo   Time: %date% %time%
echo ============================================
echo.

echo [1/5] Check ADB device...
adb devices 2>nul | findstr "device" >nul
if errorlevel 1 (
    echo [FAIL] No ADB device detected
    pause
    exit /b 1
)
echo [OK] Device connected
echo.

echo [2/5] Start target and detect bitness...
adb shell "am force-stop %PKG%" 2>nul
timeout /t 2 /nobreak >nul
adb shell "monkey -p %PKG% 1" 2>nul
timeout /t 4 /nobreak >nul

set "PID="
for /f %%p in ('adb shell "pidof %PKG%" 2^>nul') do set "PID=%%p"
if "!PID!"=="" (
    echo [FAIL] Cannot start target process
    pause
    exit /b 1
)
echo [OK] Process PID: !PID!
echo.

echo    Process list (for screenshot) 
adb shell "ps -A ^| grep %PKG%"
echo.

adb shell "su -c 'cat /proc/!PID!/maps 2^>/dev/null'" 2>nul | findstr "linker64" >nul
if !ERRORLEVEL! equ 0 (
    set "BITS=64"
    set "INJECTOR=%INJECTOR64%"
    set "INJECTED_LIB=/data/local/tmp/libhello64.so"
    set "LIBNAME=libhello64.so"
) else (
    set "BITS=32"
    set "INJECTOR=%INJECTOR32%"
    set "INJECTED_LIB=/data/local/tmp/libhello32.so"
    set "LIBNAME=libhello32.so"
)
echo   Detected: !BITS!-bit process
echo   Injector: !INJECTOR!
echo   Library:  !INJECTED_LIB!
echo.

echo [3/5] Verify injector and library, check maps BEFORE injection...
adb shell "su -c 'test -f !INJECTOR! && echo INJ_OK || echo INJ_MISSING'" 2>nul | findstr "INJ_OK" >nul
if !ERRORLEVEL! neq 0 (
    echo   [FAIL] Injector binary not found: !INJECTOR!
    echo.
    echo   For 32-bit targets, you need a 32-bit build of AndKittyInjector.
    echo   The 64-bit injector cannot ptrace-attach to a 32-bit process.
    echo   Build with: ndk-build APP_ABI=armeabi-v7a
    echo   Then push: adb push libs/armeabi-v7a/AndKittyInjector !INJECTOR!
    echo.
    pause
    exit /b 1
)
adb shell "su -c 'test -f !INJECTED_LIB! && echo LIB_OK || echo LIB_MISSING'" 2>nul | findstr "LIB_OK" >nul
if !ERRORLEVEL! neq 0 (
    echo   [FAIL] Library not found: !INJECTED_LIB!
    echo   Push a !BITS!-bit hello library to !INJECTED_LIB!
    pause
    exit /b 1
)
echo   [OK] Both injector and library found
echo   Command: cat /proc/!PID!/maps ^| grep !LIBNAME!
adb shell "su -c 'cat /proc/!PID!/maps 2^>/dev/null ^| grep !LIBNAME!'" 2>nul
if errorlevel 1 (
    echo   Result: !LIBNAME! NOT found in maps -- clean
) else (
    echo   [NOTE] Residual mapping found above
)
echo.

echo [4/5] Execute injection: !INJECTOR!...
echo ============================================
echo   RAW OUTPUT from AndKittyInjector
echo   (key evidence for screenshot)
echo   Command: su -c '!INJECTOR! --package %PKG% --launch --libs !INJECTED_LIB!'
echo ============================================
echo.
adb shell "am force-stop %PKG%" 2>nul
timeout /t 2 /nobreak >nul
adb shell "su -c '!INJECTOR! --package %PKG% --launch --libs !INJECTED_LIB!' 2>&1"
set RC=!ERRORLEVEL!
echo.
echo ============================================
echo   END of AndKittyInjector output
echo ============================================
echo.

if !RC! neq 0 (
    echo [FAIL] AndKittyInjector exit code !RC! - injection may have failed
) else (
    echo [OK] AndKittyInjector completed
)
echo.

echo [5/5] Verify injection via /proc/pid/maps...
timeout /t 2 /nobreak >nul
set "NEW_PID="
for /f %%p in ('adb shell "pidof %PKG%" 2^>nul') do set "NEW_PID=%%p"
if "!NEW_PID!"=="" (
    echo   [WARN] Process not running after injection - may have been killed
    set "GREP=1"
) else (
    echo   PID: !NEW_PID!
    echo   Command: cat /proc/!NEW_PID!/maps ^| grep !LIBNAME!
    echo ============================================
    adb shell "su -c 'cat /proc/!NEW_PID!/maps 2^>/dev/null ^| grep !LIBNAME!'" 2>nul
    set GREP=!ERRORLEVEL!
    echo ============================================
)
echo.

if !GREP! equ 0 (
    set "RESULT=SUCCESS"
    set "VERDICT=no anti-injection protection detected"
    set "EVIDENCE=!LIBNAME! loaded into process memory (see above)"
) else (
    set "RESULT=FAILED"
    set "VERDICT=target may have anti-injection protection"
    set "EVIDENCE=!LIBNAME! NOT found in maps"
)

echo [OK/FAIL] Injection !RESULT!
echo.

echo ============================================
echo   VERDICT
echo ============================================
echo   Target: %PKG% (PID: !PID!)
echo   Bitness: !BITS!-bit
echo   Injector: !INJECTOR!
echo   Library: !INJECTED_LIB!
echo   injector exit code: !RC!
echo   !LIBNAME! in maps: !GREP! (0=found, 1=not found)
echo.
echo   [VERDICT] Injection !RESULT! - !VERDICT!
echo   Evidence: !EVIDENCE!
echo.
echo   [NOTE] This test covers ptrace + /proc/pid/mem injection.
echo   For a complete audit, also test:
echo   - LD_PRELOAD injection
echo   - Frida injection (Gadget / frida-server)
echo   - /proc/pid/maps scanning detection
echo   - Thread name detection (pthread_setname_np)
echo ============================================
echo.

pause