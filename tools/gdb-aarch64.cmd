@echo off
@echo off
if defined ANDROID_NDK_HOME (
    set "GDB_DIR=%ANDROID_NDK_HOME%\prebuilt\windows-x86_64\bin"
) else if defined NDK_ROOT (
    set "GDB_DIR=%NDK_ROOT%\prebuilt\windows-x86_64\bin"
) else (
    set "GDB_DIR=C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\21.4.7075529\prebuilt\windows-x86_64\bin"
)
set "PATH=%GDB_DIR%;%PATH%"
gdb.exe %*