#!/usr/bin/env python3
"""build.py - 编译 zygote loader（arm64-v8a）

用法：
  python3 tools/inject/build.py                       # 编译 loader_fork.so
  python3 tools/inject/build.py --src loader_fork.c --hook    # 启用替换模式
  python3 tools/inject/build.py --abi arm | arm64

NDK 查找顺序：$ANDROID_NDK_HOME → %LOCALAPPDATA%\\Android\\Sdk\\ndk\\<最新> → /opt/android-ndk
"""
import argparse
import glob
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def find_ndk():
    env = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("NDK_HOME")
    if env and os.path.isdir(env):
        return env
    local = os.environ.get("LOCALAPPDATA")
    if local:
        cands = sorted(glob.glob(os.path.join(local, "Android", "Sdk", "ndk", "*")))
        if cands:
            return cands[-1]
    for p in ("/opt/android-ndk", "/usr/local/lib/android/sdk/ndk"):
        if os.path.isdir(p):
            return p
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--abi", default="arm64", choices=["arm64", "arm"])
    ap.add_argument("--out", default=os.path.join(HERE, "loader_fork.so"))
    ap.add_argument("--src", default=os.path.join(HERE, "loader_fork.c"),
                    help="source file (loader_fork.c / loader.c)")
    ap.add_argument("--hook", action="store_true", help="loader only: enable LOADER_HOOK (stage 2)")
    a = ap.parse_args()

    ndk = find_ndk()
    if ndk is None:
        print("[-] NDK not found; set ANDROID_NDK_HOME")
        return 1
    host = "windows-x86_64" if os.name == "nt" else ("darwin-x86_64" if sys.platform == "darwin" else "linux-x86_64")
    bin_dir = os.path.join(ndk, "toolchains", "llvm", "prebuilt", host, "bin")
    triple = "aarch64-linux-android29" if a.abi == "arm64" else "armv7a-linux-androideabi29"
    cc = os.path.join(bin_dir, triple + "-clang.cmd" if os.name == "nt" else triple + "-clang")
    if not os.path.exists(cc):
        print("[-] compiler not found: " + cc)
        return 1

    cmd = [cc, "-shared", "-fPIC", "-O2", "-Wall", "-o", a.out, a.src, "-llog", "-ldl"]
    if a.hook:
        cmd.append("-DLOADER_HOOK")
    print("[*] " + " ".join(cmd))
    rc = subprocess.call(cmd)
    if rc == 0:
        print("[+] built: %s (%d bytes)" % (a.out, os.path.getsize(a.out)))
    return rc


if __name__ == "__main__":
    sys.exit(main())
