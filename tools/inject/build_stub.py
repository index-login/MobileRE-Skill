#!/usr/bin/env python3
"""build_stub.py - 编译注入加载桩 stub.jar（x.L）

用途：targetSdk >= 35 时 Runtime.load(String, ClassLoader) 被平台禁用，
native 侧需要一个 App classloader 下的类来执行 System.load。

用法：
  python3 tools/inject/build_stub.py
  python3 tools/inject/build_stub.py --out tools/inject/stub/stub.jar --min-api 29

依赖：javac（JAVA_HOME 或 PATH）、Android SDK 的 android.jar 与 build-tools 的 d8.jar。
"""
import argparse
import glob
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SRC = os.path.join(HERE, "stub", "L.java")
DEFAULT_OUT = os.path.join(HERE, "stub", "stub.jar")


def find_sdk():
    for env in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        p = os.environ.get(env)
        if p and os.path.isdir(p):
            return p
    local = os.environ.get("LOCALAPPDATA")
    if local:
        p = os.path.join(local, "Android", "Sdk")
        if os.path.isdir(p):
            return p
    return None


def pick(paths):
    paths = sorted(paths)
    return paths[-1] if paths else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=DEFAULT_SRC)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--min-api", default="29")
    a = ap.parse_args()

    sdk = find_sdk()
    if sdk is None:
        print("[-] Android SDK not found; set ANDROID_SDK_ROOT")
        return 1
    android_jar = pick(glob.glob(os.path.join(sdk, "platforms", "android-*", "android.jar")))
    d8_jar = pick(glob.glob(os.path.join(sdk, "build-tools", "*", "lib", "d8.jar")))
    if not android_jar or not d8_jar:
        print("[-] missing android.jar or d8.jar under " + sdk)
        return 1

    def find_tool(name):
        jh = os.environ.get("JAVA_HOME")
        if jh:
            cand = os.path.join(jh, "bin", name + (".exe" if os.name == "nt" else ""))
            if os.path.exists(cand):
                return cand
        return shutil.which(name)

    javac, java = find_tool("javac"), find_tool("java")
    if not javac or not java:
        print("[-] javac/java not found; set JAVA_HOME")
        return 1

    def run(cmd, what):
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print("[-] %s failed (rc=%d)" % (what, r.returncode))
            print((r.stdout or "") + (r.stderr or ""))
            raise SystemExit(1)

    tmp = tempfile.mkdtemp(prefix="stub_")
    try:
        classes, dexdir = os.path.join(tmp, "classes"), os.path.join(tmp, "dex")
        os.makedirs(classes), os.makedirs(dexdir)
        run([javac, "-source", "8", "-target", "8", "-nowarn",
             "-classpath", android_jar, "-d", classes, a.src], "javac")
        class_files = glob.glob(os.path.join(classes, "**", "*.class"), recursive=True)
        if not class_files:
            print("[-] javac produced no class files")
            return 1
        # d8.bat 在 JDK 11+ 会因 java.ext.dirs 启动失败，直接调用 d8.jar
        run([java, "-cp", d8_jar, "com.android.tools.r8.D8",
             "--min-api", str(a.min_api), "--lib", android_jar,
             "--output", dexdir] + class_files, "d8")
        dex = os.path.join(dexdir, "classes.dex")
        if not os.path.exists(dex):
            print("[-] d8 produced no classes.dex")
            return 1
        with zipfile.ZipFile(a.out, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(dex, "classes.dex")
        print("[+] stub: %s (%d bytes)" % (a.out, os.path.getsize(a.out)))
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())