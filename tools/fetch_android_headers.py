"""从 AOSP 抓取 Android 运行时头文件（ART / libdexfile），走本地代理。

为什么需要
----------
逆向 hook ART 的壳时，必须拿到**真实的**结构体布局
（ArtMethod / ClassLinker / Instrumentation / JavaVMExt 等）。
从反汇编猜字段偏移既慢又易错；对应 Android 版本的 AOSP 头文件
是权威来源，每个字段都有定义。

用法
----
    python3 tools/fetch_android_headers.py                  # android-10.0.0_r1（默认）
    python3 tools/fetch_android_headers.py --tag android-11.0.0_r1
    python3 tools/fetch_android_headers.py --list           # 只列出会抓哪些文件

代理
----
用 --proxy 或环境变量 HTTP_PROXY / HTTPS_PROXY 指定。
国内直连不到 AOSP，本地代理通常是 127.0.0.1:7890。

输出目录（相对 --outdir，默认 references/android-headers）
--------------------------------------------------------
    <tag>/art/<file>.h            runtime/*.h
    <tag>/art/jni_<file>.h        runtime/jni/*.h（扁平化）
    <tag>/art/<file>.h            libdexfile/dex/*.h（扁平化）
"""
import argparse
import base64
import os
import sys
import urllib.request

AOSP = "https://android.googlesource.com/platform"

# (repo path, dest filename)
ART_RUNTIME = [
    "art_method.h",
    "class_linker.h",
    "instrumentation.h",
    "thread.h",
    "runtime.h",
    "mirror/object.h",
    "mirror/class.h",
    "dex/dex_file_structs.h",
]
ART_JNI = [
    "java_vm_ext.h",
    "jni_env_ext.h",
    "local_reference_table.h",
]
LIBDEXFILE = [
    "dex/dex_file.h",
    "dex/dex_file_layout.h",
]


def build_opener(proxy):
    if not proxy:
        proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if not proxy:
        return urllib.request.build_opener()
    handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    return urllib.request.build_opener(handler)


def fetch(opener, repo, tag, path):
    url = "%s/%s/+/refs/tags/%s/%s?format=TEXT" % (AOSP, repo, tag, path)
    raw = opener.open(url, timeout=60).read()
    return base64.b64decode(raw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="android-10.0.0_r1",
                    help="AOSP tag, e.g. android-10.0.0_r1")
    ap.add_argument("--outdir", default=None,
                    help="output root (default: references/android-headers)")
    ap.add_argument("--proxy", default=None,
                    help="http proxy, e.g. http://127.0.0.1:7890")
    ap.add_argument("--list", action="store_true", help="list files only")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    root = args.outdir or os.path.join(here, "..", "references", "android-headers")
    # AOSP tag 含点（android-10.0.0_r1），而 .gitignore 的包名目录规则会吞掉
    # 任意层级含点的目录；落盘时把点换成连字符，URL 仍用原始 tag。
    dirname = args.tag.replace(".", "-")
    out = os.path.abspath(os.path.join(root, dirname, "art"))
    os.makedirs(out, exist_ok=True)

    plan = []
    for f in ART_RUNTIME:
        plan.append(("art", "runtime/" + f, f.replace("/", "_")))
    for f in ART_JNI:
        plan.append(("art", "runtime/jni/" + f, "jni_" + f))
    for f in LIBDEXFILE:
        plan.append(("art", "libdexfile/" + f, f.replace("/", "_")))

    if args.list:
        for repo, src, dst in plan:
            print("%-10s %-40s -> %s" % (repo, src, dst))
        return 0

    opener = build_opener(args.proxy)
    ok = fail = 0
    for repo, src, dst in plan:
        try:
            data = fetch(opener, repo, args.tag, src)
            with open(os.path.join(out, dst), "wb") as fh:
                fh.write(data)
            print("%-34s %7d B" % (dst, len(data)))
            ok += 1
        except Exception as exc:  # noqa: BLE001
            print("%-34s FAIL %s" % (dst, str(exc)[:60]))
            fail += 1
    print("\n%d ok, %d failed -> %s" % (ok, fail, out))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
