#!/usr/bin/env python3
"""check_registry.py — 工具/模块/手册的登记漂移自检。

解决的问题
----------
新增工具写进 `tools/` 或 `scripts/` 后，如果忘了在入口文档登记，
新会话读 SKILL.md 时根本不知道它存在 —— 等于没写。这类漂移不报错，
只会让下次分析重写一遍。

判据（唯一）：basename 是否出现在任一「入口文档」里。
  入口文档 = SKILL.md + reverser.md + references/_index.md + README.md
  **子目录自己的 README.md 也算**（如 tools/ghidra/README.md 登记该目录下的脚本）。
按 basename 而非路径匹配，所以文档里写 `tools/so.py` 或 `so.py` 都算登记。

用法
----
    python3 tools/check_registry.py            # 输出未登记清单，有漂移则退出码 1
    python3 tools/check_registry.py --verbose  # 同时列出每个文件的命中位置

退出码：0 = 全部登记；1 = 有漂移（便于接 CI）。
"""
import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: 入口文档（相对项目根）。任一文件提到 basename 即视为已登记。
REGISTRY_DOCS = (
    ".kilo/skill/frida-mobile-security/SKILL.md",
    ".kilo/agent/reverser.md",
    "references/_index.md",
    "README.md",
)

#: 扫描范围（相对项目根）。只收文件，递归。
SCAN_DIRS = (
    "tools",
    ".kilo/skill/frida-mobile-security/scripts",
    "references",
)

#: 不参与登记的 basename（索引自身、二进制、缓存）。
SKIP_NAMES = {
    "_index.md", "README.md", "README.en.md",
    "check_registry.py",
}
#: 只按扩展名收文件。
SCAN_EXT = {".py", ".js", ".java", ".bat", ".jar", ".md"}

#: 允许只出现在其它文件里的例外（basename -> 允许出现的文件 basename）。
#: 例：GetAPKInfo.jar 由 check-janus.bat 调用，不需要单独进模块目录。
ALLOW_IN = {
    "GetAPKInfo.jar": {"check-janus.bat"},
}


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def collect_files():
    out = []
    for d in SCAN_DIRS:
        base = os.path.join(ROOT, d.replace("/", os.sep))
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [x for x in dirnames
                           if x not in ("__pycache__", "node_modules", ".git")]
            for name in filenames:
                ext = os.path.splitext(name)[1].lower()
                if ext not in SCAN_EXT:
                    continue
                if name in SKIP_NAMES:
                    continue
                full = os.path.join(dirpath, name)
                out.append((os.path.relpath(full, ROOT).replace(os.sep, "/"), name))
    return sorted(out)


def collect_docs(files):
    """入口文档 = 固定的四份 + 每个扫描目录下的 README.md。

    子目录 README 登记自己目录内的文件，这是有意设计：`tools/ghidra/` 下
    30 个脚本放进主 SKILL 模块目录会淹没重点，所以用目录级索引承接。
    """
    docs = {}
    for d in REGISTRY_DOCS:
        p = os.path.join(ROOT, d.replace("/", os.sep))
        if os.path.isfile(p):
            docs[d] = read_text(p)
    for d in SCAN_DIRS:
        base = os.path.join(ROOT, d.replace("/", os.sep))
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [x for x in dirnames
                           if x not in ("__pycache__", "node_modules", ".git")]
            if "README.md" in filenames:
                full = os.path.join(dirpath, "README.md")
                docs[os.path.relpath(full, ROOT).replace(os.sep, "/")] = read_text(full)
    return docs


def main():
    ap = argparse.ArgumentParser(
        description="工具/模块/手册登记漂移自检",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 tools/check_registry.py
  python3 tools/check_registry.py --verbose
""")
    ap.add_argument("--verbose", action="store_true",
                    help="列出每个文件的命中位置")
    args = ap.parse_args()

    files = collect_files()
    docs = collect_docs(files)
    if not docs:
        print("[!] 找不到任何入口文档，检查 REGISTRY_DOCS", file=sys.stderr)
        return 1

    missing = []
    for rel, name in files:
        hits = [d for d, t in docs.items() if name in t]
        if not hits:
            allow = ALLOW_IN.get(name)
            if allow and any(a in read_text(os.path.join(
                    ROOT, os.path.dirname(rel).replace("/", os.sep), a))
                    for a in allow):
                hits = ["(allowed: %s)" % ",".join(sorted(allow))]
        if args.verbose:
            print("%-62s %s" % (rel, ", ".join(hits) if hits else "MISSING"))
        if not hits:
            missing.append(rel)

    print()
    print("扫描 %d 个文件 / %d 个入口文档" % (len(files), len(docs)))
    if not missing:
        print("登记完整：0 处漂移")
        return 0
    print("未登记 %d 处：" % len(missing))
    for m in missing:
        print("  " + m)
    print()
    print("修法：在 SKILL.md 模块目录 / reverser.md 工具树 / _index.md 手册表 各加一行")
    return 1


if __name__ == "__main__":
    sys.exit(main())
