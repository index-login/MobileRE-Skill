#!/usr/bin/env python3
# patch_gadget_threadnames.py — 把 frida-gadget.so 里的 frida 线程名等长替换
# 用法: python3 patch_gadget_threadnames.py <frida-gadget.so> <output.so>
#
# 目的: 过 libnesec/MSA 的 /proc/self/task/<tid>/{status,comm} 线程名扫描
#   gum-js-loop(11) → ndk_worker1(11)
#   gmain(5)        → gmaio(5)
#   frida-gadget(13)→ nemediacodec(13)  (主线程名，过 /proc/task/comm 扫描)
#
# 同时把 SO 文件名改名规避 /proc/self/maps 扫描（建议输出为 libnemedia.so 等无害名称）
#
# 来源: Frida 学习笔记 · Frida Gadget 注入 · 网易云音乐易盾实战 §4.3
import sys

REPLACEMENTS = [
    (b"gum-js-loop\x00",  b"ndk_worker1\x00"),
    (b"gmain\x00",        b"gmaio\x00"),
    (b"frida-gadget\x00", b"nemediacodec\x00"),
]


def main(input_path, output_path):
    data = open(input_path, "rb").read()
    orig_len = len(data)

    for old, new in REPLACEMENTS:
        assert len(old) == len(new), f"length mismatch {old!r} vs {new!r}"
        cnt = data.count(old)
        data = data.replace(old, new)
        print(f"  {old!r} -> {new!r}: {cnt} occurrence(s)")

    assert len(data) == orig_len, "size changed!"
    open(output_path, "wb").write(data)
    print(f"wrote {output_path} ({len(data)} bytes)")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("用法: python3 patch_gadget_threadnames.py <frida-gadget.so> <output.so>")
        print("示例: python3 patch_gadget_threadnames.py libfrida-gadget.so libnemedia.so")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])