#!/usr/bin/env python3
"""
janus_check.py - Janus 漏洞 (CVE-2017-13156) 备选检测

用途：check-janus.bat 的 GetAPKInfo.jar 无法解析 APK（爱加密等加固魔改
AndroidManifest AXML）时的备选方案。效果与 GetAPKInfo.jar 对齐：
输出 V1/V2/V3 签名方案使用与验证状态 + Janus 结论。

原理：Janus 利用 ZIP 视角(签名校验)与 DEX 视角(dex2oat)不一致。V2 签名
覆盖整个 APK 文件字节，classes.dex 被篡改必然导致 V2 校验失败 → V1+V2
都验证通过即安全（与 GetAPKInfo.jar 判定口径一致）。

验证引擎：优先 apksigner（权威，不解析 Manifest，免疫加固魔改）；
无 apksigner 时退化为结构检测（DEX 伪装 / EOCD 附加 / dex 大小一致性）。

用法：
  python3 janus_check.py <apk路径>
  python3 janus_check.py <apk路径> --apksigner <apksigner.bat路径>
"""
import argparse
import glob
import os
import re
import struct
import subprocess
import sys
import zipfile

DEX_MAGICS = [b'dex\n037\x00', b'dex\n035\x00', b'dex\n036\x00', b'dex\n038\x00', b'dex\n039\x00']


def find_apksigner():
    """自动探测 apksigner（build-tools），返回路径或 None"""
    candidates = []
    env = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
    if env:
        candidates += glob.glob(os.path.join(env, 'build-tools', '*', 'apksigner.bat'))
        candidates += glob.glob(os.path.join(env, 'build-tools', '*', 'apksigner'))
    local = os.environ.get('LOCALAPPDATA', '')
    if local:
        candidates += glob.glob(os.path.join(local, 'Android', 'Sdk', 'build-tools', '*', 'apksigner.bat'))
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def apksigner_verify(apk, apksigner_path):
    """apksigner verify --verbose，返回 (v1, v2, v3, v4) 验证状态"""
    r = subprocess.run([apksigner_path, 'verify', '--verbose', apk],
                       capture_output=True, text=True, errors='replace')
    out = r.stdout + r.stderr
    def s(name):
        m = re.search(re.escape(name) + r'[^:]*:\s*(true|false)', out)
        return 'true' if m and m.group(1) == 'true' else 'false'
    return s('v1 scheme'), s('v2 scheme'), s('v3 scheme'), s('v4 scheme')


def struct_check(apk):
    """无 apksigner 时的结构检测（DEX 伪装 / EOCD 附加 / dex 大小）"""
    data = open(apk, 'rb').read()
    lines = []
    if any(data[:8] == m for m in DEX_MAGICS):
        lines.append(("!JANUS", "文件头是 DEX magic（双格式伪装）"))
    else:
        lines.append(("  ok ", "文件头 PK(正常 ZIP)"))
    eocd = None
    for i in range(len(data) - 22, -1, -1):
        if data[i:i+4] == b'PK\x05\x06':
            eocd = i
            break
    if eocd is None:
        lines.append(("!JANUS", "未找到 EOCD（ZIP 损坏）"))
    else:
        clen = struct.unpack_from('<H', data, eocd + 20)[0]
        extra = len(data) - (eocd + 22 + clen)
        if extra > 0:
            lines.append(("!JANUS", f"EOCD 后附加 {extra}B 数据（隐藏 DEX 特征）"))
        else:
            lines.append(("  ok ", "EOCD 后无附加数据"))
    try:
        z = zipfile.ZipFile(apk)
    except Exception as e:
        lines.append(("!JANUS", f"ZIP 打开失败: {e}"))
        return lines
    for n in z.namelist():
        if n.startswith('classes') and n.endswith('.dex'):
            raw = z.read(n)
            if any(raw[:8] == m for m in DEX_MAGICS):
                declared = struct.unpack_from('<I', raw, 32)[0]
                if len(raw) > declared:
                    lines.append(("!JANUS", f"{n}: DEX声明{declared}B<实际{len(raw)}B（尾部附加）"))
                else:
                    lines.append(("  ok ", f"{n}: 大小一致({len(raw)}B)"))
            else:
                lines.append(("  ok ", f"{n}: 非DEX(壳占位, {len(raw)}B)"))
    return lines


def main():
    ap = argparse.ArgumentParser(description="Janus 漏洞备选检测（签名方案 + 结构）")
    ap.add_argument("apk", help="APK 路径")
    ap.add_argument("--apksigner", help="apksigner 路径（默认自动探测）")
    args = ap.parse_args()

    print("=" * 50)
    print(f"  Janus 漏洞检测 (CVE-2017-13156) - 备选方案")
    print(f"  APK: {args.apk}")
    print("=" * 50)

    apk = args.apk
    apksigner_path = args.apksigner or find_apksigner()

    if apksigner_path:
        print(f"[+] 验证引擎: apksigner ({os.path.basename(os.path.dirname(apksigner_path))})")
        v1, v2, v3, v4 = apksigner_verify(apk, apksigner_path)
        print(f"  V1 签名验证通过 (JAR):      {v1}")
        print(f"  使用 V2 签名 / 验证通过:    {v2}")
        print(f"  使用/验证 V3 签名:          {v3}")
        print(f"  使用/验证 V4 签名:          {v4}")
        print("-" * 50)
        ok = v1 == 'true' and v2 == 'true'
        if ok:
            print(f"  [VERDICT] V1+V2 均验证通过 → 安全，无 Janus 漏洞风险")
        elif v2 == 'true':
            print(f"  [VERDICT] V2 验证通过（V1 不可用）→ 安全，无 Janus 漏洞风险")
        else:
            print(f"  [WARN] 无有效 V2 签名 → 若为 V1-only，Android<8.0 存在 Janus 风险")
    else:
        print("[-] 未找到 apksigner，使用结构检测（DEX 伪装 / EOCD / dex 大小）")
        hits = 0
        for tag, msg in struct_check(apk):
            print(f"  [{tag}] {msg}")
            if 'JANUS' in tag:
                hits += 1
        print("-" * 50)
        print(f"  [VERDICT] {'发现 Janus 结构特征' if hits else '未发现 Janus 结构特征'}")
    print("=" * 50)


if __name__ == '__main__':
    main()