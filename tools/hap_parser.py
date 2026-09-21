"""
HAP 包信息解析工具
用法: python hap_parser.py <hap文件路径>
输出: 应用名称、应用包名、应用版本、文件大小、文件MD5
"""

import sys
import os
import json
import hashlib
import zipfile
import tempfile
import shutil
import re
import struct
from typing import Optional, Dict, List, Tuple

# Windows 控制台 UTF-8 输出兼容
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def extract_null_terminated_strings(data: bytes, min_len: int = 2) -> List[Tuple[int, str]]:
    """从二进制数据中提取所有 null 结尾的 UTF-8 字符串"""
    strings = []
    start = None
    for i, byte in enumerate(data):
        if byte == 0:
            if start is not None and i - start >= min_len:
                try:
                    s = data[start:i].decode("utf-8")
                    strings.append((start, s))
                except UnicodeDecodeError:
                    pass
            start = None
        elif start is None:
            start = i
    return strings


_RES_KEY_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_.]{2,}$")
_PRINTABLE_RE = re.compile(r"^[\x20-\x7e\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]+$")


def _is_printable(s: str) -> bool:
    """判断字符串是否可打印（ASCII 可打印 + CJK 范围）"""
    return bool(_PRINTABLE_RE.match(s))


def parse_resources_index(raw: bytes) -> Dict[str, str]:
    """从 resources.index 二进制中提取 key-value 资源映射"""
    strings = extract_null_terminated_strings(raw, min_len=2)
    result = {}

    for i in range(len(strings) - 1):
        offset_i, text_i = strings[i]
        offset_j, text_j = strings[i + 1]

        if len(text_i) > 80 or len(text_j) > 80:
            continue
        if not _is_printable(text_i) or not _is_printable(text_j):
            continue
        if text_i.startswith("$") or "/" in text_i or "\\" in text_i:
            continue

        if _RES_KEY_RE.match(text_j):
            result[text_j] = text_i

    return result


def get_app_name_from_resources(resources_index_path: str) -> Optional[str]:
    """从 resources.index 提取 app_name 资源值"""
    if not os.path.exists(resources_index_path):
        return None
    with open(resources_index_path, "rb") as f:
        raw = f.read()
    mapping = parse_resources_index(raw)

    # 按优先级尝试多个可能的 key
    for key in ("app_name", "app_name_sc_it", "app_name_sit",
                "app_name_dev", "app_name_uat", "app_name_zsc_it"):
        if key in mapping and mapping[key]:
            return mapping[key]
    return None


def parse_hap(hap_path: str) -> Dict[str, str]:
    """解析 HAP 包，返回 5 要素信息"""
    if not os.path.exists(hap_path):
        raise FileNotFoundError(f"文件不存在: {hap_path}")

    # 计算文件大小和 MD5
    file_size = os.path.getsize(hap_path)
    with open(hap_path, "rb") as f:
        md5 = hashlib.md5(f.read()).hexdigest().upper()

    # 解压关键文件
    tmp_dir = tempfile.mkdtemp(prefix="hap_parse_")
    try:
        with zipfile.ZipFile(hap_path, "r") as zf:
            members = ["module.json", "resources.index"]
            for m in members:
                try:
                    zf.extract(m, tmp_dir)
                except KeyError:
                    pass

        module_json = os.path.join(tmp_dir, "module.json")
        resources_index = os.path.join(tmp_dir, "resources.index")

        if not os.path.exists(module_json):
            raise ValueError("HAP 包中未找到 module.json")

        with open(module_json, "r", encoding="utf-8") as f:
            module = json.load(f)

        app_info = module.get("app", {})
        bundle_name = app_info.get("bundleName", "unknown")
        version_name = app_info.get("versionName", "unknown")
        version_code = app_info.get("versionCode", "unknown")

        # 应用名称: 优先从 resources.index 取，回退到 bundleName
        app_name = get_app_name_from_resources(resources_index)
        if not app_name:
            app_name = bundle_name

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    size_mb = file_size / (1024 * 1024)
    return {
        "应用名称": app_name,
        "应用包名": bundle_name,
        "应用版本": f"{version_name} (code: {version_code})",
        "文件大小": f"{size_mb:.2f} MB ({file_size:,} bytes)",
        "文件MD5": md5,
    }


def main():
    if len(sys.argv) < 2:
        print("用法: python hap_parser.py <hap文件路径>")
        sys.exit(1)

    hap_path = sys.argv[1]

    try:
        info = parse_hap(hap_path)
    except Exception as e:
        print(f"[ERROR] 解析失败: {e}")
        sys.exit(1)

    print("=" * 50)
    print(f"文件: {os.path.basename(hap_path)}")
    print("=" * 50)
    for key, value in info.items():
        print(f"  {key}: {value}")
    print("=" * 50)


if __name__ == "__main__":
    main()