#!/usr/bin/env python3
"""inject.py - 一条命令完成 zygote 注入 + 配置（独立 loader 路线）

用法：
  python3 tools/inject/inject.py --pkg com.example.app --gadget /data/data/com.example.app/libhan.so
  python3 tools/inject/inject.py --pkg com.example.app --gadget ... --deday 12
  python3 tools/inject/inject.py --pkg ... --gadget ... --check      # 只检查环境

前置：
  - 设备已 root，/data/local/tmp 下有 AndKittyInjector
  - loader.so（tools/inject/build.py --src loader_fork.c --hook）
  - stub.jar（tools/inject/build_stub.py）
  - gadget 已放进目标 App 私有目录（本脚本不搬运 payload）

做的事：
  1. 校验设备/root/zygote/注入件
  2. 写 /data/local/tmp/loader.conf
  3. 临时 permissive → AndKittyInjector --memfd --hide 注入 zygote64 → 恢复 enforcing
  4. 输出后续验证命令
"""
import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = "/data/local/tmp"


def sh(cmd, serial=None, check=False):
    full = ["adb"] + (["-s", serial] if serial else []) + cmd
    r = subprocess.run(full, capture_output=True, text=True)
    if check and r.returncode != 0:
        print("[-] " + " ".join(full))
        print((r.stdout or "") + (r.stderr or ""))
        raise SystemExit(1)
    return (r.stdout or "") + (r.stderr or "")


def su(cmd, serial):
    """su -c 用整条命令字符串，避免参数被 su 的 getopt 吃掉"""
    return sh(["shell", 'su -c "%s"' % cmd.replace('"', '\\"')], serial)


def push(local, remote, serial):
    sh(["push", local, remote], serial, check=True)
    sh(["shell", "chmod 644 " + remote], serial)


def gadget_port(gadget_path, serial=None):
    """从 gadget 的 config.so 读监听端口。

    端口由 `<gadget>.config.so` 的 interaction.port 决定，不是固定值；
    读不到返回 None，由调用方决定兜底。
    """
    # libgadget.so -> libgadget.config.so（替换 .so 后缀，不是追加）
    cfg = re.sub(r"\.so$", ".config.so", gadget_path)
    try:
        raw = su("cat %s" % cfg, serial).strip()
    except Exception:  # noqa: BLE001
        return None
    m = re.search(r'"port"\s*:\s*(\d+)', raw)
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pkg", required=True)
    ap.add_argument("--gadget", required=True, help="设备上的 gadget 绝对路径，可用 %%s 占位包名")
    ap.add_argument("--deday", default="12", help="加载延迟秒数（默认 12）")
    ap.add_argument("--stub", default=TMP + "/stub.jar")
    ap.add_argument("--loader", default=os.path.join(HERE, "loader_fork.so"))
    ap.add_argument("--port", default=None,
                    help="兜底端口；默认从 <gadget>.config.so 的 interaction.port 读")
    ap.add_argument("--serial", default=None)
    ap.add_argument("--check", action="store_true", help="只检查环境，不注入")
    a = ap.parse_args()

    devs = sh(["devices"]).strip().splitlines()[1:]
    devs = [l.split("\t")[0] for l in devs if "\tdevice" in l]
    if a.serial is None:
        if len(devs) != 1:
            print("[-] 需要 --serial（当前设备：%s）" % (devs or "none"))
            return 1
        a.serial = devs[0]
    print("[*] device: " + a.serial)

    root = su("id -u", a.serial).strip().splitlines()[-1]
    print("[*] su uid: " + root)
    if root != "0":
        print("[-] root 不可用")
        return 1
    caps = su("grep CapEff /proc/self/status", a.serial)
    m = re.search(r"CapEff:\s*([0-9a-f]+)", caps)
    if not m or int(m.group(1), 16) == 0:
        print("[-] root 缺少 capability（PTRACE 会失败）：" + caps.strip())
        return 1

    zyg = sh(["shell", "pidof zygote64"], a.serial).strip().split()
    if not zyg:
        print("[-] zygote64 未运行")
        return 1
    zp = zyg[0]
    print("[*] zygote64: " + zp)

    for f in (a.loader,):
        if not os.path.exists(f):
            print("[-] 缺少 %s（先 python3 tools/inject/build.py --src loader_fork.c --hook）" % f)
            return 1
    if not su("test -f " + a.stub + " && echo ok", a.serial).count("ok"):
        print("[-] 设备上缺少 %s（先 python3 tools/inject/build_stub.py 并 push）" % a.stub)
        return 1
    if not su("test -x " + TMP + "/AndKittyInjector && echo ok", a.serial).count("ok"):
        print("[-] 设备上缺少注入器 " + TMP + "/AndKittyInjector")
        return 1

    conf = "targets=%s\ngadget=%s\ndeday=%s\nstub=%s\n" % (a.pkg, a.gadget, a.deday, a.stub)
    print("[*] loader.conf:\n" + conf.rstrip())
    if a.check:
        print("[+] 环境检查通过")
        return 0

    local_conf = os.path.join(HERE, ".loader.conf.tmp")
    with open(local_conf, "w", newline="\n") as f:
        f.write(conf)
    try:
        push(local_conf, TMP + "/loader.conf", a.serial)
    finally:
        os.unlink(local_conf)
    push(a.loader, TMP + "/loader.so", a.serial)
    sh(["shell", "touch " + TMP + "/loader.on"], a.serial)

    print("[*] injecting...")
    su("setenforce 0", a.serial)
    try:
        out = su("%s/AndKittyInjector --pid %s --libs %s/loader.so --memfd --hide" % (TMP, zp, TMP), a.serial)
        print(out.strip().splitlines()[-1] if out.strip() else "")
        if "Injection succeeded" not in out:
            print("[-] 注入失败")
            print(out)
            return 1
    finally:
        su("setenforce 1", a.serial)
    print("[*] SELinux: " + sh(["shell", "getenforce"], a.serial).strip())

    port = gadget_port(a.gadget.split("%")[0], a.serial) or a.port
    if port:
        print("""
[+] 完成。启动目标后验证：
    adb -s {serial} forward tcp:{port} tcp:{port}
    frida-ps -H 127.0.0.1:{port}
    frida -H 127.0.0.1:{port} -n Gadget
注意：zygote hook 只在本次开机有效；改 deday 需重启后重新注入。""".format(serial=a.serial, port=port))
    else:
        print("""
[+] 完成。启动目标后验证：
    端口见 <gadget>.config.so 的 interaction.port，例如：
    adb -s {serial} forward tcp:<port> tcp:<port>
    frida-ps -H 127.0.0.1:<port>
    frida -H 127.0.0.1:<port> -n Gadget
注意：zygote hook 只在本次开机有效；改 deday 需重启后重新注入。""".format(serial=a.serial))
    return 0


if __name__ == "__main__":
    sys.exit(main())