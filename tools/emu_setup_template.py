#!/usr/bin/env python3
"""emu_setup_template.py — 样本环境准备脚本骨架（`--setup` 契约）。

用法
----
复制到 `<包名>/tools/setup_<name>.py`，然后：

    python3 tools/emu_run.py <so> --sym <入口> --setup <包名>/tools/setup_<name>.py --args "vm,0"
    python3 tools/probe_layout.py <so> --entry <入口> --setup <包名>/tools/setup_<name>.py --at 0x<全局>
    python3 tools/vmp.py trace <so> -p <profile> --setup <包名>/tools/setup_<name>.py

三个工具用同一个 `prepare(h, so_path, data)` 契约。

设计
----
前 4 步是**通用**的（脱壳镜像都会遇到），不用改。第 5 步是样本专属，按日志补。

**先不加第 5 步跑一遍**，看 `[!] unstubbed` 日志缺哪些桩，再逐个补 —— 这是
给陌生壳搭环境的标准套路：不要预先猜它需要什么，让程序自己告诉你。

返回
----
`prepare()` 的返回值写进 `h.jni_vm`，之后 `--args "vm,0"` 才能解析 `vm` 记号。
VM 壳通常返回 JavaVM*；不需要 JNI 的普通 SO 返回 0。
"""
import struct


def prepare(h, so_path, data):
    # ---------------------------------------------------------------- 1) 脱壳镜像清理
    # 内存 dump 会把上一进程写进 .bss 的内容一起带下来（壳的运行时标志位、指针）。
    # 不清零的话 vm_runtime_alloc 之类会把壳的标志位当成有效 pthread key。
    from emu_run import clear_runtime_bss
    n = clear_runtime_bss(h, so_path)
    print("[setup] bss cleared: %d bytes" % n)

    # ---------------------------------------------------------------- 2) 重定位 + GOT 桩
    # 走 PT_DYNAMIC（脱壳镜像的 section header 常被伪造），未定义导入 → ret 桩。
    from emu_run import make_libc_stubs, apply_relocations
    stubs = make_libc_stubs(h, set())
    n = apply_relocations(h, so_path, stubs)
    print("[setup] relocations applied: %d imports" % n)

    # ---------------------------------------------------------------- 3) 运行时指针快照中和
    # .rodata 里残留的上一进程 libc 地址（如 0x78aa...），不在重定位表里，
    # 跳过去必然 UC_ERR_FETCH_UNMAPPED。排除重定位槽，避免覆盖刚写好的桩。
    from emu_run import neutralize_runtime_ptrs, _relocation_offsets
    n = neutralize_runtime_ptrs(h, so_path, skip=_relocation_offsets(so_path))
    print("[setup] runtime ptr snapshots neutralized: %d" % n)

    # ---------------------------------------------------------------- 4) JNI 两级表 + syscall 层
    # JavaVM* -> JNIInvokeInterface*（GetEnv @ idx 7）
    # JNIEnv* -> JNINativeInterface*（GetJavaVM @ idx 219）
    # 只造 JNIEnv 而把 vm 传 0，会让 GetEnv 读 [0+0x38] 落到 ELF 头。
    from emu_run import build_jni, install_syscalls, _ret0
    env_addr = build_jni(h, _ret0)
    vm_addr = getattr(h, "jni_vm", 0)
    print("[setup] env=%#x vm=%#x" % (env_addr, vm_addr))

    # VM 内部普遍直接发 `svc #0`（mmap/mprotect/getpid），不装会以 UC_ERR_EXCEPTION 中断
    install_syscalls(h, log=False)
    print("[setup] syscall layer installed")

    # ---------------------------------------------------------------- 5) 【样本专属】补桩
    # 跑一遍看 `[!] unstubbed: <name>` 日志，把这里逐个补上。常见几类：
    #
    #   a) 分配器类：让 mmap 返回一块真内存（而不是 0）
    #   b) TLS 类：pthread_getspecific/setspecific 要有真实语义（key -> value）
    #   c) 时间/环境类：gettimeofday / __system_property_get 返回固定值（避免分支随机）
    #   d) 文件类：fopen 返回假 FILE*，fgets 返回 EOF（或喂固定内容）
    #
    # 示例（按需启用，不要全部照抄）：
    #
    #   from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1
    #
    #   def cb_mmap(uc, addr, size, user):
    #       want = uc.reg_read(UC_ARM64_REG_X1) or 0x1000
    #       uc.reg_write(UC_ARM64_REG_X0, h.alloc(want, align=0x1000))
    #
    #   def cb_prop_get(uc, addr, size, user):
    #       # __system_property_get(name, buf) -> 写入固定值，返回长度
    #       buf = uc.reg_read(UC_ARM64_REG_X1)
    #       val = b"29\x00"
    #       uc.mem_write(buf, val)
    #       uc.reg_write(UC_ARM64_REG_X0, len(val) - 1)
    #
    #   h.install_stub 不存在；用下面这行的形式覆盖（stubs 字典在 apply_relocations 前建）：
    #   实际做法：改第 2 步的 make_libc_stubs 调用，传自己的覆盖表。

    # ---------------------------------------------------------------- 6) 返回 JavaVM*
    return vm_addr


# ---------------------------------------------------------------- 可选：自检
if __name__ == "__main__":
    print(__doc__)
    print("契约: prepare(h, so_path, data) -> JavaVM*")
    print("先不加第 5 步跑一遍，按 [!] unstubbed 日志补桩。")
