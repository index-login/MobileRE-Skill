---
name: so-emulate
description: 用 Unicorn 离线调试/模拟单个 SO 函数：不启动 App 跟踪执行、对给定输入复算算法、解密或解码数据，或绕过 JNI/syscall/libc 等环境依赖。当用户要跑一个函数、验证算法输出、批量试输入、或真机 hook 不便时使用。SO 层深挖的单步能力，入口仍在 frida-mobile-security；能真机 hook 就先 hook；本 skill 不含调试器。
---

# so-emulate - 单函数离线仿真

用 Unicorn 离线调试/模拟单个 SO 函数：不启动 App 跟踪执行、对给定输入复算、解密/解码、或绕过 JNI/libc/syscall 依赖。

## 何时用 / 何时不用

| 用 | 不用 |
|---|---|
| 要试上万个输入 / 穷举 | App 能跑、只看一次真实调用 → **真机 hook** |
| 反调试挂不上 / 不想在设备留痕 | 依赖真实上下文（网络、文件、TEE）→ 真机 hook |
| 算法复算 / 解密验签 / 批量试参 | 要调试断点/单步 → GDB（本 skill 不是调试器） |
| 只想看这个函数对给定输入输出什么 | 要判漏洞/可达性 → `references/native-audit.md` |

## 前置

1. `pip install unicorn`（依赖见根目录 `requirements.txt`）。
2. `.so` 已拉到本地。
3. 先确认映射方式：`python3 tools/so.py info <so>` 看 PT_LOAD 的 `raw=YES/NO`。
4. 默认先真机 hook（[native-analysis.md ›「三、SO 动态分析」](../../../references/native-analysis.md)）；确实跑不了再仿真。

## 步骤

### 1. 一行跑起来

```bash
python3 tools/emu_run.py <so> --sym <export> --args "0,0" --timeout 5
# 按地址：--off 0x1234
# JNI：--jni --args "env,0" --trace-stubs
```

输出形如 `x0=0x0  insns=4`。

### 2. 看信号，对症处理

| 现象 | 含义 / 下一步 |
|---|---|
| 正常返回 `x0=…` | 成功；记录 `insns` 与输出 |
| 立刻取指/数据错 | 映射方式错：`so.py info` 看 `raw`；必要时 `--raw` |
| `[!] unstubbed: name` | 导入没桩：`--imp name` 或 `--stub name=val` |
| TLS 崩 / `__stack_chk_fail` | 走 Harness `setup_tls()`（见手册） |
| 一直不返回 | 加计数/`--timeout`；可能是死循环 |
| JNI 返回 NULL 后崩 | `--trace-stubs` 看命中槽位；按槽补桩 |

### 3. 要观测中间状态

```bash
--watch-code 0x… --watch-regs x0,x1 --watch-buf "x19+0x61f0:16"
--watch-read lo-hi --watch-write lo-hi --scan <hex>
```

日志可接 `tools/trace_recon.py`（缓冲状态序列）与 `tools/cipher_lab.py`（密码结构判定）。

### 4. 复杂调用（C++ 对象 / sret / GOT 桩）

- 先试 CLI 便捷项：`--ret-str`（sret 返回 `std::string`）、`--out-arg N:LEN`（dump 第 N 参缓冲）。
- 仍不够 → `--setup hooks.py`，用 `tools/emu_setup.py` 的 `std_string` / `std_vector` / `call_sret` / `install_stub`。

### 5. 记录结论

- 记录：so 指纹、函数地址/符号、参数、返回值、`insns`、桩命中
- 依赖真实上下文的结论标 **置信度**，必要时回真机 hook 复核

## 卡壳出口

| 症状 | 先查 |
|---|---|
| JNI 槽位推导 / TLS / syscall / 死循环 | [so-emulation.md ›「6. 卡壳树」](../../../references/so-emulation.md#6-卡壳树) |
| `emu_run` 参数与观测层细节 | [native-analysis.md ›「3.6 复杂函数离线仿真（emu_run 广度 + setup 助手）」](../../../references/native-analysis.md) |
| 不清楚该 hook 还是仿真 | [so-emulation.md ›「1. 定位：仿真是下钻手段，不是首选」](../../../references/so-emulation.md) |

## 产出

- 复算结果（输入 → 输出）与置信度
- 必要时附 `hooks.py`（可复现）
- 关键发现写 `REPORT.md`
