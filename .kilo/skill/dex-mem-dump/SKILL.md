---
name: dex-mem-dump
description: 运行时 DEX 内存 dump / 脱壳（root 直读 /proc/<pid>/mem，不注入、不 ptrace）：常规解包拿不到、抽取壳未回填、或目标查 TracerPid 时用。流程：推工具 → 跑 → 拉回 → 清理；分诊与排障见 references/unpacking.md。
---

# dex-mem-dump - 运行时 DEX dump

从运行中进程的内存里抠 DEX。两个 arm64 工具，都不走 ptrace：

| 工具 | 访问方式 | 冻结目标 | 定位 |
|---|---|---|---|
| `panda-dex-dumper` | `/proc/<pid>/mem` | 是（SIGSTOP/SIGCONT） | 主选：快、快照一致 |
| `mem-dex-dumper` | `/proc/<pid>/mem` 或 `process_vm_readv(2)` | 否 | 备选 / 交叉校验 / 不能冻结时 |

> 二者都不用 `ptrace`。目标即使已用 `PTRACE_TRACEME` 占住 ptrace 槽（TracerPid != 0）也挡不住；能挡住的是真正基于 ptrace 的 dumper。
>
> 二进制与源码在本 skill 目录；`mem-dex-dumper` 为本仓库自研。

## 何时用 / 何时不用

| 场景 | 走本卡 | 说明 |
|---|---|---|
| 有壳，想先低成本拿 DEX | ✅ | 不注入、无痕、比 Frida 快 |
| 一代壳（整体加密） | ✅ | 解密后的完整 DEX 就在内存里 |
| 抽取壳，只要类名 / 结构 | ✅ | 骨架够用 |
| 抽取壳，要完整方法体 | ❌ → `tools/unpack.py` | 被动扫描拿不到未执行过的方法体 |
| Frida 一挂就被杀 | ✅ 退路 | 只能拿已执行过的部分，产物必须标注不完整 |
| 无壳 | ❌ | 直接 unzip，不进任何 dump |
| 目标是 SO / native | ❌ | 走 native 分析 |

**边界**：本卡是**被动取快照**，`tools/unpack.py` 是**主动触发回填**——后者靠 `loadClass` 让壳把方法体写回 DEX，所以能补出前者原理上拿不到的内容；代价是必须过 Frida 检测。对"按方法执行粒度回填"的高级壳，两者都拿不到，转 native。升级路径：分诊 → 本卡（快照）→ 方法体齐全则结束 → 骨架则 `tools/unpack.py`（回填）→ 仍骨架 = 高级壳。

分诊与升级细节见 [references/unpacking.md ›「Step 1 root 内存 dump（非 Frida，优先）」](../../../references/unpacking.md#step-1-root-内存-dump非-frida优先)。

## 前置

1. `adb devices` 有设备；多设备所有命令加 `-s <serial>`。
2. 目标进程在跑，且已过启动页（载荷解密后才在内存里）。
3. root 可用：`adb shell su -c 'id'` 返回 uid=0。
4. 二进制已推送（步骤 1）。本页路径以**项目根**为基准。

## 步骤

### 1. 推工具

```bash
adb push .kilo/skill/dex-mem-dump/panda-dex-dumper /data/local/tmp/
adb shell chmod +x /data/local/tmp/panda-dex-dumper
```

`mem-dex-dumper` 同理，只换文件名。

### 2. 取 pid

```bash
adb shell pidof <包名>
```

- 为空 → 先拉起：`adb shell monkey -p <包名> -c android.intent.category.LAUNCHER 1`
- 多个 pid → 每个都要 dump，载荷可能只在其中一个。

### 3. 跑

```bash
# 主选：panda（SIGSTOP 冻结快照）
adb shell "cd /data/local/tmp && ./panda-dex-dumper -p <pid>"

# 备选：mem（不冻结；-b mem 默认，-b vmreadv 换后端）
adb shell "su -c 'cd /data/local/tmp && ./mem-dex-dumper -p <pid> -o /data/local/tmp/memdump'"
```

### 4. 拉回

```bash
adb pull /data/local/tmp/panda/ ./
adb pull /data/local/tmp/memdump/ ./
```

### 5. 清理

```bash
adb shell "su -c 'rm -rf /data/local/tmp/panda /data/local/tmp/memdump /data/local/tmp/panda-dex-dumper /data/local/tmp/mem-dex-dumper'"
```

## 判据

| 现象 | 结论 |
|---|---|
| 每命中一行 `find dex off: 0x… file_size: 0x… dumped: 0x…` | 正常输出 |
| 末行 `scanned N bytes, done.` | 扫描结束 |
| `dumped < file_size` | 读到一半失败，文件残缺 → 重跑或换 panda |
| 命中地址在 `[anon:libc_malloc]` 等匿名堆 | 载荷（业务 DEX） |
| 命中地址在 `/system/framework/*.jar`、`/apex/*/javalib/*.jar`、`*.vdex` | 系统噪音，忽略 |
| 两工具同地址 md5 相同 | 抓取一致，可信 |
| 有 `class_defs` 但方法体多为 `return-void` | 抽取壳骨架 → 升级 `tools/unpack.py` |

## 卡壳出口

| 症状 | 先查 |
|---|---|
| `open /proc/<pid>/mem: Permission denied` | 非 root / SELinux → `su -c`、`setenforce 0`；仍失败换 `-b vmreadv` |
| 完全没命中，但 App 明明加固了 | 载荷未解密 → 停在功能页再跑；或换 panda 冻结 |
| 文件很大（几十 MB） | `.vdex` 内嵌 header，噪音；载荷在匿名堆 |
| 部分类解析失败 | 边扫边写的撕裂读 → 重跑；要一致快照用 panda |
| 两工具结果不一致 | 校验松紧不同，属正常；以严格校验的 mem 为准，再手工补 |
| 设备上跑不起来 | arm64-only、静态链接、API 29；按文末重建 |

更细的排障（`PR_SET_DUMPABLE`、`hidepid`、多进程）见 [references/unpacking.md ›「Step 1 root 内存 dump（非 Frida，优先）」](../../../references/unpacking.md#step-1-root-内存-dump非-frida优先)。

## 产出

- DEX 落到 `<包名>/dex/`（或用户指定目录），保留工具原始命名。
- 壳改过内存时 checksum 必失效：`python3 tools/dex_rebuilder.py --fix-checksum <dump.dex> -o fixed.dex`，否则 jadx 报 `Bad dex file checksum`。
- `REPORT.md` 记：工具、后端、命中地址 → maps 归属、md5 交叉校验。
- 设备侧产物与二进制必须清掉。

## 工具机制

扫描/校验细节与重建步骤见 [references/unpacking.md ›「工具机制与重建」](../../../references/unpacking.md#工具机制与重建)。
