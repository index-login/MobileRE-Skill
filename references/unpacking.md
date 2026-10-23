# 脱壳（Unpacking）

> 何时读：用户提到"脱壳/加固解密/提取 dex/so 提取/FART/frida-dexdump/指令抽取"时读取。
> 由 SKILL.md 任务路由表指向，按需读取。Python 工具在项目根 `tools/`；Frida JS 模块（`codeitem_dump` / `dex_finder` / `dex_cache_dump` / `dex_defineclass_dump` / `scan_register_natives`）在 skill `scripts/utils/`（root 内存 dump 见 skill `dex-mem-dump/`）。

---

## 脱壳策略：先分诊，成本递增（默认决策）

**别一上来就跑 Frida。** 顺序：分诊 → 最轻工具 → 逐级升级。

### Step 0 分诊（先花 5 分钟，决定后面怎么走）
1. **有没有壳**：Application 类（`com.stub.StubApp` / `StubShell`…）、lib 目录壳 SO、DEX 内壳字符串、assets 次级载荷。
2. **DEX 形态**：APK 内 DEX 的 `class_defs` 与方法体统计（coded / native / return-void）。
3. 判定：
   - **无壳**（明文 DEX + 方法体完整 + 无壳特征）→ 直接 `unzip` 提取 DEX，**到此为止**，不进任何 dump 流水线。
   - **有壳** → 进 Step 1。

### Step 1 root 内存 dump（非 Frida，优先）
`panda-dex-dumper` / `mem-dex-dumper`（skill `dex-mem-dump`），只读 `/proc/<pid>/mem`，不注入、不 ptrace，对 Frida 检测隐身；panda 用 SIGSTOP 冻结快照，mem 用 `-b mem`/`-b vmreadv` 双后端交叉校验。
- 覆盖：一代壳（整体加密）；二代壳已回填部分。
- **门禁自检**：读不到目标 `/proc/<pid>/maps` 时，先**对照另一个 App**——只有目标读不到才怀疑其 `PR_SET_DUMPABLE=0`（转 Step 2）；都读不到则是环境/权限问题。注意 `maps` 属主 `root:root` 在 Magisk/hidepid 设备上是全局现象，**不能**据此判定。
- 地址归属：命中后回查 `/proc/<pid>/maps`，`/data/app/.../base.apk` = 业务 DEX，`/system/framework/*.jar`、`/apex/*/javalib/*.jar` = 系统噪音。
- checksum：壳改过内存后必失效，jadx 报 `Bad dex file checksum` → `python3 tools/dex_rebuilder.py --fix-checksum <dex> -o fixed.dex`。

#### 工具机制与重建

二进制在 `.kilo/skill/dex-mem-dump/`（arm64 静态；`mem-dex-dumper.c` 带源码）。

**扫描流程**：解析 `/proc/<pid>/maps` → 按 1 MiB 分块读（7 字节重叠，防 `dex\n` magic 跨块）→ 扫 `dex\n` + 3 位版本 + NUL → 校验 header（`header_size==0x70`、`endian_tag` 合法、`file_size` 在 0x70~1 GiB、string/class 表落在文件内）→ 去重 → 按 `file_size` dump。读到一半失败会保留部分数据（日志 `dumped < file_size`）。

**重建**（NDK r21+）：

```bash
aarch64-linux-android29-clang -O2 -static -o mem-dex-dumper mem-dex-dumper.c
llvm-strip mem-dex-dumper
```

`mem-dex-dumper` 有源码可改；`panda-dex-dumper` 是第三方二进制，只能绕不能修。

### Step 2 Frida 脱壳（升级项，仅在需要时）
`unpack.py`（codeitem_dump whole + dex_finder），一次 spawn/attach 完成回填与采集。
- **只在 Step 1 拿不到完整方法体（抽取壳未回填、需 loadClass 触发）时用**；三代 Dex2C/VMP 也走这里看 native 占比。
- **前提**：Frida 已能稳定注入（绕过检测属于 anti-detection / bypass，不在本工具内）。
- 代价：触发反注入检测、留 Frida 痕迹、慢、可能影响目标。

---

## Step 2 细节：`unpack.py` 一键流程（需 Frida 升级时）

**需要回填时，一条命令，线性自动完成：**

```bash
python3 tools/unpack.py <包名> [--out 输出目录] [--wait 45]
```

> `--wait` 是**停滞判定**：多少秒没有任何新进度才算卡死，只要还在推进就一直等；`--timeout N` 才是绝对上限（默认 0 = 不限）。

**连接方式（frida-server / Gadget / 任意端口）**：

| 场景 | 命令 |
|---|---|
| USB 直连 frida-server | `--usb` |
| 端口转发（默认） | `--host 127.0.0.1:8888`（自动 `adb forward`） |
| Gadget / 自定义端口 | `--host 127.0.0.1:<port> --pid <pid>`；进程唯一时可省略 `--pid` 自动 attach |
| Gadget 且无 root | 自动切外部私有目录；可显式 `--ext`（Android 11+ 若 `/sdcard/Android/data` 受限，需 root 或改私有目录） |
| 已手动转发 / Gadget 走内网 | 加 `--no-forward` |
| 多进程（`:remote`） | `--all-pids` |
| 多设备 | `--serial <序列号>` |

**内部自动执行**（单次 spawn/attach，同一会话）：
1. **dex_defineclass_dump**：DefineClass 钩子，抓运行时动态定义的 DEX（最先挂；`--no-defineclass` 关闭）
2. **codeitem_dump whole**：loadClass 全部类（默认回填）→ dump DEX；**每 15 批增量落盘**，中途被杀已落盘部分不丢
3. **dex_finder 补充**：同一会话接续扫描；stage1 无产物时**自动开 deepSearch**
4. **自动 pull**（私有目录走 root→`/sdcard`；`--ext` 直拉外部私有目录；**只此一个目录**，无兜底）
5. **fix-checksum**（壳改过内存后必失效）
6. **去重**（dex_dedupe）
7. **方法体标记** + `_unpack_summary.txt`（含 CDEX 提示）
8. **清理设备端**：拉取成功后删除私有/外部产物与兜底目录；`--keep` 保留

**产物保护**：启动时旧产物轮换为 `dump.prev`（`--fresh` 才清空），采集失败仍可回取。

**节奏控制**（壳对异常 loadClass 敏感时）：`--batch 50 --delay 800`；仍被杀属方法级回填壳（需 FART/AOSP）。

**为什么默认全量回填**：`loadClass` 对一代壳无害（无副作用），对抽取壳必要（触发回填）——无需判断壳类型，无脑全量即可。Dex2C/VMP 只标记不深挖。

**产物**：统一目录 + 每文件状态标记，直接拖进 jadx 静态分析。

**AI 查看脱壳产物的备选方案**：无 jadx-gui 时，用 jadx CLI 把 dump 产物转成 .java 文件目录，AI 直接 `read`/`grep` 读文件分析（比 jadx MCP 更灵活，不依赖 GUI 打开）。jadx CLI 路径按环境探测（不写死）：

```bash
# 探测 jadx CLI 路径（三选一，按环境）
# 1. 环境变量
echo $JADX_JAR   # Windows: %JADX_JAR%
# 2. PATH 中的 jadx 命令（Windows 上 jadx-gui 同目录）
where jadx        # Windows
# 3. 常见安装位置（Windows 示例）
#   C:\Program Files\jadx\lib\jadx-gui-*.jar
#   C:\jadx\lib\jadx-gui-*.jar
```

找到后转换：

```bash
# 批量转换 dump 目录下所有 DEX 为 java 文件
java -cp "<JADX_JAR路径>" jadx.cli.JadxCLI -d ./sources <dump目录>/*.dex
# 或单文件
java -cp "<JADX_JAR路径>" jadx.cli.JadxCLI -d ./sources <dump目录>/classes.dex
```

DEX 已 fix-checksum（unpack.py 内置），无需 `-Pdex-input.verify-checksum=no`；若手动 dump 未修复需加该参数。转换后 `read <sources>/com/xxx/Class.java` 查看源码。

**何时需要动底层脚本**（unpack.py 之外）：
- 产物 `[Dex2C]` 标记 → `scripts/utils/scan_register_natives.js` 定位 + native-analysis.md 分析
- jadx 打不开/类缺失 → `scripts/utils/dex_cache_dump.js` 精确 dump（抹 magic/假 DEX 场景）
- 延迟加载 DEX 未捕获 → `scripts/utils/dex_defineclass_dump.js` 被动拦截
- 高级抽取壳（方法执行粒度）→ codeitem_dump 调小 batchSize / 增大 batchDelay

---

## 壳识别

加固厂商通过 SO 文件名识别（常见）：

| SO 文件名 | 厂商 |
|-----------|------|
| `libjiagu.so` / `libjgdtc.so` | 360 |
| `libshell*.so` / `libtup.so` | 腾讯乐固 |
| `libDexHelper.so` | 梆梆 |
| `libexec.so` / `libexecmain.so` | 爱加密 |
| `libnaga.so` | 娜迦 |
| `libnesec.so` / `libsec2023.so` | 网易易盾 |

辅助识别：Application 类名 `com.stub.StubApp`（360）、`com.tencent.StubShell.TxAppEntry`（腾讯乐固）等。

三代壳原理（决定分析策略）：
1. **一代（整体加密）**：整 dex 加密，运行时整体解密 → 内存有完整明文，搜 magic 即可
2. **二代（指令抽取）**：方法体被抽走，运行时按需回填 → 需 loadClass 触发回填
3. **三代（VMP）/Dex2C**：方法体在 DEX 层永久丢失（虚拟指令/机器码）→ 脱壳无效，转 native-analysis.md

---

## 产物验证决策树

```
jadx 打开 dump 产物（先 fix-checksum）：
├─ 能反编译 + 显示业务类 → 成功
├─ 类齐全 + 方法体空 → 抽取壳未回填，检查 loadClass 是否触发 / 是否方法执行粒度壳
├─ 类缺失 / 全是系统类 → 假 DEX 干扰，转 scripts/utils/dex_cache_dump.js
└─ native 方法占比高 → Dex2C，转 scripts/utils/scan_register_natives.js 按需分析
```

---

## 关键细节（排查时必读，AI 常漏）

- **所有 dump 产物必须 fix-checksum**：壳修改 DEX 内存后 checksum 不同步，jadx 报 `Bad dex file checksum`。`unpack.py` 内置；手动 dump 用 `dex_rebuilder.py --fix-checksum`
- **输出目录必须是 app 私有目录**（`/data/data/<包名>/files/dump/`）：脚本在 app 进程内执行，`/data/local/tmp/` 属 root 无写权限
- **目录解析必须延迟**：spawn 早期 `Java.perform` 异步，`currentApplication()` 为 null，`getDumpDir()` 失败——需在 setTimeout 回调或惰性重试
- **判断"能否用"必须真跑 jadx**：REPORT.md 等旧记录只作参考，不代表现行结论（曾误判 7 个 DEX"可用"实为 checksum 未验证）
- **方法体判定**：return-void(0x0E) 占比高 → 抽取未回填；native 方法占比高 → Dex2C
- **deepSearch 谨慎**：`scripts/utils/dex_finder.js` 的 deep 会对未映射内存误命中产生假地址噪音；`unpack.py` 默认关，**stage1 无产物时自动开**，也可 `--deep` 强制

---

## 实战要点

- frida-dexdump 的 `-d` 深度扫描会对 OAT 缓存合并区重复 dump（七猫案例：96 DEX 实为 40 个独立）——统计前必须 dex_dedupe.py
- 反检测强的壳（MobiKwik/AppSealing 检测 frida + root）需先过 `anti-detection.md` 再脱壳
- 多进程场景：主进程 dump 后子进程（`:remote`、`:push`）需单独 dump