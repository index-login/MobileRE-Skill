# 脱壳（Unpacking）

> 何时读：用户提到"脱壳/加固解密/提取 dex/so 提取/FART/frida-dexdump/指令抽取"时读取。
> 由 SKILL.md 任务路由表指向，按需读取。Python 工具在项目根 `tools/`；Frida JS 模块（`codeitem_dump` / `dex_finder` / `dex_cache_dump` / `dex_defineclass_dump` / `scan_register_natives`）在 skill `scripts/utils/`（root 内存 dump 见 skill `rev-dex-dumper/`）。

---

## 一键脱壳（默认工作流）

**大多数场景直接跑 `unpack.py`，一条命令，线性自动完成，无需 AI 决策：**

```bash
python3 tools/unpack.py <包名> [--out 输出目录] [--wait 120]
```

内部自动执行（默认全量回填，无判断环节）：
1. **codeitem_dump whole**：spawn → loadClass 全部类（默认回填函数体）→ dump 全部 DEX
2. **dex_finder 补充**：内存扫描 DexCache 未覆盖的 DEX（deepSearch 默认关，避免假 DEX 噪音）
3. **自动 pull** 产物到本地（app 私有目录 → /sdcard → 本地）
4. **默认 fix-checksum**（全部 DEX，壳修改内存后 checksum 必失效）
5. **去重**（dex_dedupe）
6. **方法体标记**：`[OK]` 完整 / `[Dex2C]` native 占比高 / `[Skeleton]` 抽取未完成

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
- **deepSearch 谨慎**：`scripts/utils/dex_finder.js` 的 deep 会对未映射内存误命中产生大量假地址噪音，unpack.py 默认关闭

---

## 实战要点

- frida-dexdump 的 `-d` 深度扫描会对 OAT 缓存合并区重复 dump（七猫案例：96 DEX 实为 40 个独立）——统计前必须 dex_dedupe.py
- 反检测强的壳（MobiKwik/AppSealing 检测 frida + root）需先过 `anti-detection.md` 再脱壳
- 多进程场景：主进程 dump 后子进程（`:remote`、`:push`）需单独 dump