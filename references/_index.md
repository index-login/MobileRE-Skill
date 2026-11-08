# references 索引（llm-wiki）

技巧手册与参考资料。**路径基准：项目根**（`references/<文档>`）。

约定：

- 新增文档 → 本表加一行（作用 + 何时读）；无索引不加文件。
- **重要手册**（任务域入口 / 卡点自救）同时登记进 `.kilo/agent/reverser.md`（常驻层），见「常驻」列。
- 字典 / 参考 / 文章类只留本表，按需查阅。
- 案例 / 回归记录 / 待办**不进手册**：回归记录放「其它资料」，单 App 案例放 `<包名>/REPORT.md`，待办进 FEEDBACK。
- 手册内路径基准：Frida 模块写 `scripts/<子目录>/<模块>`（相对 skill 根）；独立工具写 `tools/<工具>`（相对项目根）。可执行命令须可直接复现（写全路径，或注明先 `cd .kilo/skill/frida-mobile-security`）；文档头部须声明基准，已声明后同文档内可简写模块名。

## 修订纪律

手册是长期资产，按"写书"方式修订：

- **小步、定点、可审**：先判断归属（信息只存一份），不整段重写、不灌未验证内容；改动须有证据（实测/源码），存疑先记 `feedback/FEEDBACK.md`、不动文档
- **不留过程痕迹**：新增内容默认不写过程与来源（日期、来源人/脚本、调查经过、反馈编号）；仅当复现必需时保留最短前提（版本/环境约束），以"约束"形式而非"故事"形式写
- **反馈沉淀**：反馈闭环时，属通用纪律/规范的内容沉淀到对应常驻文件（`AGENTS.md` / `.kilo/agent/reverser.md` / 本索引），不只留在反馈日志里
- **面向 AI**：手册是给 AI 的经验补丁，只写决策依据、可执行路径与坑；不写教程式解释、不重复工具 help、不写案例流水账

## 链接写法

1. **就地引入，不堆末尾清单**：在讨论某个概念的**那句话里**说明"另一页那段讲什么"再给指针，读到这里就知道要不要跳。
   - ✗ `机制见 references/native-analysis.md`
   - ✓ 「函数大到读不下去就别硬读：[native-analysis.md ›「3.6 复杂函数离线仿真（emu_run 广度 + setup 助手）」](native-analysis.md#36-复杂函数离线仿真emu_run-广度--setup-助手) 里用 `emu_run` 跑起来，看它到底读写哪块内存。」
2. **链接文字固定为 `页面.md ›「完整章节标题」`，并配可点击锚点**：`[页面.md ›「章节标题」](页面.md#锚点)`。
   - **人**：点锚点直接跳到该标题；
   - **AI**：从链接文字取出「章节标题」→ 用 `grep` 工具（`pattern`=标题、`path`=页面.md、`context`≈60）取该段，或先取行号再 `read`(offset/limit) 读到下一个标题前——**不必整篇读**；
   - 锚点 = 标题小写、去标点、空格转 `-`、CJK 保留；
   - **标题在文件内必须唯一**（否则 grep 有歧义），且锚点失效时链接文字仍可人工定位。
3. **不引入链接类型/标签**（"参见 / 依赖 / 父级"）：语义靠正文那句话。
4. **锚点必须与标题一致**：落笔前确认标题存在；改标题须同步改锚点与所有引用。
5. **每页一行索引**：新增文档必须进下方「手册」表（作用 + 何时读）。

## 手册

| 文档 | 作用 | 何时读 | 常驻 |
|------|------|--------|:----:|
| `anti-detection.md` | 反调试/反注入对抗：检测原理、保活、模块选择与坑 | 检出 Frida、闪退、要藏特征 | ★ |
| `behavior-analysis.md` | 行为摸底、协议还原、Intent 污点、设备交互、内核文件事件（fsmon） | 看网络/跨组件、要操作设备、看文件落地 | ★ |
| `crypto-hook.md` | 加解密监控、hook/替换套路、SSL 明文、内存扫描 | 找算法/密钥、改参数、伪造返回 | ★ |
| `native-analysis.md` | SO 层下钻、Ghidra、离线仿真、结构体恢复、字符串/交叉引用 | 深挖 .so、单函数复算 | ★ |
| `native-audit.md` | SO 漏洞审计：可达面 → 分诊 → 深审（含环境能力 / malloc debug / Frida 内存守卫）→ tombstone 归因 → 函数级 fuzz | 要审 .so 找漏洞、判断"某函数是否可达"、怀疑越界/UAF/double-free | ★ |
| `so-analysis-pipeline.md` | **Ghidra 12 API 差异表、字符串符号化规则、`DAT_` 分类、失败方案清单**（流水线本身见 skill `so-function-recovery`） | 写 Ghidra 脚本报编译错、字符串不显示、想避开已否决方案 | — |
| `so-function-recovery.md` | **大型 SO 函数级还原方法论**：台账三层筛选、库边界用调用边密度判定、机械桩多条件判据、CFF case 块识别、VM 编码从 trace 反推、`DT_INIT` 指向函数内部、结构体动态实测、命名证据分级、完成判据（可执行流水线见 skill `so-function-recovery`） | 2000+ 函数要还原、不想重复读同一批函数、判断"分析到什么程度算完成" | ★ |
| `vmp-analysis`（skill） | **VM/VMP 8 步执行清单**：确认是 VM → 找表 → 取 trace 字段 → 写 profile → trace → verify → disasm → 命名。含常见报错处理 | 遇到字节码 VM 壳、要复用/新建编码模型 | — |
| `android-headers/` | ART/libdexfile 头文件（AOSP 原版）+ `art_make_structs.java` 结构体生成脚本。**头文件不入库**，用 `python3 tools/fetch_android_headers.py --tag <tag>` 按需拉；说明见 `android-headers/README.md` | 逆向 hook ART 的壳、要 ArtMethod/ClassLinker 真实偏移 |
| `tools/probe_layout.py` | **动态结构体布局探测（通用）**：按 ELF 段自动分类槽位、指针追踪、`--setup` 挂样本专属环境 | 静态看不出结构体布局时、要验证字段含义 | — |
| `tools/ptr_table.py` | **ELF 指针表枚举与分类（通用）**：扫连续代码指针数组、按目标分类、反查表槽位 | 找 VM 分派表/handler 表/虚表、判断某地址被哪张表引用 | — |
| `tools/fetch_android_headers.py` | 按 AOSP tag 抓 ART 头文件（走代理） | 换目标 Android 版本时重新取头文件 | — |
| `android-internals.md` | Android 机制：zygote/ART·ArtMethod/linker 命名空间/SELinux/PMS/Binder/检测面/加载时机 | 写注入或 hook、解释"为什么加载失败/被杀" | ★ |
| `so-func-naming.md` | 无符号函数命名：符号表优先、魔数/成对调用/参数·返回值模式、卡壳树 | 已知地址要判函数用途/算法 | — |
| `cross-platform.md` | 跨端框架手法：Flutter/Dart AOT（偏移基准、证书校验）、uni-app x、科蓝 Ares、Cordova+mPaas、RN/Hermes | DEX 里找不到业务逻辑、要枚举 H5 桥 | — |
| `so-emulation.md` | 单函数离线仿真：JNI/syscall/TLS 打桩、Harness / hooks.py 协作、卡壳树 | 要复算/解密/批量试输入、写 Harness | — |
| `static-analysis.md` | 攻击面枚举、序列化、WebView、jadx-mcp | 分析类/找入口/攻击面 | ★ |
| `troubleshooting.md` | 故障排查：无输出/闪退/hook 不生效/完整性校验 | 崩了、没输出、结果不可解释 | ★ |
| `unpacking.md` | 壳识别、脱壳、提取修复 | 加固壳、提 dex | ★ |
| `api-reference.md` | Frida API 手册（Interceptor/Stalker/RegisterNatives…） | 写自定义 hook 时查 | — |
| `articles.md` | 参考文章索引（脱壳原理/攻击面方法论） | 扩展阅读 | — |

## 其它资料

非手册类内容（回归清单、速查表、样本说明、临时结论等）。

| 文档 | 作用 | 何时读 |
|------|------|--------|
| `smoke-test.md` | 整套链路冒烟自检（L2/L3 回归 + 离线复算预期结果） | 回归验证 / 链路自检 |
| `../tools/ghidra/README.md` | **Ghidra / IDA 批量脚本唯一索引**：30 个脚本的类型（class/inline）、调用方式、cfg 键、默认值来源 | 要跑批量脚本、不确定某脚本怎么调 |
