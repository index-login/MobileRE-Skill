# AGENTS.md — 开发规范

所有脚本、模块、工具的开发规范。编码时遵循此规范，确保产出可组合、可观测、可复现。

## 编码规范

### Frida 脚本 (JavaScript)

- 语言：JavaScript（Frida QuickJS / V8），非 Node.js，无 `require`、无 npm
- 文件编码：UTF-8 无 BOM
- 缩进：2 空格，不混用 Tab
- 变量名 camelCase，常量 UPPER_SNAKE_CASE
- 函数单一职责，单个 hook 逻辑不超过 50 行
- 不写注释，除非逻辑不直观需要解释 why
- 使用 `utils.js` 提供的工具函数，不重复实现

### Python 工具

- Python 3.9+，使用 frida Python binding
- 配置通过 dict 注入，不硬编码路径/参数
- 模板：`scripts/templates/analysis.py`

### bat 检测脚本

- 放在 `tools/` 目录
- 结构化输出，方便截图取证
- 前置条件在脚本头部注释说明

## 模块结构

采用「常驻层 + 加载层 + 知识层 + 工具层」四层结构，引用基准为**项目根**：

```
MobileRE-Skill/                    ← 工作目录（项目根）
├── references/                    ← 知识层：技巧手册 wiki（项目级共享）
│   ├── _index.md                    ← 全量索引（作用 / 何时读 / 是否常驻）
│   ├── anti-detection.md            环境对抗
│   ├── unpacking.md                 脱壳
│   ├── crypto-hook.md               加密/功能 hook
│   ├── behavior-analysis.md         行为分析
│   ├── static-analysis.md           静态分析（jadx-mcp）
│   ├── native-analysis.md           SO 层分析
│   ├── troubleshooting.md           故障诊断
│   ├── api-reference.md             Frida API 参考
│   └── articles.md                  参考文章索引
├── tools/                         ← 工具层：独立工具（py/bat/jar，无 Frida 依赖）
│   ├── so.py                        SO 静态分析（ELF 侦察/字符串/反汇编/交叉引用/SVC/JNI 判型）
│   ├── unpack.py / dex_*.py         脱壳与 DEX 处理
│   ├── frida_run.py / device_ui.py   非交互 Frida 运行 / 设备交互
│   ├── emu_run.py / uniharness.py   离线仿真（rev-unicorn-debug）
│   └── check-*.bat / debug-gdb.py / janus_check.py   检测项（注入/调试/Janus）
├── <包名>/                         ← 每个 App 的分析产物（不入库）
├── feedback/FEEDBACK.md            ← 反馈积压（agent 级，本地保留不入库）
└── .kilo/
    ├── agent/reverser.md           ← 常驻层：工作纪律 + 重要手册清单
    └── skill/frida-mobile-security/
        ├── SKILL.md                ← 加载层：任务路由 + 决策树导航 + 模块目录（精华区）
        └── scripts/                ← Frida JS 模块（由 frida `-l` 加载）
            ├── core/utils.js         ← 始终首个加载，提供公共工具
            ├── monitors/             ← 纯观测，不修改行为
            ├── bypass/               ← 主动干预，修改 app 行为
            ├── utils/                ← 内存 dump / 运行时 JS 工具
            ├── checklist/            ← 检测清单脚本
            └── templates/            ← 模板，复制后修改使用
```

规则：
- **工具即路径**：独立工具放项目根 `tools/`（py/bat/jar），Frida JS 模块留在 skill `scripts/`；两边都不加转发包装层
- **信息只存一份**：知识只存在于 SKILL.md 或某个 references 之一，不重复
- **常驻层只放纪律与指针**：`.kilo/agent/reverser.md` 只写重要手册（作用 + 何时读）与停手规则，技巧知识只存 `references/`
- **新手册**：`references/<域>.md` + `_index.md` 加一行；属重要手册（任务域入口 / 卡点自救）同时登记 `.kilo/agent/reverser.md`
- **新工具**：独立工具放 `tools/`，Frida JS 模块放对应 `scripts/` 子目录，并在 SKILL.md 模块目录加一行
- **路径基准**：命令按需写全（工作目录 = 项目根）；`references/*` 相对项目根，`scripts/*` 相对 skill 目录

新模块导出标准接口：

```javascript
var CONFIG = { ... };
if (typeof CONFIG_OVERRIDE !== 'undefined') {
    Object.assign(CONFIG, CONFIG_OVERRIDE[模块名] || {});
}
```

## Frida API 约定

- **Hook 前先检查目标是否存在**：`Java.use()` 前用 `Java.available`，`Module.findExportByName()` 前用 `Module.findBaseAddress()`
- **大量数据用 `send()` 而非 `console.log()`**：`send()` 走 channel，`console.log()` 走 stdout，大数据会丢
- **Interceptor.attach 比 Interceptor.replace 安全**：replace 替换原函数，签名不匹配会崩
- **Native callback 必须持有引用**：`new NativeCallback(...)` 赋值给全局变量，否则 GC 回收后崩溃
- **Stalker 只在必要时用**：性能开销大，用 `Interceptor.attach` + `Thread.backtrace()` 能解决的不要 Stalker

## 软件工程原则

- **单一职责**：一个模块做一件事，不要把监控和绕过混在一起
- **可组合**：模块通过 `-l` 参数组合，不互相依赖
- **可观测**：所有 hook 点必须有日志输出，不能静默吞掉
- **可复现**：脚本能在其他设备上跑，不依赖特定路径硬编码
- **最小权限**：只 hook 需要的目标，不做全量扫描除非明确要求

## Karpathy 编码准则

写 Frida Agent 脚本时遵循 `karpathy-guidelines` skill 的 4 条原则：

1. **Think Before Coding** — 不假设，暴露不确定性。hook 前先确认目标类/方法存在。
2. **Simplicity First** — 最少代码解决问题。不写投机性 hook，不加未请求的功能。
3. **Surgical Changes** — 只改必须改的。修改现有模块时不顺手重构，匹配已有风格。
4. **Goal-Driven Execution** — 定义可验证的成功标准。hook 有输出 = 成功，无输出 = 需排查。

## 反馈协议

分析过程中遇到以下情况时，往 `feedback/FEEDBACK.md`（项目根，agent 级）**追加**一条（不改写他人条目；状态更新与归档见文件头协议）：

- 决策树某个分支走不通或没覆盖
- 模块崩溃 / 无输出 / 逻辑错
- 发现需要但不存在的能力
- AGENTS/SKILL 说明误导了判断

字段约束：
- 类型限 5 种：`decision-tree` / `module-bug` / `missing-module` / `doc` / `tool`
- 复现**必须**给完整 `frida` 命令（开发时原样跑）
- 状态默认 `open`；谁修复谁闭环——附核对证据后改 `closed` 并移入归档，无证据不得关闭

## 不重复造轮子

- 写新模块前先查 `scripts/` 是否已有可复用的
- 写新手册前先查 `references/_index.md`，避免重复；知识与文档不重复两处
- `utils.js` 已有日志格式化、hexdump、backtrace 解析，直接调用
- 配置走 `CONFIG_OVERRIDE` 机制，不硬编码
- 检测类脚本放 `checklist/`，监控类放 `monitors/`，绕过类放 `bypass/`
- 新增可复用工具 → 放对应 `scripts/` 子目录（或 `tools/`），**路径即入口**；在 SKILL.md 模块目录登记
- 修工具 bug 直接改脚本本身（不加转发包装层）

## 工具登记（防遗忘）

- 写一次性脚本前先查对应 skill 的 SKILL.md 模块目录（工具索引：在哪/叫什么/干什么）
- 可复用的工具沉淀到项目根 `tools/`（独立工具）或 skill `scripts/`（Frida JS 模块），并在 SKILL.md 模块目录登记
- 一次性产物留在 `<包名>/`，每个 App 以 `REPORT.md` 收口（新会话先读报告再动手）
- 新增/删除工具后同步 SKILL.md 模块目录（唯一索引，不维护全局清单）
- **skill 内容为会话开始快照**：编辑 SKILL.md / skill 文件后，同一会话内 `skill` 工具仍可能返回旧版；新会话生效。判断与执行一律以磁盘文件为准

## 能力选择（工具预算）

- MCP 工具列表每次请求常驻上下文（30+ 工具 ≈ 数 K tokens）；只保留"没有它就不行"的 MCP（本仓库：jadx / ghidra）
- 有维护中的 MCP → 直接用，不重复造；没有 → 写成 `scripts/`/`tools/` 下的独立脚本（可移植 + 可脚本化 + 零常驻成本）
- 设备交互用 `tools/device_ui.py`（元素树/按文本点击/等待/常亮）

## 集成新检测项

把新的检测能力集成到 skill 时：

1. 判断类型：Frida JS 模块 → `scripts/`，独立工具（py/bat/jar）→ 项目根 `tools/`，模板 → `templates/`
2. 遵循上述模块规范（CONFIG、CONFIG_OVERRIDE）
3. 沉渍到对应技巧域：更新 SKILL.md 路由表（如新技巧域则新建 references/<域>.md）
4. 更新 SKILL.md 模块目录和常用组合速查表
5. 添加反馈条目（如有）