# references 索引（llm-wiki）

技巧手册与参考资料。**路径基准：项目根**（`references/<文档>`）。

约定：

- 新增文档 → 本表加一行（作用 + 何时读）；无索引不加文件。
- **重要手册**（任务域入口 / 卡点自救）同时登记进 `.kilo/agent/reverser.md`（常驻层），见「常驻」列。
- 字典 / 参考 / 文章类只留本表，按需查阅。
- 案例 / 回归记录 / 待办**不进手册**：回归记录放「其它资料」，单 App 案例放 `<包名>/REPORT.md`，待办进 FEEDBACK。
- 手册内路径基准：Frida 模块写 `scripts/<子目录>/<模块>`（相对 skill 根）；独立工具写 `tools/<工具>`（相对项目根）。可执行命令须可直接复现（写全路径，或注明先 `cd .kilo/skill/frida-mobile-security`）；文档头部须声明基准，已声明后同文档内可简写模块名。

## 手册

| 文档 | 作用 | 何时读 | 常驻 |
|------|------|--------|:----:|
| `anti-detection.md` | 反调试/反注入对抗：检测原理、保活、模块选择与坑 | 检出 Frida、闪退、要藏特征 | ★ |
| `behavior-analysis.md` | 行为摸底、协议还原、Intent 污点、设备交互 | 看网络/跨组件、要操作设备 | ★ |
| `crypto-hook.md` | 加解密监控、hook/替换套路、SSL 明文、内存扫描 | 找算法/密钥、改参数、伪造返回 | ★ |
| `native-analysis.md` | SO 层下钻、Ghidra、离线仿真、字符串/交叉引用 | 深挖 .so、单函数复算 | ★ |
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
