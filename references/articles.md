# 参考文章索引

> 何时读：需要引用文章/方法论出处、写报告归因、或学习脱壳原理和攻击面方法论时读取。
> 由 SKILL.md 任务路由表指向，按需读取。方法论要点已沉淀到 `unpacking.md` 和 `static-analysis.md`。

---

## 脱壳原理

### Frida学习笔记（二十六）：DEX 脱壳实战
- 链接: https://mp.weixin.qq.com/s/8DRlBCUFGHL6Toxp5YufgA
- 作者: 泡泡以安
- 日期: 2026-07
- 核心内容:
  - 三代壳原理（整体加密 → 指令抽取 → VMP/Dex2C）
  - 加固厂商识别（SO 文件名 ↔ 厂商对应表）
  - frida-dexdump 源码精读（magic 通配、map_list 校验、mprotect 提权、fix_header 修复）
  - frida_dump 源码精读（DefineClass 被动拦截、DexCache 主动枚举）
  - FART 源码精读（主动 loadClass + hook LoadMethod + CodeItem 离线重组）
  - 七猫小说实战（裸 DEX，96 个 DEX 中 40 个真独立，10 个 OAT 缓存重复）
  - MobiKwik/AppSealing v2.35.1 实战（GOT-XOR 62 槽位、三进程架构、16 个检测因子）
- 适用场景: 面试准备、脱壳工具选型、报告归因

## Android 攻击面方法论

参考来源：Oversecured Blog (https://oversecured.com/blog)

### SDK Security in Mobile Apps
- 链接: https://oversecured.com/blog/blog-sdk-security-mobile-apps
- 核心: 第三方 SDK 继承宿主信任边界，攻击面 = SDK 代码 + 宿主代码，SAST 必须分析编译产物而非源码
- 适用场景: 攻击面枚举、SDK 漏洞归因

### Android Deep Link Vulnerabilities
- 链接: https://oversecured.com/blog/android-deep-link-vulnerabilities
- 核心: Intent Filter 配置不当 → Account Takeover，5 种漏洞模式（scheme hijacking / open redirect / intent redirection / full intent redirection / domain takeover）
- 适用场景: 深度链接安全审计、Intent Redirection 检测

### Content Providers Weak Spots
- 链接: https://oversecured.com/blog/content-providers-and-the-potential-weak-spots-they-can-have
- 核心: 7 类 Content Provider 漏洞（不安全 FileProvider / 路径遍历 / 权限声明错误 / 代理请求降级 / 动态 URI 代理 / 敏感功能混入 CP / SQL 注入）
- 适用场景: Content Provider 安全审计

### Android Security Checklist: WebView
- 链接: https://oversecured.com/blog/android-security-checklist-webview
- 核心: WebView 全攻击面（JS Bridge / SSL 绕过 / 文件访问 / intent:// / HierarchicalUri）
- 适用场景: WebView 安全审计

### Android Security Checklist: Theft of Arbitrary Files
- 链接: https://oversecured.com/blog/android-security-checklist-theft-of-arbitrary-files
- 核心: 任意文件窃取链（Intent Redirection → Content Provider → FileProvider 路径遍历）
- 适用场景: 文件安全审计、漏洞链追踪

### Inside Mobile Taint Analysis: How Source-to-Sink Tracking Finds Real Data-Leak Paths
- 链接: https://oversecured.com/blog/inside-mobile-taint-analysis
- 日期: 2026-04-24
- 核心:
  - 模式匹配 vs 污点分析的本质区别：前者看代码行，后者追完整攻击路径（Source → Flow → Sink）
  - 跨组件跟踪（Cross-Component Tracking）：数据流经 Activity → Intent → Service/Receiver/Provider，多数工具在组件边界失明
  - 7 类必须用污点分析才能检测的漏洞：路径遍历、Intent 重定向、WebView URL 注入、SQL 注入、Token 拦截、HTML/JS 注入、SSRF
  - Flag-based sanitizer 建模：不是二分（安全/不安全），而是按漏洞类型分别标记（路径遍历 flag 被 split 清除，但 XSS flag 可能保留）
  - Serializable/Parcelable 反序列化攻击面：所有实现了这些接口的类都可以从 Intent 反序列化，`readObject()` → `Class.forName().newInstance()` 是典型 sink
  - 真实案例：Google Auth Library `OAuth2Credentials`，`transportFactoryClassName` 字段可控 → `Class.forName(str).newInstance()`，bounty $3,133.70
- 适用场景: 污点分析方法论、攻击面枚举、跨组件漏洞链追踪、Serializable 反序列化审计

## Case Study：跨应用漏洞链实战

### Two Weeks of Securing Samsung Devices: Part 1
- 链接: https://oversecured.com/blog/two-weeks-of-securing-samsung-devices-part-1
- 核心: 7 个 CVE，覆盖 6 种漏洞模式——exported Service 安装任意 App、vendor 修改 AOSP 绕过权限校验、Intent Redirection 窃取 Content Provider 权限、sharedUserId 跨应用提权、exported Receiver 写任意文件、隐式 Intent 劫持
- 适用场景: 跨应用攻击面分析、sharedUserId 信任链、预装 App 安全审计

### Two Weeks of Securing Samsung Devices: Part 2
- 链接: https://oversecured.com/blog/two-weeks-of-securing-samsung-devices-part-2
- 核心: 5 个 CVE，重点——sharedUserId="android.uid.system" 串联两个 App 的 FileProvider 实现系统级文件读写、protectionLevel 不设默认 normal 导致权限绕过、隐式 Intent 劫持 + setResult 注入
- 适用场景: 系统 UID 提权链、permission 默认值审计、隐式 Intent 劫持