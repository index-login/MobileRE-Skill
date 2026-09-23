# 静态分析（jadx-mcp 攻击面）

> 何时读：用户提到"分析这个类/攻击面/序列化/反序列化/WebView/深链/Provider/Intent-filter"时读取。
> 由 SKILL.md 任务路由表指向，按需读取。使用 jadx MCP 工具（`jadx_*`）。

---

## 一、攻击面枚举方法论

**攻击面优先，hook 在后。** 先枚举所有外部可控入口，再决定 hook 什么。

### 1.1 入口枚举（从 AndroidManifest 出发）

| 入口 | 检查项 | 工具 |
|------|--------|------|
| Exported Activity | 是否有 intent-filter、是否 `<android:exported="true">`、是否需权限 | `jadx_get_android_manifest` |
| Exported Service | 能否被外部 startService | 同上 |
| Broadcast Receiver | 隐式 Intent 能否触发 | 同上 |
| Content Provider | 读写权限、path traversal、FileProvider | 同上 |
| Deep Link | scheme/host 配置、Intent Redirection | 搜索 intent-filter |
| WebView 入口 | JS Bridge、loadUrl 可控性 | 搜索 `WebView` / `addJavascriptInterface` |
| 反序列化入口 | Serializable/Parcelable 类 | 搜索 `readObject` / `createFromParcel` |

### 1.2 数据流追踪（Taint Analysis）

```
Source（外部输入：Intent extras、URI 参数、文件路径、网络请求）
  → Path（经过的代码路径）
  → Sink（危险操作：startActivity、loadUrl、File.write、rawQuery、exec）
```

- 模式匹配看代码行，污点分析追完整攻击路径
- 跨组件跟踪：数据流经 Activity → Intent → Service/Receiver/Provider，多数工具在组件边界失明，需人工追踪
- 7 类必须用污点分析才能检测的漏洞：路径遍历、Intent 重定向、WebView URL 注入、SQL 注入、Token 拦截、HTML/JS 注入、SSRF

### 1.3 攻击面不限于单 App

- 跨 App 共享 UID、隐式 Intent 劫持、权限继承、预装系统 App 的特权链路都是入口
- SDK 继承宿主信任边界：攻击面 = SDK 代码 + 宿主代码，SAST 必须分析编译产物而非源码

---

## 二、序列化攻击面扫描（Serializable / Parcelable）

```
Android 中所有 Serializable/Parcelable 类都可从 Intent 反序列化。
攻击者构造恶意对象塞入 Intent extras → 触发 readObject()/createFromParcel() 中的危险 sink。

Step 1: 搜索候选类（JADX）
  方法1: 搜索方法名 "readObject" → 找到所有自定义反序列化入口
  方法2: 搜索方法名 "createFromParcel" → 找到所有 Parcelable 工厂方法
  方法3: 搜索类声明 "implements Serializable" / "implements Parcelable"

Step 2: 逐个检查反序列化链
  对每个 readObject(ObjectInputStream) 方法，追踪数据流：
    ois.readObject() / readUTF() / readInt() 等  ← SOURCE
    → 赋值给 this.xxx 字段                          ← FLOW
    → 后续方法使用 this.xxx 做了什么？              ← SINK?

Step 3: 重点 sink 模式
  ├── Class.forName(字段).newInstance()       → 任意类实例化（Google Auth bug）
  ├── Class.forName(字段).getMethod().invoke() → 任意方法反射调用
  ├── new FileInputStream(字段) / new File(字段) → 路径遍历文件读取
  ├── Runtime.exec(字段) / ProcessBuilder(字段) → 命令注入
  ├── loadUrl(字段) / loadData(字段)           → WebView URL 注入
  ├── startActivity(字段) / startService(字段) → Intent 重定向
  └── SQLiteDatabase.execSQL(字段)            → SQL 注入

Step 4: 确认字段外部可控
  只要满足任一条件，字段即外部可控：
  ├── 类本身实现了 Serializable → 可直接 Intent.putExtra()
  ├── 类是某个 Intent extra 的成员字段 → 间接可控
  └── 类通过 Bundle.putSerializable() 传递 → 间接可控
```

### 真实案例

Google Auth Library `OAuth2Credentials`：`transportFactoryClassName` 字段可控 → `Class.forName(str).newInstance()`，bounty $3,133.70。

---

## 三、WebView 安全审计

| 检查点 | 漏洞特征 |
|--------|---------|
| `addJavascriptInterface` | JS Bridge 暴露敏感方法 |
| `setJavaScriptEnabled(true)` + 外部 URL | XSS 风险 |
| `setAllowFileAccess(true)` | 任意文件读取 |
| `onReceivedSslError` → `proceed()` | SSL 忽略（见 crypto-hook.md） |
| `intent://` scheme | Intent 重定向 |
| `loadUrl` 参数可控 | URL 注入 |

---

## 四、Deep Link / Content Provider

### Deep Link 漏洞模式（5 种）

1. scheme hijacking — scheme 可被恶意 app 抢注
2. open redirect — 深链跳转到外部 URL
3. intent redirection — 深链构造 Intent 跳转
4. full intent redirection — 深链携带完整 Intent
5. domain takeover — 域名归属变化

### Content Provider 漏洞（7 类）

1. 不安全 FileProvider
2. 路径遍历
3. 权限声明错误
4. 代理请求降级
5. 动态 URI 代理
6. 敏感功能混入 CP
7. SQL 注入

---

## 五、jadx-mcp 工具速查

| 工具 | 用途 |
|------|------|
| `jadx_get_android_manifest` | 读取 AndroidManifest.xml |
| `jadx_get_main_activity_class` | 获取主 Activity |
| `jadx_get_main_application_classes_names` | 主应用类列表 |
| `jadx_get_class_source` | 获取类源码 |
| `jadx_get_methods_of_class` / `jadx_get_method_by_name` | 方法列表/源码 |
| `jadx_get_fields_of_class` | 字段列表 |
| `jadx_search_method_by_name` | 全局方法搜索（如 readObject） |
| `jadx_get_resource_file` | 资源文件（如 network_security_config.xml） |
| `jadx_get_smali_of_class` | smali 源码 |
| `jadx_get_selected_text` | 获取当前选中文本 |
| `jadx_rename_*` | 重命名类/方法/字段 |

### Manifest 解析失败（jadx 乱码/二进制）

- 症状：jadx 输出二进制 AXML（头 `03 00 0C 00`），apktool 报 `got: 0x000c0003` → 爱加密魔改（首 chunk 插 4 字节 + headerSize 谎报 0x000C）
- 修复：`tools/fix_axml.py`（删 4 字节填充 + headerSize 回 8 + size 减 4）
  ```bash
  python3 tools/fix_axml.py -i base.apk -o base_fixed.apk
  ```
- 验证：jadx CLI `--no-src` 重解应为文本；备选 `aapt dump xmltree base.apk AndroidManifest.xml`

---

## 与动态分析的配合

**静态找可能，动态验证实。** JADX 找代码路径（广度），Frida 验证运行时可达性（精度）。

| 静态发现 | 动态验证 |
|---------|---------|
| 可疑 Intent 传递 | `intent_tracker`（behavior-analysis.md） |
| 加密调用点 | `crypto_monitor`（crypto-hook.md） |
| 反序列化 sink | 触发 deeplink 后观察 file/network 日志 |
| 免检 WebView | `scripts/checklist/webview_ssl_check.js` |