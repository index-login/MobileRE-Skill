# 加密/功能 Hook（crypto-hook）

> 何时读：用户提到"加密明文/算法/密钥/AES/找明文/加密前数据/hook 方法/修改参数/伪造返回值/SSL 证书/TrustManager/onReceivedSslError"时读取。
> 由 SKILL.md 任务路由表指向，按需读取。相关模块在 `scripts/monitors/`（命令里的 `scripts/...` 为技能相对：复制执行先 `cd .kilo/skill/frida-mobile-security` 或展开全路径 `.kilo/skill/frida-mobile-security/scripts/...`）。

---

## 一、加密算法分析决策树

```
Step 1: crypto_monitor（Java 层自吐）
  模块: utils + crypto_monitor
  │
  ├── [有输出] → 拿到算法、密钥(hex/base64)、IV、明文/密文
  │               配置 showStack:true 从调用栈定位业务代码 → 结束
  │
  └── [无输出] → 加密不在 Java 层，判因下钻
       ├── Java.available = false → 纯 native 进程/iOS → Step 2-Native
       ├── 自定义 ClassLoader/反射 → hook ClassLoader.loadClass 定位类名
       └── 加密在 native 层（OpenSSL/BoringSSL/自实现）→ Step 2-Native

Step 2-Native: native_hooker
  模块: utils + native_hooker(targetLibs:["libencrypt","libssl","libcrypto"])
  ├── [命中] → 自动打印参数(hexdump)/返回值/调用栈
  ├── [STRIPPED] → 追加 dlsym_tracer 看运行时解析
  ├── [没找到明显 crypto so] → 清空 targetLibs 扫描全部 /data/ so
  └── Step 3: network_monitor 字节级兜底
       模块: utils + network_monitor(showPayload:true) + syscall_tracer
       密文必经 write/sendto 发出 → backtrace → so+offset
```

### 加密算法识别线索

| 特征 | 算法 |
|------|------|
| 32/48/64 位 hex 字符串 | AES-128/192/256 |
| `eyJ...` 格式 | JWT Token |
| `-----BEGIN...PRIVATE KEY-----` | PEM 私钥 |
| `AKIA...` / `AIza...` / `ghp_...` / `sk_live_...` | AWS/Google/GitHub/Stripe key |
| `https://user:pass@host` | URL 凭证 |

## 二、内存敏感数据扫描（memory_scanner）

`memory_scanner.js` 做三件事：
1. 自动扫描预设高价值数据（AES key、JWT、私钥、API key、URL 凭证）
2. 实时监听密码输入框的输入内容
3. 通过 Frida console 提供交互式搜索 API

```
Step 1: 加载模块
  frida -U -f com.app -l scripts/core/utils.js -l scripts/monitors/memory_scanner.js
  → 3 秒后自动扫描一次，输出所有匹配

Step 2: 交互式搜索（Frida console 中执行）
  MemoryScanner.search("password")               搜索所有 rw- 内存区域
  MemoryScanner.searchJava("api_key")            搜索 Java 堆 String 对象
  MemoryScanner.searchMod("libnative.so", "secret")  搜索指定模块
  MemoryScanner.dump("0x7a12345678", 256)        hexdump 指定地址
  MemoryScanner.stats()                          查看扫描统计
  MemoryScanner.scanNow()                        手动触发一次完整扫描
  MemoryScanner.addPattern("MY_KEY", "sk-[a-z]{24}")  添加自定义模式

Step 3: 密码输入捕获（Frida console 中启动，无需 -e 参数）
  MemoryScanner.startPasswordCapture()  启动密码输入监听
  MemoryScanner.passwordCaptureStatus() 查看状态
  → 自动检测 EditText 的 password 类型字段，输入时实时输出
```

## 三、Java Hook 模板

```bash
# 枚举已加载的类（按关键词过滤）
frida -U -f com.app -e 'Java.perform(function(){Java.enumerateLoadedClasses({onMatch:function(n){if(n.indexOf("keyword")!==-1)console.log(n);},onComplete:function(){}});});'

# Hook 指定方法并打印返回值
frida -U -f com.app -l scripts/core/utils.js \
  -e 'Java.perform(function(){var C=Java.use("com.example.Class");C.method.implementation=function(){var r=this.method();console.log("[*]",r);return r;};});'

# 修改参数 / 伪造返回值
frida -U -f com.app -l scripts/core/utils.js \
  -e 'Java.perform(function(){var C=Java.use("com.example.Class");C.method.implementation=function(a){a=0;return 1;};});'
```

## 四、Python 工作流（推荐）

避免手敲超长 CLI 命令。使用 `scripts/templates/analysis.py`：

```
1. 复制 analysis.py → <包名>/analysis.py
2. 修改 TARGET_PACKAGE / LOAD_MODULES / CONFIG_OVERRIDE
3. 在 CUSTOM_HOOK_SCRIPT 中写入 app 专属逻辑
4. 运行: python analysis.py
```

模板自动处理模块加载顺序（utils.js 首加载 → monitors → bypass → 自定义脚本）。`CONFIG_OVERRIDE` 以 Python dict 形式配置。

**交互模式**（需要用户在 app 上点击按钮）：设 `TIMEOUT=0`（手动 Ctrl+C 停止）和 `LOG_TO_FILE=True`。

---

## 五、SSL/TLS 忽略检测 — 全层参考

Android App 的网络通信分 5 层架构，每层 SSL 忽略的检测 API 不同。**`onReceivedSslError` 是 WebView 专属，不能用于检测 OkHttp。**

### 检测判定标准速查

| 层 | 框架 | 检测点 | 漏洞特征 |
|----|------|--------|---------|
| Java HTTP | OkHttp 3/4 | `X509TrustManager.checkServerTrusted()` | 方法体为空 |
| Java HTTP | OkHttp 3/4 | `HostnameVerifier.verify()` | `return true;` |
| Java HTTP | Retrofit | 同上（底层即 OkHttp） | 查 `OkHttpClient` 构造处 |
| Java HTTP | HttpURLConnection | `HttpsURLConnection.setDefaultSSLSocketFactory()` | 注入 TrustAll SSLSocketFactory |
| Java HTTP | HttpURLConnection | `HttpsURLConnection.setDefaultHostnameVerifier()` | `return true;` |
| Java HTTP | Volley | `HurlStack` 自定义 `SSLSocketFactory` | 查 `Volley.newRequestQueue` 的 stack 参数 |
| WebView | 系统 WebView | `WebViewClient.onReceivedSslError()` | 调用了 `handler.proceed()` |
| WebView | 腾讯 X5 | `IX5WebViewClient.onReceivedSslError()` | 同上，`com.tencent.smtt.sdk` |
| WebView | UC | `com.uc.webview.export.WebViewClient` | 同上 |
| Native | OpenSSL/BoringSSL | `SSL_CTX_set_verify(ctx, mode, ...)` | `mode` = `SSL_VERIFY_NONE` (0x00) |
| Native | OpenSSL | `SSL_set_verify(ssl, mode, ...)` | 同上 |
| Native | libcurl | `curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L)` | 参数为 0 |
| Native | MbedTLS | `mbedtls_ssl_conf_authmode()` | 设为 `MBEDTLS_SSL_VERIFY_NONE` |
| WebSocket | OkHttp WS | 继承 OkHttp SSL 配置 | 同上 OkHttp 检测点 |
| WebSocket | Java-WebSocket | 自定义 `SSLSocketFactory` | TrustAll 工厂 |
| 全局配置 | Network Security Config | `res/xml/network_security_config.xml` | `<certificates src="user" />` 信任用户证书 |
| 全局配置 | Network Security Config | 同上 XML | `<domain-config cleartextTrafficPermitted="true">` |

### 静态检测方法 (JADX)

| 目标 | JADX 搜索关键字 |
|------|----------------|
| OkHttp TrustAll | `checkServerTrusted` → 方法体为空 |
| OkHttp HostnameVerifier | `HostnameVerifier` → `return true` |
| OkHttp Builder 注入 | `sslSocketFactory` + `hostnameVerifier` |
| WebView SSL 忽略 | `onReceivedSslError` → 含 `proceed()` |
| X5 WebView | `com.tencent.smtt` + `onReceivedSslError` |
| Native SSL_VERIFY_NONE | 搜索字符串 `SSL_VERIFY_NONE` |
| Network Security Config | `jadx_get_resource_file("res/xml/network_security_config.xml")` |

### 动态检测方法 (Frida)

| 目标 | Hook 点 | 模块 |
|------|--------|------|
| OkHttp SSLContext Init | `javax.net.ssl.SSLContext.init()` → 检查 `TrustManager[]` 是否 TrustAll | `ssl_plaintext.js` |
| OkHttp HostnameVerifier | `javax.net.ssl.HostnameVerifier.verify()` → 日志 `return true` | `ssl_plaintext.js` |
| WebView SSL 忽略 | `android.webkit.SslErrorHandler.proceed()` | 自定义 hook |
| X5 WebView SSL | `com.tencent.smtt.sdk.SslErrorHandler.proceed()` | 自定义 hook |
| Native SSL_CTX_set_verify | `libssl.so` → `SSL_CTX_set_verify` → 打印 `mode` 参数 | `native_hooker.js` |
| Native curl | `libcurl.so` → `curl_easy_setopt` → `CURLOPT_SSL_VERIFYPEER` | `native_hooker.js` |
| WebView SSL 清单 | `scripts/checklist/webview_ssl_check.js` | checklist 脚本 |

> **绕过（抓包场景）**：通用多栈绕过用 `scripts/bypass/ssl_unpinning.js`（SSLContext/TrustAll、OkHttp2/3、WebView、HttpsURLConnection、XUtils、httpclientandroidlib、Conscrypt、OpenSSLSocketImpl、TrustKit、Cronet、Appcelerator 共 12 类目）；native TLS/自研国密 SDK（GMSSL 等）不在覆盖内，需 `native_hooker.js`（SSL_CTX_set_verify / SSL_set_verify / curl_easy_setopt）或绕开 TLS 走 hook 层。

### 检测优先级（金融 App 视角）

| 优先级 | 检测层 | 原因 |
|--------|--------|------|
| **P0** | OkHttp `X509TrustManager` + `HostnameVerifier` | 覆盖率 90%+，API 全量暴露 |
| **P0** | WebView `onReceivedSslError` → `proceed()` | H5 页面含敏感操作 |
| **P1** | X5 WebView 同等接口 | 金融 App 高占比 |
| **P1** | Native `SSL_CTX_set_verify` | 核心交易/加密常走 Native |
| **P2** | Network Security Config 信任用户证书 | 配合抓包利用 |
| **P2** | HttpURLConnection / Volley / libcurl | 老项目残留 |

### 常见误判

| 误判 | 纠正 |
|------|------|
| 在 OkHttp 层搜索 `onReceivedSslError` | 这是 WebView API，OkHttp 不适用 |
| 在 WebView 层搜索 `checkServerTrusted` | 这是 OkHttp API，WebView 不适用 |
| 看到 `SSLSocketFactory` 自定义就判漏洞 | 需确认 TrustManager 是否 TrustAll，正常自定义 TLS 协议版本是安全的 |
| 看到 `onReceivedSslError` 重写就判漏洞 | 必须确认内部调用了 `handler.proceed()`，仅 log 不调用是安全的 |

---

## 六、Android Keystore 密钥策略审计

### 何时读

App 用生物识别/硬件密钥保护本地数据，或抓到的密文怀疑由 Keystore 密钥加密时。
目标：拿到"密钥是什么、怎么保护的、能不能导出"三类事实，再据此定后续路线。

### 决策树

```
想拿到什么？
├─ 只要事实（密钥清单 / 创建策略 / 密钥操作）
│   → utils + monitors/keystore_monitor
└─ 还要"哪些配置是弱的"（领域判定）
    → utils + monitors/keystore_monitor + checklist/keystore_audit
        （audit 自带 hook，可单独加载）
```

### 关键事实 → 解读（判断依据）

脚本只输出事实，以下是**解读配方**（不进脚本）：

| 事实 | 解读 |
|---|---|
| `insideSecureHardware=true` | 密钥在安全硬件，`getEncoded()` 必为 null，无法导出 |
| `getEncoded() != null`（AndroidKeyStore 密钥） | 异常：密钥材料可被应用读到 |
| `origin=IMPORTED` | 密钥由外部导入，非本机生成 |
| `userAuthRequired=true` + `validityDuration=-1` | 每次使用都需认证（最强） |
| `userAuthRequired=true` + `validityDuration>0` | 解锁后**该秒数内**可复用密钥（无需再次认证） |
| `userAuthRequired=false` | 密钥不绑定用户认证 |
| `invalidatedByBiometricEnrollment=false` | 新增生物特征后旧密钥仍有效 |
| `randomizedEncryptionRequired=false` | 调用方可控 IV |
| 用途位（purposes） | ENCRYPT / DECRYPT / SIGN / VERIFY / WRAP_KEY / UNWRAP_KEY / DERIVE_KEY / AGREE_KEY |

标准域对照（**参考**；条款编号随版本变，勿硬编码）：认证绑定强度 → MASVS `AUTH-2`；
密钥存储/不可导出 → `CRYPTO-1`；IV/算法配置 → `CRYPTO-2`。

### 判定规则（checklist/keystore_audit）

| 规则 | 条件 | 级别 |
|---|---|---|
| K1 | `userAuthRequired=true` 且 `validityDuration>0` | WEAK |
| K2 | `userAuthRequired=false` | INFO |
| K3 | `userAuthRequired=true` 且 `invalidatedByBiometricEnrollment=false` | WEAK |
| K4 | `userAuthRequired=true` 且 `unlockedDeviceRequired≠true` | INFO |
| K5 | `insideSecureHardware=false` | INFO |
| K6 | `origin=IMPORTED` | INFO |
| K7 | AndroidKeyStore 密钥却 `getEncoded()!=null` | HIGH |
| K8 | `randomizedEncryptionRequired=false` | WEAK |
| K9 | ECB / AES<128 / NoPadding(加密) / DIGEST_NONE(签名) | WEAK·INFO |

K4 会与 K1/K3 同时命中（同一密钥的多个事实），属预期；用 `severityFloor` 降噪。
规则是纯函数，可离线自测：`KeystoreAudit.evaluate(view)`。

### 坑

| 坑 | 说明 |
|---|---|
| 用 `getKey` 拿不到 KeyInfo | KeyInfo 须经 `SecretKeyFactory`/`KeyFactory.getKeySpec(key, KeyInfo.class)` 取（脚本已处理） |
| `getEntry` 返回 Entry 不是 Key | 需再取 `getSecretKey()/getPrivateKey()`（脚本已处理） |
| alias 归属靠 `lastBuilderAlias` 启发式 | Builder 实例→alias 无稳定映射；顺序构造时准确，交叉构造会串味 |
| 部分 getter 随 API level 缺失 | 脚本逐个 `try/catch`，缺失即跳过（如 `setUserPresenceRequired` 在 Android 10 不存在） |
| 硬件密钥不可导出 | 这是设计而非缺陷；结论应是"走设备+认证路线"，不是"无法分析" |

---

## 常用组合

| 分析目标 | 模块组合 |
|---------|---------|
| 加解密自吐 | `utils + crypto_monitor` |
| Native 加密 | `utils + native_hooker`（默认模式: encrypt/decrypt/aes/rsa/des/sha/hmac/base64/xor） |
| HTTP 明文 | `utils + ssl_plaintext` |
| 内存敏感数据 | `utils + memory_scanner` |
| 看特定 URL | `utils + ssl_plaintext(urlFilter:["api.example.com"])` |
| Keystore 密钥事实 | `utils + keystore_monitor` |
| Keystore 弱配置判定 | `utils + keystore_monitor + keystore_audit` |