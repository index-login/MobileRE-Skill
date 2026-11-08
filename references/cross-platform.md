# 跨端框架分析（实测手法）

> 何时读：目标是 Flutter / uni-app / Cordova / mPaas / 科蓝等容器，DEX 里找不到业务逻辑，或要枚举 H5 桥、绕证书校验。

## 一、Flutter（Dart AOT）

**结构**：业务在 `lib/<abi>/libapp.so`（Dart AOT 快照），引擎在 `libflutter.so`（Skia + Dart VM + BoringSSL 副本）。

- `libapp.so` 导出：`_kDartIsolateSnapshotInstructions`、`_kDartVmSnapshotInstructions`、`_kDartIsolateSnapshotData`、`_kDartVmSnapshotData`、`_kDartSnapshotBuildId`。
- **头号坑**：工具（Blutter / dump）给的函数偏移相对 `_kDartIsolateSnapshotInstructions`，**不是模块基址**；该符号在模块内偏移为 MB 量级，漏加会让所有 hook 整体偏离。`hook = base + (sym - base) + offset`。

**找业务逻辑**：

1. 先 strings：未混淆构建保留库 URI（`package:<pkg>/...dart`）、类名、方法名、接口与常量。
2. 私有方法名带库哈希 `_foo@123456789`，`@` 后是库标识，可回连库路径。
3. 名字 → 地址靠 Blutter（需匹配的 Dart SDK），产物 `pp.txt` / `objs.txt` / `asm/`。
4. 混淆判定：`package:` 条数骤降、类名退化为单字母。

**先判 TLS 在哪**：Flutter 常只是 UI，真正握手可能在某 native 核心（自带 OpenSSL 并导出 `SSL_*`）。先跑 `scripts/monitors/tls_surface.js` 看哪个模块有 SSL_/X509_ 导出：有导出就按名 hook（`X509_verify_cert` / `SSL_CTX_set_verify`），只有字符串才回到下面的版本定位流程。

**工具边界**：`libapp.so` 无 `.symtab`、无 PLT 导入 → `so.py` 的符号/交叉引用、`emu_run` 的 C++ 约定都不成立，只能用段/字符串/字节；`libflutter.so` 只导出 `JNI_OnLoad`，按名字 findExport 必空；系统 `libssl.so` 与 Java 层 unpinning 均无效。

**证书校验绕过**：目标 `ssl_crypto_x509_session_verify_cert_chain`（`src/third_party/boringssl/src/ssl/ssl_x509.cc`），通过返回 **1**；patch 头为 `mov w0,#1; ret` 或 Frida `onLeave retval.replace(1)`（`bypass/flutter_ssl.js`）。**签名随版本变，公开模式常 0 命中**，定位顺序：`strings --grep ssl_x509.cc` → `strref`（引用点常落 `.cold` 几十字节小块，不能当目标）→ `.eh_frame` FDE 表恢复真实边界 → 挑三参数、循环证书栈、原样返回 w0 的函数 → `probe` 跑一次握手确认。只装系统 CA 仅对无 pinning 应用有效；`badCertificateCallback` 在 Dart 层，native 强制返回不覆盖。

**动态坑**：库晚于 App 加载（轮询再 attach）；Dart AOT 无 JNI 边界，参数不是 Java 对象；Blutter 版本不符会直接解析失败（先看 `_kDartSnapshotBuildId` 与快照头特性串）；split ABI 只装 arm64 时 32 位设备加载不到。

## 二、uni-app x（DCloud UTS）

- Android：UTS 编译成 Kotlin/DEX。类名带编译前缀 `Luni/UNIB4<hash>/GenPages<Page>;`，包 `uts.sdk.modules.*` / `io.dcloud.uniapp.*`；页面逻辑就是普通方法体，jadx 可读。**Android 包里没有 `app-service.js`，别去找。**
- iOS：业务在 `app-service.js`（可达 MB 级），由 `DCloudUniappRuntime` 内嵌 JSCore 执行。两端实现方式不同，结论不能互推。
- 桥：`uni-web-view` 经 `addJavascriptInterface` 注入 `window.__uniapp_x_`；外部页面能否拿到，取决于是否复用同一 WebView 实例。

## 三、科蓝银行框架（AresH5Container）

- 包前缀 `com.yitong.*`；容器 `AresH5Container`，桥 `YTJsBridge` 走 **WVJB（WebViewJavascriptBridge）**：Java 侧 `registerHandler(name)` 的方法名即可调用面全集，消息体 `{handlerName, data, callbackId}`。
- 枚举：`registerHandler` 调用点 → 方法名表 → 每个 handler 参数是否外部可控。

## 四、Cordova + mPaas（双容器）

- Cordova：插件白名单在 `res/xml/config.xml` 的 `<feature>`；统一入口 `CordovaPlugin.execute(action, args, callbackId)`，`action` 是外部可控字符串。
- mPaas：`com.alipay.mobile.nebula`，桥 `alipayjs.postMessage`；H5 路由查 `stage.json`。实测 URL 片段 `#weakauth` 能让弱实名页面直出——鉴权在 H5 侧，native 只负责放行。
- 双容器时先确认当前 WebView 归属（nebula `H5Page` / Cordova `CordovaWebView`），否则枚举到的是另一套桥。

## 五、RN / Hermes

- `index.android.bundle` 可能是 Hermes 字节码：`strings` / jadx 均看不到逻辑，用 `hbctool` / `hermes-dec` 反序列化。
- 桥面从 `@ReactMethod` 与 `postMessage` 入手。

## 六、通用手法

- 桥能力 = `registerHandler` / `@JavascriptInterface` 的**方法名与注解**，不是类名；注解在父类同样生效（继承来的方法也暴露）。
- H5 侧鉴权（路由白名单、`weakauth`）逻辑在 JS：native 只看到"放行"，漏洞结论必须落到 JS 片段才算成立。
- 业务在 JS 时，抓包 + 解包 H5 资源比反编译 native 快；native 只需查**桥**与**加载器**。
