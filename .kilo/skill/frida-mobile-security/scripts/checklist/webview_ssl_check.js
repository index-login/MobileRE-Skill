/**
 * webview_ssl_check.js — 检测 WebView 是否忽略 SSL 证书错误
 * 
 * 检测原理：
 *   1. Hook onReceivedSslError → 看 App 是否重写了这个回调
 *   2. Hook SslErrorHandler.proceed() → 看 App 是否调用了 proceed（忽略证书错误）
 *   3. 同时覆盖系统 WebView 和腾讯 X5 WebView
 * 
 * 用法：frida -H 127.0.0.1:8888 -f com.tdx.AndroidNewXZGJ.test -l webview_ssl_check.js
 */
Java.perform(function () {
    console.log("[*] WebView SSL Check Starting...\n");

    var findings = {
        systemWebView: { onSslError: false, proceed: false },
        x5WebView: { onSslError: false, proceed: false }
    };

    // ====== 1. 系统 WebView ======
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        
        WebViewClient.onReceivedSslError.overload(
            'android.webkit.WebView', 
            'android.webkit.SslErrorHandler', 
            'android.net.http.SslError'
        ).implementation = function (view, handler, error) {
            findings.systemWebView.onSslError = true;
            console.log("[!!!] WebViewClient.onReceivedSslError CALLED");
            console.log("    URL: " + view.getUrl());
            console.log("    Error: " + error.toString());
            
            // 打印调用栈定位代码
            var stack = Java.use("java.lang.Throwable").$new().getStackTrace();
            for (var i = 0; i < Math.min(stack.length, 8); i++) {
                console.log("    " + stack[i].toString());
            }
            console.log("");
            
            return this.onReceivedSslError(view, handler, error);
        };
        console.log("[+] Hooked: android.webkit.WebViewClient.onReceivedSslError");
    } catch (e) {
        console.log("[-] System WebViewClient hook failed: " + e);
    }

    // 系统 WebView SslErrorHandler.proceed()
    try {
        var SslErrorHandler = Java.use("android.webkit.SslErrorHandler");
        SslErrorHandler.proceed.implementation = function () {
            findings.systemWebView.proceed = true;
            console.log("\n[!!!] SslErrorHandler.proceed() CALLED — SSL ERROR IGNORED!");
            var stack = Java.use("java.lang.Throwable").$new().getStackTrace();
            for (var i = 0; i < Math.min(stack.length, 8); i++) {
                console.log("    " + stack[i].toString());
            }
            console.log("");
            return this.proceed();
        };
        console.log("[+] Hooked: android.webkit.SslErrorHandler.proceed");
    } catch (e) {
        console.log("[-] System SslErrorHandler hook failed: " + e);
    }

    // ====== 2. 腾讯 X5 WebView ======
    try {
        var X5WebViewClient = Java.use("com.tencent.smtt.sdk.WebViewClient");
        X5WebViewClient.onReceivedSslError.overload(
            'com.tencent.smtt.sdk.WebView',
            'com.tencent.smtt.sdk.SslErrorHandler',
            'android.net.http.SslError'
        ).implementation = function (view, handler, error) {
            findings.x5WebView.onSslError = true;
            console.log("[!!!] X5 WebViewClient.onReceivedSslError CALLED");
            console.log("    URL: " + view.getUrl());
            console.log("    Error: " + error.toString());
            var stack = Java.use("java.lang.Throwable").$new().getStackTrace();
            for (var i = 0; i < Math.min(stack.length, 8); i++) {
                console.log("    " + stack[i].toString());
            }
            console.log("");
            return this.onReceivedSslError(view, handler, error);
        };
        console.log("[+] Hooked: com.tencent.smtt.sdk.WebViewClient.onReceivedSslError");
    } catch (e) {
        console.log("[-] X5 WebViewClient not found (package not used): " + e.message);
    }

    try {
        var X5SslErrorHandler = Java.use("com.tencent.smtt.sdk.SslErrorHandler");
        X5SslErrorHandler.proceed.implementation = function () {
            findings.x5WebView.proceed = true;
            console.log("\n[!!!] X5 SslErrorHandler.proceed() CALLED — SSL ERROR IGNORED!");
            var stack = Java.use("java.lang.Throwable").$new().getStackTrace();
            for (var i = 0; i < Math.min(stack.length, 8); i++) {
                console.log("    " + stack[i].toString());
            }
            console.log("");
            return this.proceed();
        };
        console.log("[+] Hooked: com.tencent.smtt.sdk.SslErrorHandler.proceed");
    } catch (e) {
        console.log("[-] X5 SslErrorHandler not found: " + e.message);
    }

    console.log("\n[*] All hooks active. Visit WebView pages to trigger detection...");
    console.log("[*] Use Ctrl+C to stop, or wait for SSL events.\n");

    // 每 30 秒打印一次汇总
    function printSummary() {
        console.log("\n========== WebView SSL Check Summary ==========");
        console.log("System WebView:");
        console.log("  onReceivedSslError overridden: " + findings.systemWebView.onSslError);
        console.log("  proceed() called:             " + findings.systemWebView.proceed);
        if (findings.systemWebView.proceed) {
            console.log("  [VULNERABLE] SSL certificate errors are IGNORED!");
        } else if (findings.systemWebView.onSslError) {
            console.log("  [SAFE] onReceivedSslError overridden but proceed() NOT called");
        } else {
            console.log("  [N/A] No WebView SSL events detected yet");
        }
        console.log("===============================================\n");
        setTimeout(printSummary, 30000);
    }
    setTimeout(printSummary, 15000);
});