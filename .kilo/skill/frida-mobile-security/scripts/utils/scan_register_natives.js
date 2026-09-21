/**
 * scan_register_natives.js - 定位 native 方法实现（Dex2C 按需分析第一步）
 * 用途：hook art::JNI::RegisterNatives，建立「Java 方法名 → native 函数地址 → so+offset」映射
 *       拿到偏移后喂给 Ghidra 反汇编单个函数，实现 Dex2C 按需分析（不脱壳、不全量逆向）
 * 对比 frida-dexdump：Dex2C 的 DEX 方法体是 native 跳转，脱壳无效；本脚本是运行时定位，直接找实现
 * 加载：frida -U -f com.app -l scripts/core/utils.js -l scripts/utils/scan_register_natives.js
 * 用法：定位后输出 libxxx.so + 0xoffset，用 Ghidra 打开该 so 反汇编对应函数
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) { console.log("[-] scan_register_natives requires utils.js (load it first)"); return; }

    var CONFIG = U.mergeConfig('scan_register_natives', {
        // 只输出类名含这些关键字的注册，空 = 全部
        filterClass: [],
        // 只输出方法名含这些关键字的注册，空 = 全部
        filterMethod: [],
        // 按方法名过滤（如 ["encrypt","sign","check"]），空 = 全量输出
        methodKeywords: [],
        // 只输出指向 /data/app/ 下 SO 的注册（排除系统库）
        onlyAppSo: true,
        // 扫描 app 私有 SO 的静态导出符号（Java_xxx），兜底 RegisterNatives 未捕获的情况
        scanStaticExports: true,
        // 解析真实类名（Java.perform + Java.cast）。注意：Android 10 上壳早期注册会
        // stale Local 崩溃（native abort，try/catch 救不了），默认关；Android 14/attach 模式可开
        resolveClassName: false,
    });

    var registered = 0;

    function matchesFilter(className, methodName) {
        if (CONFIG.filterClass.length > 0) {
            var hit = false;
            for (var i = 0; i < CONFIG.filterClass.length; i++) {
                if (className.indexOf(CONFIG.filterClass[i]) !== -1) { hit = true; break; }
            }
            if (!hit) return false;
        }
        if (CONFIG.filterMethod.length > 0) {
            var hit = false;
            for (var i = 0; i < CONFIG.filterMethod.length; i++) {
                if (methodName.indexOf(CONFIG.filterMethod[i]) !== -1) { hit = true; break; }
            }
            if (!hit) return false;
        }
        return true;
    }

    // JNI 签名翻译：(IILjava/lang/String;)V → (int, int, String) → void
    function parseJniSignature(sig) {
        var types = { "Z": "boolean", "B": "byte", "C": "char", "S": "short",
            "I": "int", "J": "long", "F": "float", "D": "double", "V": "void" };
        function parseOne(s, i) {
            var dims = 0;
            while (s[i] === '[') { dims++; i++; }
            var t;
            if (types[s[i]]) { t = types[s[i]]; i++; }
            else if (s[i] === 'L') {
                var end = s.indexOf(';', i);
                t = s.substring(i + 1, end).replace(/\//g, '.').replace("java.lang.", "");
                i = end + 1;
            } else { t = s[i] || "?"; i++; }
            for (var d = 0; d < dims; d++) t += "[]";
            return { type: t, next: i };
        }
        try {
            var params = [];
            var i = 1;
            while (i < sig.length && sig[i] !== ')') {
                var p = parseOne(sig, i);
                params.push(p.type);
                i = p.next;
            }
            var ret = parseOne(sig, i + 1);
            return "(" + params.join(", ") + ") → " + ret.type;
        } catch (e) { return sig; }
    }

    // 定位 RegisterNatives：符号优先，vtable 索引 215 兜底（JNI 规范固定）
    function findRegisterNatives() {
        var artModule = Process.findModuleByName("libart.so");
        if (artModule) {
            var addr = Module.findExportByName("libart.so",
                "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi");
            if (addr) return addr;
            var found = null;
            artModule.enumerateSymbols().forEach(function (sym) {
                if (!found &&
                    sym.name.indexOf("RegisterNatives") !== -1 &&
                    sym.name.indexOf("CheckJNI") === -1 &&
                    sym.name.indexOf("JNINativeMethod") !== -1) {
                    found = sym.address;
                }
            });
            if (found) return found;
        }
        // vtable 兜底（JNIEnv 第 215 个槽位 = RegisterNatives，JNI 规范固定）
        try {
            var env = Java.vm.getEnv();
            var vtable = Memory.readPointer(env.handle);
            return Memory.readPointer(vtable.add(215 * Process.pointerSize));
        } catch (e) {}
        return null;
    }

    function hookRegisterNatives() {
        var addr = findRegisterNatives();
        if (!addr) {
            U.fail("RegisterNatives symbol not found (check libart.so on this API level)");
            return;
        }

        U.ok("[SCANRN] RegisterNatives @ " + addr);
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    var jclass = args[1];
                    var methods = args[2];
                    var count = args[3].toInt32();

                    // 注意：RegisterNatives 是 ART 内部函数，回调里调用 Java API 有崩溃风险
                    // （Java.perform/Java.cast 可能重入 ART 或访问 stale Local）
                    // 默认纯 native 读取（稳定）；resolveClassName:true 时尝试解析类名
                    var className = "class@" + jclass;
                    if (CONFIG.resolveClassName) {
                        try {
                            Java.perform(function () {
                                className = Java.cast(jclass, Java.use("java.lang.Class")).getName();
                            });
                        } catch (e) {
                            className = "class@" + jclass;
                        }
                    }

                    for (var i = 0; i < count; i++) {
                        var m = methods.add(i * 3 * Process.pointerSize);
                        var namePtr = m.readPointer();
                        var sigPtr = m.add(Process.pointerSize).readPointer();
                        var fnPtr = m.add(Process.pointerSize * 2).readPointer();

                        var methodName = namePtr.readCString ? namePtr.readCString() : String(namePtr);
                        var signature = sigPtr.readCString ? sigPtr.readCString() : String(sigPtr);
                        if (!methodName) continue;

                        if (!matchesFilter(className, methodName)) continue;

                        var mod = Process.findModuleByAddress(fnPtr);
                        var modName = mod ? mod.name : "???";
                        var offset = mod ? fnPtr.sub(mod.base) : fnPtr;

                        if (CONFIG.onlyAppSo && mod && mod.path.indexOf("/data/app/") === -1) continue;

                        registered++;
                        U.ok("[SCANRN] " + className + "." + methodName + signature +
                            " (" + parseJniSignature(signature) + ")" +
                            " → " + modName + " + 0x" + offset.toString(16) +
                            (mod ? " (" + mod.path + ")" : ""));
                    }
                } catch (e) {}
            }
        });
    }

    global.ScanRegisterNatives = {
        getRegisteredCount: function () { return registered; },
    };

    // 扫描 app 私有 SO 的 Java_xxx 静态导出符号（JNI_OnLoad 静态注册，不经过 RegisterNatives）
    function scanStaticExports() {
        var found = 0;
        Process.enumerateModules().forEach(function (mod) {
            if (CONFIG.onlyAppSo && mod.path.indexOf("/data/app/") === -1) return;
            try {
                var exports = Module.enumerateExports(mod.name);
                for (var i = 0; i < exports.length; i++) {
                    var name = exports[i].name;
                    if (name.indexOf("Java_") !== 0) continue;
                    // Java_com_pkg_Class_method → com.pkg.Class.method（SWIG 用 _1 转义 _，还原为 .）
                    var parts = name.split("_");
                    if (parts.length < 4) continue;
                    var className = parts.slice(1, parts.length - 1).join(".").replace(/_1/g, "_");
                    var methodName = parts[parts.length - 1].replace(/_1/g, "_");
                    if (!matchesFilter(className, methodName)) continue;
                    if (CONFIG.methodKeywords.length > 0) {
                        var hit = false;
                        for (var k = 0; k < CONFIG.methodKeywords.length; k++) {
                            if (methodName.indexOf(CONFIG.methodKeywords[k]) !== -1) { hit = true; break; }
                        }
                        if (!hit) continue;
                    }
                    var offset = exports[i].address.sub(mod.base);
                    registered++;
                    found++;
                    U.ok("[SCANRN:STATIC] " + className + "." + methodName +
                        " → " + mod.name + " + 0x" + offset.toString(16) +
                        " (" + mod.path + ")");
                }
            } catch (e) {}
        });
        if (found > 0) {
            U.ok("[SCANRN] static export scan done: " + found + " native methods");
        } else {
            U.info("[SCANRN] no static Java_xxx exports found in app SO");
        }
    }

    U.info("scan_register_natives.js ready (filterClass=" + (CONFIG.filterClass.join(",") || "all") +
        " methodKeywords=" + (CONFIG.methodKeywords.join(",") || "all") + ")");
    console.log("");

    hookRegisterNatives();
    if (CONFIG.scanStaticExports) {
        // 延迟到壳完成 SO 加载后再扫静态导出
        setTimeout(scanStaticExports, 5000);
    }

})(this);