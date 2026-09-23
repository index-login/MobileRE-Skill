/**
 * utils.js - 通用工具模块
 * 用途：提供所有监控模块复用的工具函数
 * 加载方式：frida -U -f com.app -l utils.js -l file_monitor.js -l thread_monitor.js
 */
(function (global) {
    'use strict';

    var Utils = {};

    // --------------- 日志输出 ---------------
    var TAG_PREFIX = "[+]";
    var TAG_FAIL = "[-]";
    var TAG_ALERT = "[!]";
    var TAG_INFO = "[*]";

    Utils.info = function (msg) { console.log(TAG_INFO, msg); };
    Utils.ok = function (msg) { console.log(TAG_PREFIX, msg); };
    Utils.fail = function (msg) { console.log(TAG_FAIL, msg); };
    Utils.alert = function (msg) { console.log(TAG_ALERT, msg); };

    // --------------- CONFIG 覆盖机制（所有模块共用） ---------------

    /**
     * 合并 CONFIG_OVERRIDE 到模块默认配置。
     * 用法: var CONFIG = Utils.mergeConfig('module_name', { key: 'default', ... });
     */
    Utils.mergeConfig = function (moduleName, defaults) {
        var cfg = {};
        for (var k in defaults) {
            if (defaults.hasOwnProperty(k)) cfg[k] = defaults[k];
        }
        if (typeof CONFIG_OVERRIDE !== 'undefined' && CONFIG_OVERRIDE[moduleName]) {
            var over = CONFIG_OVERRIDE[moduleName];
            for (var k in over) {
                if (over.hasOwnProperty(k)) cfg[k] = over[k];
            }
        }
        return cfg;
    };

    // --------------- 安全 Hook ---------------
    Utils.safeHook = function (moduleName, funcName, callbacks) {
        try {
            var addr = Module.findExportByName(moduleName, funcName);
            if (!addr) {
                Utils.fail("not found: " + (moduleName || "<any>") + "!" + funcName);
                return null;
            }
            var listener = Interceptor.attach(addr, callbacks);
            Utils.ok("hooked: " + funcName + " @ " + addr);
            return listener;
        } catch (e) {
            Utils.fail("hook failed: " + funcName + " - " + e.message);
            return null;
        }
    };

    // --------------- 调用栈 ---------------
    Utils.logBacktrace = function (ctx, depth) {
        depth = depth || 15;
        try {
            var trace = Thread.backtrace(ctx, Backtracer.ACCURATE);
            console.log(TAG_INFO, "Call stack (" + trace.length + " frames):");
            for (var i = 0; i < Math.min(trace.length, depth); i++) {
                var sym = DebugSymbol.fromAddress(trace[i]);
                var mod = Process.findModuleByAddress(trace[i]);
                var modName = mod ? mod.name : "???";
                var offset = mod ? trace[i].sub(mod.base) : trace[i];
                console.log("  [" + i + "] " + modName + " + 0x" + offset.toString(16) + " | " + sym);
            }
        } catch (e) {
            console.log(TAG_FAIL, "backtrace failed: " + e.message);
        }
    };

    /**
     * 格式化单帧调用栈为 so+offset 格式。
     * 输出如 "libmsaoaidsec.so + 0x1CEF8" 或 "libmsaoaidsec.so + 0x1CEF8 | sub_1CEF8"
     */
    Utils.formatFrameWithOffset = function (addr) {
        try {
            var mod = Process.findModuleByAddress(addr);
            if (mod) {
                var offset = addr.sub(mod.base);
                var sym = DebugSymbol.fromAddress(addr);
                var symName = sym.toString();
                if (symName.indexOf("0x") === 0 && symName.length > 10) {
                    symName = "";
                } else {
                    symName = " | " + symName;
                }
                return mod.name + " + 0x" + offset.toString(16) + symName;
            }
        } catch (e) {}
        return addr.toString();
    };

    // --------------- 调用者模块解析 ---------------

    /**
     * 通过返回地址解析调用者所在的模块名、基址、偏移。
     * 返回 { name, base, offset, address } 或 null。
     */
    Utils.resolveCallerMod = function (returnAddr) {
        if (!returnAddr || returnAddr.isNull()) return null;
        try {
            var mod = Process.findModuleByAddress(returnAddr);
            if (!mod) return null;
            return {
                name: mod.name,
                base: mod.base,
                offset: returnAddr.sub(mod.base),
                address: returnAddr,
            };
        } catch (e) { return null; }
    };

    /**
     * 打印带 so+offset 标注的完整调用栈。
     * 帧 [0] 标 [caller]，帧 [1] 标 [detect]。
     */
    Utils.logBacktraceWithOffsets = function (ctx, depth) {
        depth = depth || 12;
        try {
            var trace = Thread.backtrace(ctx, Backtracer.ACCURATE);
            var frames = Math.min(trace.length, depth);
            Utils.alert("Call stack (" + trace.length + " frames, showing " + frames + "):");
            for (var i = 0; i < frames; i++) {
                var frameInfo = Utils.formatFrameWithOffset(trace[i]);
                var marker = (i === 0) ? " [caller]" : (i === 1 ? " [detect]" : "");
                console.log("  [" + i + "]" + marker + " " + frameInfo);
            }
            if (trace.length > depth) {
                console.log("  ... (" + (trace.length - depth) + " more frames omitted)");
            }
        } catch (e) {
            Utils.fail("backtrace failed: " + e.message);
        }
    };

    // --------------- 正则匹配工具 ---------------

    /**
     * 将字符串数组编译为正则数组（大小写不敏感）。
     */
    Utils.compilePatterns = function (strings) {
        return strings.map(function (p) {
            return new RegExp(p, 'i');
        });
    };

    /**
     * 检查 str 是否匹配 patterns 数组中的任一正则。
     */
    Utils.matchesAnyPattern = function (str, patterns) {
        if (!str) return false;
        for (var i = 0; i < patterns.length; i++) {
            if (patterns[i].test(str)) return true;
        }
        return false;
    };

    // --------------- 路径过滤 ---------------
    var BORING_PREFIXES = [
        "/system/", "/vendor/", "/apex/", "/dev/", "/proc/self/",
        "/sys/", "/data/dalvik-cache/", "/data/resource-cache/",
    ];
    var BORING_EXTS = [".so", ".dex", ".odex", ".vdex", ".art", ".oat", ".jar", ".apk"];
    var BORING_FILES = ["/dev/urandom", "/dev/__properties__", "property_service",
                        "/proc/stat", "/proc/self/status", "/proc/self/auxv",
                        "schedtune", "cpuctl", "cgroup"];

    Utils.isInteresting = function (path) {
        if (!path) return false;
        for (var i = 0; i < BORING_FILES.length; i++) {
            if (path.indexOf(BORING_FILES[i]) !== -1) return false;
        }
        if (path.startsWith("/data/app/") || path.startsWith("/system/") || path.startsWith("/apex/")) {
            for (var j = 0; j < BORING_EXTS.length; j++) {
                if (path.endsWith(BORING_EXTS[j])) return false;
            }
        }
        return true;
    };

    Utils.createPathFilter = function (interestingPaths, boringPaths) {
        return function (path) {
            if (!path) return false;
            if (boringPaths) {
                for (var i = 0; i < boringPaths.length; i++) {
                    if (path.indexOf(boringPaths[i]) !== -1) return false;
                }
            }
            if (interestingPaths) {
                for (var j = 0; j < interestingPaths.length; j++) {
                    if (path.indexOf(interestingPaths[j]) !== -1) return true;
                }
                return false;
            }
            return Utils.isInteresting(path);
        };
    };

    // --------------- 内存工具 ---------------
    Utils.isReadable = function (ptr, size) {
        try {
            ptr.readByteArray(size || 1);
            return true;
        } catch (e) {
            return false;
        }
    };

    /**
     * 读取 [base, base+size) 的全部内存，自动处理权限。
     * 优先直接读取（DEX 区域通常 rw- 可读），失败时对所在区域单独 Memory.protect 加 r 后重试。
     * 不依赖 Process.enumerateRanges 全量遍历（frida-server 版本不匹配时该 API 会抛异常）。
     * 返回 ArrayBuffer，失败返回 null。
     */
    Utils.readDexMemory = function (base, size) {
        if (!base || base.isNull() || size <= 0 || size > 0x40000000) return null;
        try {
            return base.readByteArray(size);
        } catch (e) {}
        try {
            var rg = Process.findRangeByAddress(base);
            if (!rg) return null;
            if (rg.protection.indexOf("r") !== 0) {
                Memory.protect(rg.base, rg.size, "r" + rg.protection.substr(1, 2));
            }
            return base.readByteArray(size);
        } catch (e) {
            return null;
        }
    };

    Utils.safeReadCString = function (ptr, maxLen) {
        if (!ptr || ptr.isNull()) return null;
        try {
            if (!Utils.isReadable(ptr, 1)) return null;
            return ptr.readCString(maxLen || 512) || null;
        } catch (e) {
            return null;
        }
    };

    // --------------- 模块工具 ---------------
    Utils.getModuleBase = function (name) {
        try {
            var m = Process.findModuleByName(name);
            return m ? m.base : null;
        } catch (e) {
            return null;
        }
    };

    Utils.findSymbolInModule = function (moduleName, pattern) {
        try {
            var exports = Module.enumerateExports(moduleName);
            for (var i = 0; i < exports.length; i++) {
                if (exports[i].name.indexOf(pattern) !== -1) {
                    return exports[i].address;
                }
            }
        } catch (e) { }
        return null;
    };

    /**
     * 等待模块加载后回调。spawn 早期目标 so 尚未 dlopen，
     * 直接 findExportByName 会静默返回 null。
     * 用法: Utils.waitForModule("libfoo.so", function (mod) { hook(mod); }, 10000);
     */
    Utils.waitForModule = function (name, callback, timeoutMs) {
        timeoutMs = timeoutMs || 10000;
        var waited = 0;
        var iv = setInterval(function () {
            var m = Process.findModuleByName(name);
            if (m) {
                clearInterval(iv);
                callback(m);
                return;
            }
            waited += 100;
            if (waited >= timeoutMs) {
                clearInterval(iv);
                Utils.fail("waitForModule timeout: " + name);
            }
        }, 100);
    };

    // --------------- 时间工具 ---------------
    Utils.timestamp = function () {
        var d = new Date();
        var h = d.getHours().toString().padStart(2, '0');
        var m = d.getMinutes().toString().padStart(2, '0');
        var s = d.getSeconds().toString().padStart(2, '0');
        var ms = d.getMilliseconds().toString().padStart(3, '0');
        return h + ":" + m + ":" + s + "." + ms;
    };

    Utils.timeLog = function (msg) {
        console.log("[" + Utils.timestamp() + "]", msg);
    };

    /**
     * 获取 app 私有可写目录（/data/data/<包名>/files/dump/）。
     * 脚本在 app 进程内执行，/data/local/tmp/ 属 root 无写权限，必须用 app 可写目录。
     * 返回路径字符串，失败返回 null。
     */
    Utils.getDumpDir = function () {
        try {
            if (!Java.available) return null;
            var dataDir = null;
            Java.perform(function () {
                var at = Java.use("android.app.ActivityThread");
                var app = at.currentApplication();
                if (app) {
                    dataDir = app.getApplicationContext().getFilesDir().getAbsolutePath();
                }
            });
            if (!dataDir) return null;
            return dataDir + "/dump/";
        } catch (e) {
            return null;
        }
    };

    /**
     * 确保输出目录存在（Frida File API 无内置 mkdir，用 libc mkdir 递归创建）。
     * 返回 true 成功 / false 失败。
     */
    Utils.ensureDir = function (path) {
        if (!path) return false;
        try {
            var mkdir = Module.findExportByName("libc.so", "mkdir");
            if (!mkdir) return false;
            var mkdirFn = new NativeFunction(mkdir, 'int', ['pointer', 'int']);
            var parts = path.split("/");
            var cur = "";
            for (var i = 0; i < parts.length; i++) {
                if (parts[i] === "") continue;
                cur += "/" + parts[i];
                if (cur === "/data") continue;
                try {
                    mkdirFn(Memory.allocUtf8String(cur), 0x1ED); // 0755，已存在则忽略错误
                } catch (e) {}
            }
            return true;
        } catch (e) {
            return false;
        }
    };

    // --------------- 编码工具（Java 层加解密常用） ---------------
    var BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    Utils.bytesToHex = function (arrBytes) {
        var str = "";
        for (var i = 0; i < arrBytes.length; i++) {
            var tmp;
            var num = arrBytes[i];
            if (num < 0) {
                tmp = (255 + num + 1).toString(16);
            } else {
                tmp = num.toString(16);
            }
            if (tmp.length == 1) tmp = "0" + tmp;
            str += tmp;
        }
        return str;
    };

    Utils.bytesToStr = function (arrBytes) {
        return Utils.hexToStr(Utils.bytesToHex(arrBytes));
    };

    Utils.bytesToBase64 = function (arrayBuffer) {
        var base64 = '';
        var bytes = new Uint8Array(arrayBuffer);
        var byteLength = bytes.byteLength;
        var byteRemainder = byteLength % 3;
        var mainLength = byteLength - byteRemainder;
        var a, b, c, d, chunk;

        for (var i = 0; i < mainLength; i = i + 3) {
            chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
            a = (chunk & 16515072) >> 18;
            b = (chunk & 258048)   >> 12;
            c = (chunk & 4032)     >> 6;
            d = chunk & 63;
            base64 += BASE64_CHARS[a] + BASE64_CHARS[b] + BASE64_CHARS[c] + BASE64_CHARS[d];
        }
        if (byteRemainder == 1) {
            chunk = bytes[mainLength];
            a = (chunk & 252) >> 2;
            b = (chunk & 3)   << 4;
            base64 += BASE64_CHARS[a] + BASE64_CHARS[b] + '==';
        } else if (byteRemainder == 2) {
            chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1];
            a = (chunk & 64512) >> 10;
            b = (chunk & 1008)  >> 4;
            c = (chunk & 15)    << 2;
            base64 += BASE64_CHARS[a] + BASE64_CHARS[b] + BASE64_CHARS[c] + '=';
        }
        return base64;
    };

    Utils.strToHex = function (str) {
        return str.split("").map(function (c) {
            return ("0" + c.charCodeAt(0).toString(16)).slice(-2);
        }).join("");
    };

    Utils.hexToStr = function (hexStr) {
        var hex = hexStr.toString();
        var str = '';
        for (var i = 0; i < hex.length; i += 2)
            str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
        return str;
    };

    Utils.utf8ToStr = function (utf8Bytes) {
        var str = "";
        for (var pos = 0; pos < utf8Bytes.length;) {
            var flag = utf8Bytes[pos];
            var unicode = 0;
            if ((flag >>> 7) === 0) {
                str += String.fromCharCode(utf8Bytes[pos]);
                pos += 1;
            } else if ((flag & 0xE0) === 0xC0) {
                unicode = (utf8Bytes[pos] & 0x1F) << 6;
                unicode |= (utf8Bytes[pos + 1] & 0x3F);
                str += String.fromCharCode(unicode);
                pos += 2;
            } else if ((flag & 0xF0) === 0xE0) {
                unicode = (utf8Bytes[pos] & 0xF) << 12;
                unicode |= (utf8Bytes[pos + 1] & 0x3F) << 6;
                unicode |= (utf8Bytes[pos + 2] & 0x3F);
                str += String.fromCharCode(unicode);
                pos += 3;
            } else if ((flag & 0xF8) === 0xF0) {
                unicode = (utf8Bytes[pos] & 0x7) << 18;
                unicode |= (utf8Bytes[pos + 1] & 0x3F) << 12;
                unicode |= (utf8Bytes[pos + 2] & 0x3F) << 6;
                unicode |= (utf8Bytes[pos + 3] & 0x3F);
                str += String.fromCharCode(unicode);
                pos += 4;
            } else {
                str += String.fromCharCode(utf8Bytes[pos]);
                pos += 1;
            }
        }
        return str;
    };

    Utils.javaStack = function () {
        if (!Java.available) {
            Utils.info("Java stack not available");
            return;
        }
        Java.perform(function () {
            var stack = Java.use("android.util.Log").getStackTraceString(
                Java.use("java.lang.Exception").$new()
            );
            console.log(stack);
        });
    };

    // --------------- 数据发送 ---------------
    Utils.sendJson = function (tag, data) {
        var obj = { tag: tag };
        for (var k in data) {
            if (data.hasOwnProperty(k)) obj[k] = data[k];
        }
        send(obj);
    };

    // --------------- Hexdump 包装 ---------------
    Utils.hexdumpSafe = function (ptr, length) {
        if (!ptr || ptr.isNull()) return "(null)";
        try {
            return hexdump(ptr, { offset: 0, length: length || 128, header: true, ansi: false });
        } catch (e) {
            return "(hexdump failed: " + e.message + ")";
        }
    };

    // --------------- 清理 ---------------
    Utils.hooks = [];
    Utils.registerHook = function (listener) {
        if (listener) Utils.hooks.push(listener);
        return listener;
    };
    Utils.cleanup = function () {
        Utils.hooks.forEach(function (h) {
            try { h.detach(); } catch (e) { }
        });
        Utils.hooks = [];
        Utils.info("all hooks detached");
    };

    // 导出
    global.Utils = Utils;
    console.log("[*] utils.js loaded");
})(this);
