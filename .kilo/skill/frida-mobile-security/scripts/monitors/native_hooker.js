/**
 * native_hooker.js - Native SO 自动 Hook 器
 * 用途：监控 dlopen，在目标 .so 加载后自动枚举导出函数并按模式匹配 hook，
 *       自动打印函数参数/返回值/调用栈。适用于加密分析、协议分析、反调试分析
 *       等任何需要深入 Native 库内部的通用场景。
 * 覆盖层级：Native .so（应用自有库）
 * 加载方式：frida -U -f com.app -l utils.js -l native_hooker.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) {
        console.log("[-] native_hooker requires utils.js (load it first)");
        return;
    }

    console.log('[*] pre-flight: 目标疑似加固/自校验时，先做"不 hook 对照"实验；崩了即停手 → references/troubleshooting.md');

    var CONFIG = U.mergeConfig('native_hooker', {
        targetLibs: [],
        hookPatterns: [
            "encrypt", "decrypt", "crypt", "cipher",
            "aes", "rsa", "des", "3des", "sm4", "chacha",
            "hash", "md5", "sha", "hmac", "sha1", "sha256", "sha512",
            "base64", "b64", "xor",
            "encode", "decode", "pack", "unpack",
            "serialize", "protobuf", "flatbuf",
            "sign", "verify", "signature",
            "compress", "decompress", "gzip", "zlib",
        ],
        argMaxLen: 128,
        showArgs: true,
        showRetval: true,
        showBacktrace: false,
        backtraceDepth: 5,
        hookDelay: 0,
        hookDlsymResolved: false,
        _compiledLibPatterns: [],
        _compiledHookPatterns: [],
    });

    // ========== 工具函数 ==========
    function compilePatterns() {
        CONFIG._compiledHookPatterns = U.compilePatterns(CONFIG.hookPatterns);
        CONFIG._compiledLibPatterns = U.compilePatterns(CONFIG.targetLibs);
    }

    function matchesAnyPattern(str, patterns) {
        return U.matchesAnyPattern(str, patterns);
    }

    function shouldHookLib(path) {
        if (!path) return false;
        if (CONFIG._compiledLibPatterns.length === 0) {
            // 默认：只关注 app 自身的 so（/data/ 路径下），忽略系统库
            return path.indexOf("/data/") !== -1;
        }
        return matchesAnyPattern(path, CONFIG._compiledLibPatterns);
    }

    function getLibShortName(path) {
        if (!path) return "?";
        var parts = path.split("/");
        return parts[parts.length - 1];
    }

    function isPointerLike(val) {
        try {
            return val && !val.isNull() && val.compare(ptr(1)) > 0;
        } catch (e) {
            return false;
        }
    }

    function smartPrintArg(val, index) {
        if (!val || val.isNull()) {
            console.log("   arg[" + index + "] = null");
            return;
        }
        if (!isPointerLike(val)) {
            var intVal = 0;
            try { intVal = val.toInt32(); } catch (e) { }
            console.log("   arg[" + index + "] = " + val + " (int:" + intVal + "/0x" + intVal.toString(16) + ")");
            return;
        }
        // 尝试作为指针读取
        try {
            var testByte = val.readU8();
            // 尝试作为 C 字符串读取
            var cstr = U.safeReadCString(val, CONFIG.argMaxLen);
            if (cstr && cstr.length > 0) {
                var display = cstr;
                if (cstr.length > CONFIG.argMaxLen) display = cstr.substring(0, CONFIG.argMaxLen) + "...";
                console.log("   arg[" + index + "] ptr " + val + " -> str: \"" + display + "\"");
                return;
            }
        } catch (e) { /* not readable as string */ }
        // 默认 hexdump
        try {
            console.log("   arg[" + index + "] ptr " + val + ":");
            console.log(hexdump(val, { offset: 0, length: CONFIG.argMaxLen, header: true, ansi: false }));
        } catch (e) {
            console.log("   arg[" + index + "] ptr " + val + " (unreadable)");
        }
    }

    function smartPrintRetval(retval) {
        if (!retval || retval.isNull()) {
            console.log("   => ret: null");
            return;
        }
        var intVal = 0;
        try { intVal = retval.toInt32(); } catch (e) { }
        if (intVal !== 0 && Math.abs(intVal) < 0x10000) {
            console.log("   => ret: " + retval + " (int:" + intVal + "/0x" + intVal.toString(16) + ")");
            return;
        }
        try {
            console.log("   => ret ptr " + retval + ":");
            console.log(hexdump(retval, { offset: 0, length: CONFIG.argMaxLen, header: true, ansi: false }));
        } catch (e) {
            console.log("   => ret: " + retval);
        }
    }

    // ========== 核心：hook 单个导出函数 ==========
    function hookExportedFunction(libName, expName, expAddr) {
        var listener = Interceptor.attach(expAddr, {
            onEnter: function (args) {
                U.info("========== [native_hooker] " + libName + "!" + expName + " ==========");
                U.timeLog("called from thread " + Process.getCurrentThreadId());

                if (CONFIG.showArgs) {
                    for (var i = 0; i < 8; i++) {
                        if (args[i] === undefined) break;
                        smartPrintArg(args[i], i);
                    }
                }

                if (CONFIG.showBacktrace) {
                    U.logBacktrace(this.context, CONFIG.backtraceDepth);
                }
            },
            onLeave: function (retval) {
                if (CONFIG.showRetval) {
                    smartPrintRetval(retval);
                }
                U.info("========== [native_hooker] END  ==========");
            }
        });
        U.registerHook(listener);
        return listener;
    }

    // ========== 核心：枚举并 hook 目标库 ==========
    function enumerateAndHook(libPath, libBase) {
        var libName = getLibShortName(libPath);
        var exports;
        try {
            exports = Module.enumerateExports(libName);
        } catch (e) {
            U.fail("Failed to enumerate exports: " + libName + " - " + e.message);
            return 0;
        }

        if (exports.length === 0) {
            U.fail(libName + " has NO exports [STRIPPED] — use pattern scan or dlsym_tracer instead");
            return 0;
        }

        var hookedCount = 0;
        exports.forEach(function (exp) {
            if (exp.type !== 'function') return;
            if (matchesAnyPattern(exp.name, CONFIG._compiledHookPatterns)) {
                hookExportedFunction(libName, exp.name, exp.address);
                U.ok("hooked: " + libName + "!" + exp.name + " @ " + exp.address);
                hookedCount++;
            }
        });

        if (hookedCount > 0) {
            U.info(libName + ": hooked " + hookedCount + "/" + exports.length + " exports");
        }
        return hookedCount;
    }

    // ========== dlsym 动态解析 hook ==========
    function hookDlsymResolved() {
        var dlsymAddr = Module.findExportByName(null, "dlsym");
        if (!dlsymAddr) return;

        Interceptor.attach(dlsymAddr, {
            onEnter: function (args) {
                this.handle = args[0];
                this.name = U.safeReadCString(args[1]);
            },
            onLeave: function (retval) {
                if (!this.name || retval.isNull()) return;
                if (!matchesAnyPattern(this.name, CONFIG._compiledHookPatterns)) return;
                // 检查是否已经 hook 了该地址（避免重复 hook）
                if (hookedAddresses[retval.toString()]) return;
                hookedAddresses[retval.toString()] = true;

                var mod = Process.findModuleByAddress(retval);
                var modName = mod ? mod.name : "?";
                U.alert("dlsym resolved: " + this.name + " = " + retval + " (" + modName + ")");
                hookExportedFunction(modName, this.name + "(dlsym)", retval);
            }
        });
    }

    var hookedAddresses = {};

    // ========== dlopen 监控 ==========
    function hookDlopen() {
        var dlopenAddr = Module.findExportByName(null, "android_dlopen_ext");
        if (!dlopenAddr) {
            dlopenAddr = Module.findExportByName(null, "dlopen");
        }
        if (!dlopenAddr) {
            U.fail("dlopen not found, native_hooker disabled");
            return;
        }

        Interceptor.attach(dlopenAddr, {
            onEnter: function (args) {
                this.path = U.safeReadCString(args[0]);
                this.flags = args[1] ? args[1].toInt32() : 0;
            },
            onLeave: function (retval) {
                if (!this.path) return;
                if (!shouldHookLib(this.path)) return;
                if (retval.isNull()) {
                    U.fail("dlopen FAILED: " + this.path);
                    return;
                }
                U.info("dlopen OK: " + this.path + " base=" + retval);
                var libName = getLibShortName(this.path);

                if (CONFIG.hookDelay > 0) {
                    U.info("delaying hook " + CONFIG.hookDelay + "ms for " + libName);
                    var path = this.path;
                    setTimeout(function () {
                        enumerateAndHook(path, retval);
                    }, CONFIG.hookDelay);
                } else {
                    enumerateAndHook(this.path, retval);
                }
            }
        });
    }

    // ========== 已加载模块扫描（spawn 模式下 .so 可能已在 Frida 注入前加载） ==========
    function scanLoadedModules() {
        U.info("Scanning already-loaded modules...");
        var totalHooked = 0;
        Process.enumerateModules().forEach(function (mod) {
            if (!shouldHookLib(mod.path)) return;
            var count = enumerateAndHook(mod.path, mod.base);
            totalHooked += count;
        });
        if (totalHooked > 0) {
            U.ok("Pre-loaded scan: hooked " + totalHooked + " functions across already-loaded modules");
        }
    }

    // ========== 导出 API ==========
    global.NativeHooker = {
        /**
         * 手动 hook 指定库（库名如 "libencrypt.so"）
         */
        hookLibrary: function (libName) {
            var mod = Process.findModuleByName(libName);
            if (!mod) {
                U.fail("Library not loaded: " + libName);
                return 0;
            }
            return enumerateAndHook(mod.path, mod.base);
        },

        /**
         * 添加函数名匹配规则
         */
        addPattern: function (pattern) {
            CONFIG._compiledHookPatterns.push(new RegExp(pattern, 'i'));
            U.info("added hook pattern: " + pattern);
        },

        /**
         * 返回已 hook 函数数量
         */
        getHookedCount: function () {
            return global.Utils ? global.Utils.hooks.length : 0;
        },
    };

    // ========== 启动 ==========
    (function init() {
        compilePatterns();

        U.info("native_hooker.js initializing...");
        U.info("targetLibs: " + (CONFIG._compiledLibPatterns.length > 0
            ? CONFIG.targetLibs.join(", ") : "<auto: /data/ so files>"));
        U.info("hookPatterns: " + CONFIG.hookPatterns.length + " patterns");
        U.info("dlsymResolved: " + CONFIG.hookDlsymResolved + " delay: " + CONFIG.hookDelay + "ms");

        hookDlopen();
        if (CONFIG.hookDlsymResolved) hookDlsymResolved();
        scanLoadedModules();

        U.info("native_hooker.js ready");
        console.log("");
    })();

})(this);
