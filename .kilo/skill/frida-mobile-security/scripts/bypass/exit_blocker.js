/**
 * exit_blocker.js - 强制退出阻断（分析 Phase 4：真正阻止进程退出）
 * 用途：用 Interceptor.replace 替换退出函数，防止 Frida 检测杀死进程
 *
 * 关键设计：
 *   Interceptor.replace 用 NativeCallback 替换原函数实现，原函数不会被调用 —— 真正阻断
 *   对比 Interceptor.attach → 只能观察，无法阻止原函数执行
 *
 * 覆盖层级：
 *   libc: exit_group / _exit / exit / abort / kill / tgkill
 *   syscall: 拦截 exit/exit_group/tgkill 系统调用
 * 加载方式：frida -U -f com.app -l utils.js -l exit_blocker.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) { console.log("[-] exit_blocker requires utils.js"); return; }

    var CONFIG = U.mergeConfig('exit_blocker', {
        blockLibc: true,
        blockSyscall: true,
        showBacktrace: true,
        backtraceDepth: 12,
        allowTids: [],
    });

    var BLOCK_STATS = {};

    function toInt(v) {
        return (typeof v === 'number') ? v : v.toInt32();
    }

    function shouldAllow() {
        var tid = Process.getCurrentThreadId();
        for (var i = 0; i < CONFIG.allowTids.length; i++) {
            if (CONFIG.allowTids[i] === tid) return true;
        }
        return false;
    }

    function logBlock(label, detail) {
        if (shouldAllow()) return;
        BLOCK_STATS[label] = (BLOCK_STATS[label] || 0) + 1;
        U.alert("BLOCKED: " + label + " " + (detail || "") + " (count=" + BLOCK_STATS[label] + ")");
        if (CONFIG.showBacktrace) {
            U.logBacktrace((this && this.context) || null, CONFIG.backtraceDepth);
        }
    }

    // ========== Interceptor.replace 真正阻断 ==========

    function replaceVoidFunction(moduleName, funcName, label) {
        try {
            var addr = Module.findExportByName(moduleName, funcName);
            if (!addr) { U.fail(label + " not found: " + funcName); return; }

            Interceptor.replace(addr, new NativeCallback(function (status) {
                logBlock(label, "status=" + (status !== undefined ? status : "?"));
            }, 'void', ['int']));
            U.ok(label + " REPLACED: " + funcName);
        } catch (e) {
            // replace 失败时回退到 attach（仍有原始调用，但会记录）
            U.fail(label + " replace failed: " + e.message + " — falling back to attach (log-only)");
            try {
                U.registerHook(Interceptor.attach(addr, {
                    onEnter: function (args) {
                        logBlock(label + " [attach]", "status=" + args[0]);
                    }
                }));
            } catch (e2) {
                U.fail(label + " attach also failed: " + e2.message);
            }
        }
    }

    function replaceAbort() {
        try {
            var addr = Module.findExportByName("libc.so", "abort");
            if (!addr) { U.fail("abort not found"); return; }
            Interceptor.replace(addr, new NativeCallback(function () {
                logBlock("abort");
            }, 'void', []));
            U.ok("abort REPLACED");
        } catch (e) {
            U.fail("abort replace failed: " + e.message);
            try {
                U.registerHook(Interceptor.attach(Module.findExportByName("libc.so", "abort"), {
                    onEnter: function () { logBlock("abort [attach]"); }
                }));
            } catch (e2) { }
        }
    }

    function replaceKill(moduleName, funcName, label) {
        try {
            var addr = Module.findExportByName(moduleName, funcName);
            if (!addr) return;
            Interceptor.replace(addr, new NativeCallback(function (pid, sig) {
                if (toInt(pid) === Process.id && [1, 3, 4, 6, 9, 11, 15].indexOf(toInt(sig)) !== -1) {
                    logBlock(label, "pid=" + pid + " sig=" + sig);
                }
                return 0;
            }, 'int', ['int', 'int']));
            U.ok(label + " REPLACED: " + funcName);
        } catch (e) {
            U.fail(label + " replace failed: " + e.message);
        }
    }

    function replaceTgkill() {
        try {
            var addr = Module.findExportByName("libc.so", "tgkill");
            if (!addr) return;
            Interceptor.replace(addr, new NativeCallback(function (tgid, tid, sig) {
                if (toInt(tgid) === Process.id && [1, 3, 4, 6, 9, 11, 15].indexOf(toInt(sig)) !== -1) {
                    logBlock("tgkill", "tgid=" + tgid + " tid=" + tid + " sig=" + sig);
                }
                return 0;
            }, 'int', ['int', 'int', 'int']));
            U.ok("tgkill REPLACED: tgkill");
        } catch (e) { U.fail("tgkill replace failed: " + e.message); }
    }

    // ========== libc 层 ==========
    function blockLibc() {
        replaceVoidFunction("libc.so", "exit_group", "exit_group");
        replaceVoidFunction("libc.so", "_exit", "_exit");
        replaceVoidFunction("libc.so", "exit", "exit");
        replaceVoidFunction("libc.so", "_Exit", "_Exit");
        replaceVoidFunction("libc.so", "quick_exit", "quick_exit");
        replaceAbort();
        replaceKill("libc.so", "kill", "kill");
        replaceTgkill();

        // raise
        try {
            var raiseAddr = Module.findExportByName("libc.so", "raise");
            if (raiseAddr) {
                Interceptor.replace(raiseAddr, new NativeCallback(function (sig) {
                    if ([6, 9, 15].indexOf(toInt(sig)) !== -1) {
                        logBlock("raise", "sig=" + sig);
                    }
                    return 0;
                }, 'int', ['int']));
                U.ok("raise REPLACED");
            }
        } catch (e) { U.fail("raise replace failed: " + e.message); }
    }

    // ========== syscall 层 (attach-only, no replace to avoid conflicts) ==========
    function blockSyscall() {
        var NR_EXIT_GROUP = Process.pointerSize === 8 ? 94 : 248;
        var NR_EXIT       = Process.pointerSize === 8 ? 93 : 1;
        var NR_TGKILL     = Process.pointerSize === 8 ? 131 : 268;
        var NR_KILL       = Process.pointerSize === 8 ? 129 : 37;

        U.registerHook(U.safeHook(null, "syscall", {
            onEnter: function (args) {
                var nr = args[0].toInt32();
                if (nr === NR_EXIT_GROUP) {
                    logBlock.call(this, "syscall(exit_group)", "status=" + args[1]);
                } else if (nr === NR_EXIT) {
                    logBlock.call(this, "syscall(exit)", "status=" + args[1]);
                } else if (nr === NR_TGKILL) {
                    var sig = args[3].toInt32();
                    if ([6, 9, 11].indexOf(sig) !== -1) {
                        logBlock.call(this, "syscall(tgkill)", "sig=" + sig);
                    }
                } else if (nr === NR_KILL) {
                    var pid = args[1].toInt32();
                    var sig2 = args[2].toInt32();
                    if (pid === Process.id && [6, 9, 15].indexOf(sig2) !== -1) {
                        logBlock.call(this, "syscall(kill)", "sig=" + sig2);
                    }
                }
            }
        }));
    }

    // ========== 启动 ==========
    (function init() {
        U.info("exit_blocker.js initializing (using Interceptor.replace)...");
        if (CONFIG.blockLibc) blockLibc();
        if (CONFIG.blockSyscall) blockSyscall();
        U.info("exit_blocker.js ready — exit functions REPLACED with no-ops");
        console.log("");
    })();

})(this);
