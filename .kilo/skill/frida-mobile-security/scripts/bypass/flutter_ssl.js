/**
 * flutter_ssl.js - Flutter/Dart 证书校验绕过（libflutter.so 内 BoringSSL，native 层）
 * 用途：Flutter 把证书链校验编进 libflutter.so，ssl_unpinning.js（Java 层）对它无效
 * 目标：ssl_crypto_x509_session_verify_cert_chain —— 校验通过返回 1（Dart 分支返回 int/bool）
 * 加载：frida -U -f <pkg> -l scripts/core/utils.js -l scripts/bypass/flutter_ssl.js
 * 配置：-e 'var CONFIG_OVERRIDE={flutter_ssl:{patterns:["ff 03 05 d1 ..."], offset:0x3b15a4}}'
 *       probe:[0x3b15a4,0x3b1558] 只观测不修改，用于在未知版本上认出目标函数
 * 注意：函数字节签名随引擎版本变化（实测同一 APK 的 9.5MB libflutter.so 上公开模式 0 命中），
 *       未命中时用 probe + 抓一次握手确认，再固化 offset/pattern
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) { console.log("[-] flutter_ssl requires utils.js (load it first)"); return; }

    var CONFIG = U.mergeConfig('flutter_ssl', {
        quiet: false,
        moduleName: 'libflutter.so',
        patterns: [
            // Horangi 公开模式（Flutter 3.x 早期引擎；与版本强绑定）
            'ff 03 05 d1 fd 7b 0f a9 bc de 05 94 08 0a 80 52 48'
        ],
        offset: 0,          // 模块内偏移（相对 libflutter.so 基址），>0 时优先使用
        probe: [],          // 只 hook 并打印 args/retval，不改返回值
        forceReturn: 1,     // 校验成功值：int/bool 分支均为 1
        maxHits: 4
    });

    function log(msg) { if (!CONFIG.quiet) console.log('[flutter_ssl] ' + msg); }

    function findModule() {
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            if (mods[i].name === CONFIG.moduleName) return mods[i];
        }
        return null;
    }

    function attachForce(addr, label) {
        try {
            Interceptor.attach(addr, {
                onLeave: function (retval) {
                    var before = retval.toInt32();
                    retval.replace(CONFIG.forceReturn);
                    log(label + ' ret ' + before + ' -> ' + CONFIG.forceReturn);
                }
            });
            log('hooked ' + label + ' @ ' + addr);
            return true;
        } catch (e) {
            log('hook failed ' + label + ': ' + e.message);
            return false;
        }
    }

    function attachProbe(addr, label) {
        try {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    log('[probe] ' + label + ' enter x0=' + args[0] + ' x1=' + args[1] + ' x2=' + args[2]);
                },
                onLeave: function (retval) {
                    log('[probe] ' + label + ' leave ret=' + retval.toInt32());
                }
            });
            log('probing ' + label + ' @ ' + addr);
            return true;
        } catch (e) {
            log('probe failed ' + label + ': ' + e.message);
            return false;
        }
    }

    function run() {
        var mod = findModule();
        if (mod === null) {
            log('module not found: ' + CONFIG.moduleName + '（Flutter 可能未加载或库名被改）');
            return;
        }
        log('base=' + mod.base + ' size=' + mod.size + ' name=' + mod.name);

        if (CONFIG.probe.length > 0) {
            for (var i = 0; i < CONFIG.probe.length; i++) {
                attachProbe(mod.base.add(CONFIG.probe[i]), 'off=0x' + CONFIG.probe[i].toString(16));
            }
        }

        if (CONFIG.offset > 0) {
            attachForce(mod.base.add(CONFIG.offset), 'off=0x' + CONFIG.offset.toString(16));
        }

        var hooked = 0;
        for (var p = 0; p < CONFIG.patterns.length; p++) {
            var pattern = CONFIG.patterns[p];
            if (!pattern) continue;
            var hits = Memory.scanSync(mod.base, mod.size, pattern);
            if (hits.length === 0) {
                log('pattern #' + p + ' no match');
                continue;
            }
            log('pattern #' + p + ' -> ' + hits.length + ' hit(s)');
            for (var h = 0; h < hits.length && h < CONFIG.maxHits; h++) {
                if (attachForce(hits[h].address, 'pat' + p + ':' + hits[h].address)) hooked++;
            }
        }

        if (hooked === 0 && CONFIG.offset === 0 && CONFIG.probe.length === 0) {
            log('未命中。定位顺序：');
            log('  1) so.py strings libflutter.so --grep ssl_x509.cc 取 xref（注意 xref 常落在 .cold 小函数上，不能当目标）');
            log('  2) 用 .eh_frame FDE 表恢复真实函数边界（冷块只有几十字节）');
            log('  3) 在 ssl 函数簇里找 3 参、循环处理证书栈、结尾 bl 共享 epilogue 返回 w0 的那个');
            log('  4) 先 probe 该地址，抓一次握手确认命中，再设 offset/patterns');
        }
    }

    // Flutter 引擎可能晚于脚本加载
    var waited = 0;
    var timer = setInterval(function () {
        if (findModule() !== null || waited >= 100) {
            clearInterval(timer);
            run();
        }
        waited++;
    }, 100);
})(this);
