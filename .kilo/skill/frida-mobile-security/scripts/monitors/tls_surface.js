/**
 * tls_surface.js - 定位 TLS 实现（先判"证书校验在哪个 so"，再决定 hook 策略）
 * 用途：一个 App 里可能同时有三个 TLS：系统 libssl、某 native 核心自带的 OpenSSL/BoringSSL、
 *       Flutter 引擎内置的 BoringSSL。符号、hook 点、绕过方式各不相同，先看清再动手。
 * 加载：frida -U -f <pkg> -l scripts/core/utils.js -l scripts/monitors/tls_surface.js
 * 配置：-e 'var CONFIG_OVERRIDE={tls_surface:{minExports:3,quiet:false}}'
 * 输出：每个模块的 SSL_/X509_/EVP_ 导出数量 + 样例；无导出但含 OpenSSL 字符串的模块单独标注
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) { console.log("[-] tls_surface requires utils.js (load it first)"); return; }

    var CONFIG = U.mergeConfig('tls_surface', {
        quiet: false,
        minExports: 3,
        showSamples: 4,
        includePatterns: /^(SSL_|X509_|EVP_|BIO_|ERR_|CRYPTO_|OPENSSL_)/,
        stringHints: ['OpenSSL', 'BoringSSL', 'ssl_crypto_x509_session_verify_cert_chain']
    });

    function log(msg) { if (!CONFIG.quiet) console.log('[tls_surface] ' + msg); }

    function scan() {
        var rows = [];
        Process.enumerateModules().forEach(function (m) {
            var hits = [];
            try {
                m.enumerateExports().forEach(function (e) {
                    if (CONFIG.includePatterns.test(e.name)) hits.push(e.name);
                });
            } catch (e) {
                /* 某些模块无导出表 */
            }

            var strings = [];
            try {
                var ranges = Process.findRangeByAddress(m.base) ? [[m.base, m.size]] : [];
                for (var i = 0; i < ranges.length; i++) {
                    var r = ranges[i];
                    CONFIG.stringHints.forEach(function (hint) {
                        var found = Memory.scanSync(r[0], Math.min(r[1], 4 * 1024 * 1024), hint.toString().split('').map(function (c) {
                            return ('0' + c.charCodeAt(0).toString(16)).slice(-2);
                        }).join(' '));
                        if (found.length > 0) strings.push(hint);
                    });
                }
            } catch (e) {
                /* 扫描失败忽略 */
            }

            if (hits.length >= CONFIG.minExports || strings.length > 0) {
                rows.push({ name: m.name, base: m.base, size: m.size, count: hits.length, hits: hits, strings: strings });
            }
        });

        rows.sort(function (a, b) { return b.count - a.count; });
        if (rows.length === 0) {
            log('未发现 TLS 符号：可能全静态链接且已剥符号 → 改按字符串/行为定位');
            return;
        }
        rows.forEach(function (r) {
            var tag = r.count > 0 ? ('exports=' + r.count) : 'exports=0';
            var sample = r.hits.slice(0, CONFIG.showSamples).join(',');
            log(r.name + ' ' + tag + (r.strings.length ? ' strings=' + r.strings.join('/') : '') +
                (sample ? ' e.g. ' + sample : '') + ' @' + r.base + ' size=' + r.size);
        });
        log('判断：exports 多且含 SSL_CTX_set_verify/X509_verify_cert → 直接按名 hook；' +
            '仅 strings 命中 → 需按版本定位（见 cross-platform.md › Flutter / native-analysis.md）');
    }

    // 等目标库加载完（Flutter / 自研核心常晚于进程启动）
    var waited = 0;
    var timer = setInterval(function () {
        waited++;
        if (waited >= 30) {
            clearInterval(timer);
            scan();
        }
    }, 200);
})(this);
