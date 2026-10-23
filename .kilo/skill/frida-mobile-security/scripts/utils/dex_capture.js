/**
 * dex_capture.js - 早期 DEX 捕获（mmap 记录 + 严格校验 + 异步落盘）
 *
 * 设计约束：
 *   - mmap 回调里只做"读 4 个字段"的廉价校验，绝不读大块/写文件（避免持有 ART 锁时阻塞）
 *   - 真实落盘放到 JS 定时器里做，队列有上限
 *   - 只认标准 dex（magic + file_size 上限 + endian + map_off 校验），避免假命中 OOM
 * 与 codeitem_dump / dex_finder 互补，只做"多脱"，不做任何判定。
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) { console.log('[-] dex_capture requires utils.js (load it first)'); return; }

    var CONFIG = U.mergeConfig('dex_capture', {
        outputDir: '/data/local/tmp/dex_capture/',
        useExternalDir: false,
        // mmap 是高频调用：JS 回调会占满脚本线程，与 loadClass 的 setTimeout 冲突。
        // 默认关闭；短时 attach 场景可显式打开。
        hookMmap: false,
        sweepIntervalMs: 3000,
        maxRanges: 300,
        rangesPerSweep: 2,
        maxScanBytes: 512 * 1024,
        maxDexSize: 64 * 1024 * 1024,
        maxQueue: 64
    });

    var dumped = {};
    var queue = [];
    var ranges = [];
    var count = 0;
    var dirReady = false;

    function resolveDir() {
        if (dirReady) return true;
        try {
            var d = U.getDumpDir(CONFIG.useExternalDir);
            if (d) {
                CONFIG.outputDir = d;
                U.ensureDir(d);
                dirReady = true;
            }
        } catch (e) {}
        return dirReady;
    }

    // 廉价校验：只读 4 个 32 位字段
    function dexSize(p) {
        try {
            if (p.readU32() !== 0x0a786564) return 0;                 // "dex\n"
            var size = p.add(0x20).readU32();
            if (size < 0x70 || size > CONFIG.maxDexSize) return 0;
            var endian = p.add(0x28).readU32();
            if (endian !== 0x12345678 && endian !== 0x78563412) return 0;
            var mapOff = p.add(0x34).readU32();
            if (mapOff !== 0 && (mapOff < 0x70 || mapOff >= size)) return 0;
            return size;
        } catch (e) {
            return 0;
        }
    }

    function enqueue(p, tag) {
        if (!p || p.isNull()) return;
        var key = p.toString();
        if (dumped[key]) return;
        var size = dexSize(p);
        if (!size) return;
        if (queue.length >= CONFIG.maxQueue) return;
        dumped[key] = true;
        queue.push({ p: p, size: size, tag: tag });
    }

    function flush() {
        if (!queue.length || !resolveDir()) return;
        var n = 0;
        while (queue.length && n < 4) {
            var item = queue.shift();
            n++;
            try {
                var data = U.readDexMemory(item.p, item.size);
                if (!data) continue;
                count++;
                var path = CONFIG.outputDir + 'capture_' + count + '.dex';
                var f = new File(path, 'wb');
                f.write(data);
                f.close();
                U.ok('[CAPTURE] ' + path + ' base=' + item.p + ' size=' + item.size + ' (' + item.tag + ')');
            } catch (e) {}
        }
    }

    function remember(base, size) {
        if (!base || base.isNull() || size < 0x1000) return;
        if (ranges.length >= CONFIG.maxRanges) ranges.shift();
        ranges.push({ base: base, size: size, sweeps: 0 });
    }

    function sweep() {
        if (!dirReady) resolveDir();
        var scanned = 0;
        while (ranges.length && scanned < CONFIG.rangesPerSweep) {
            var r = ranges.shift();
            if (r.sweeps >= 3) continue;
            scanned++;
            var len = Math.min(r.size, CONFIG.maxScanBytes);
            try {
                var hits = Memory.scanSync(r.base, len, '64 65 78 0a');
                for (var j = 0; j < hits.length && j < 2; j++) {
                    enqueue(hits[j].address, 'sweep');
                }
            } catch (e) {}
            r.sweeps++;
            if (r.sweeps < 3) ranges.push(r);
        }
        flush();
    }

    function hookMmap() {
        var p = Module.findExportByName(null, 'mmap');
        if (!p) { U.fail('[CAPTURE] mmap not found'); return; }
        Interceptor.attach(p, {
            onEnter: function (args) {
                this.mmapSize = args[1].toInt32();
                this.mmapProt = args[2].toInt32();
            },
            onLeave: function (ret) {
                if (ret.toInt32() === -1) return;
                if (!(this.mmapProt & 1)) return;
                if (this.mmapSize >= 0x70) remember(ret, this.mmapSize);
                enqueue(ret, 'mmap');
            }
        });
        U.ok('[CAPTURE] mmap hooked @ ' + p);
    }

    function start() {
        resolveDir();
        if (CONFIG.hookMmap) hookMmap();
        setInterval(sweep, CONFIG.sweepIntervalMs);
        U.info('[CAPTURE] active, dir=' + CONFIG.outputDir +
            ' (sweep ' + CONFIG.sweepIntervalMs + 'ms, maxDex=' + (CONFIG.maxDexSize / 1048576) + 'MB)');
    }

    setTimeout(start, 1000);
    global.DexCapture = { count: function () { return count; } };
})(global);
