/**
 * dex_finder.js - DEX 内存搜索 + 指纹校验 + 去重
 * 用途：全内存扫 DEX magic（通配兼容 035/037/038/039），双层 verify，从 map_list 反推真实大小，去重输出
 * 互补：frida-dexdump 的 -d 深度扫描会对 OAT 缓存合并区重复 dump 同一段内存；本模块输出结构化指纹便于去重审计
 * 加载：frida -U -f com.app -l scripts/core/utils.js -l scripts/utils/dex_finder.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) { console.log("[-] dex_finder requires utils.js (load it first)"); return; }

    var CONFIG = U.mergeConfig('dex_finder', {
        // 输出目录（设备上）
        outputDir: "/data/local/tmp/dex_dump/",
        // 写外部私有目录（/sdcard/Android/data/<pkg>/files/dump/）：无 root / Gadget 时可 adb pull
        useExternalDir: false,
        // 是否 dump（false 只打印清单）
        autoDump: true,
        // 深度搜索：对抹掉 magic 的壳按 header_size(0x70) 反推
        deepSearch: true,
        // 排除系统路径段（/system/ /data/dalvik-cache/）
        excludeSystem: true,
        // 只 dump 含这些包名指纹的 DEX（读 class_defs 或字符串），空 = 全部
        filterPackage: [],
    });

    // DEX magic 通配：dex\n0XX\0 覆盖 035/037/038/039
    var DEX_MAGIC_WILDCARD = "64 65 78 0a 30 ?? ?? 00";
    var dumped = {};   // base -> size
    var dexCount = 0;

    // fast 校验：string_ids_off(0x3C) 必须等于 0x70（header 固定大小）
    function fastVerify(dexPtr, rangeEnd) {
        if (dexPtr.add(0x70).compare(rangeEnd) > 0) return false;
        try {
            return dexPtr.add(0x3C).readU32() === 0x70;
        } catch (e) { return false; }
    }

    // 轻校验（对齐 frida-dexdump）：只验证 header 可读 + 大小合理，不做真假过滤
    // 宁可多拉假 DEX，也不漏真 DEX；假 DEX 干扰交给 dex_dedupe.py 去重
    function lightVerify(dexPtr, rangeEnd) {
        try {
            if (dexPtr.add(0x70).compare(rangeEnd) > 0) return false;
            var hdrSize = dexPtr.add(0x24).readU32();
            if (hdrSize < 0x70) return false;
            var fileSize = dexPtr.add(0x20).readU32();
            if (fileSize < 0x70) return false;
            return true;
        } catch (e) { return false; }
    }

    // deep 校验：map_list 自引用闭合（TYPE_MAP_LIST=0x1000 的 offset 必须等于 header.map_off）
    function deepVerify(dexPtr, rangeEnd) {
        try {
            var mapOff = dexPtr.add(0x34).readU32();
            var mapsPtr = dexPtr.add(mapOff);
            if (mapsPtr.add(4).compare(rangeEnd) > 0) return false;
            var mapsSize = mapsPtr.readU32();
            if (mapsSize <= 0 || mapsSize > 0x10000) return false;
            for (var i = 0; i < mapsSize; i++) {
                var itemType = mapsPtr.add(4 + i * 0xC).readU16();
                if (itemType === 4096) {
                    var mapOffset = mapsPtr.add(4 + i * 0xC + 8).readU32();
                    return mapOff === mapOffset;
                }
            }
        } catch (e) {}
        return false;
    }

    // 从 map_list 末尾反推真实大小（不信任被改坏的 file_size）
    function getRealSize(dexPtr, rangeEnd) {
        var fileSize = dexPtr.add(0x20).readU32();
        try {
            var mapOff = dexPtr.add(0x34).readU32();
            var mapsPtr = dexPtr.add(mapOff);
            var mapsSize = mapsPtr.readU32();
            if (mapsSize <= 0 || mapsSize > 0x10000) return fileSize;
            var maxEnd = mapOff;
            for (var i = 0; i < mapsSize; i++) {
                var itemOff = mapsPtr.add(4 + i * 0xC + 8).readU32();
                var itemSize = mapsPtr.add(4 + i * 0xC + 4).readU32();
                var end = itemOff + itemSize;
                if (end > maxEnd) maxEnd = end;
            }
            if (maxEnd > 0 && maxEnd <= rangeEnd.sub(dexPtr).toInt32()) return maxEnd;
        } catch (e) {}
        return fileSize;
    }

    function saveDex(dexPtr, dexSize, source) {
        if (!dexPtr || dexPtr.isNull() || dexSize <= 0 || dexSize > 0x40000000) return;
        var key = dexPtr.toString() + ":" + dexSize;
        if (dumped[key]) return;
        dumped[key] = dexSize;
        dexCount++;

        var clsDefs = 0;
        try { clsDefs = dexPtr.add(0x60).readU32(); } catch (e) {}

        U.info("[DEXFINDER] [" + source + "] base=" + dexPtr + " size=" + dexSize +
            " class_defs=" + clsDefs + " (" + (dexSize / 1024 / 1024).toFixed(2) + " MB)");

        if (!CONFIG.autoDump) return;
        try {
            var data = U.readDexMemory(dexPtr, dexSize);
            if (!data) { U.fail("[DEXFINDER:DUMP] " + dexPtr + " read failed"); return; }
            var outputPath = CONFIG.outputDir + "found_" + dexCount + ".dex";
            var f = new File(outputPath, "wb");
            f.write(data);
            f.close();
            U.ok("[DEXFINDER:DUMP] " + outputPath);
        } catch (e) {
            U.fail("[DEXFINDER:DUMP] " + dexPtr + " failed: " + e.message);
        }
    }

    function isExcluded(range) {
        if (!CONFIG.excludeSystem) return false;
        if (range.file && range.file.path) {
            var p = range.file.path;
            if (p.indexOf("/system/") === 0 || p.indexOf("/data/dalvik-cache/") === 0) return true;
        }
        return false;
    }

    function scan() {
        var hit = 0;
        Process.enumerateRanges("r--").forEach(function (range) {
            if (isExcluded(range)) return;
            try {
                Memory.scanSync(range.base, range.size, DEX_MAGIC_WILDCARD).forEach(function (match) {
                    var rangeEnd = range.base.add(range.size);
                    if (!lightVerify(match.address, rangeEnd)) return;
                    var realSize = getRealSize(match.address, rangeEnd);
                    saveDex(match.address, realSize, "magic");
                    hit++;
                });
            } catch (e) {}
        });

        if (CONFIG.deepSearch) {
            Process.enumerateRanges("r--").forEach(function (range) {
                if (isExcluded(range)) return;
                try {
                    Memory.scanSync(range.base, range.size, "70 00 00 00").forEach(function (match) {
                        var dexBase = match.address.sub(0x3C);
                        if (dexBase.compare(range.base) < 0) return;
                        var magic = "";
                        try { magic = dexBase.readCString(4); } catch (e) {}
                        if (magic === "dex") return; // 前面已处理
                        var rangeEnd = range.base.add(range.size);
                        if (!lightVerify(dexBase, rangeEnd)) return;
                        if (!deepVerify(dexBase, rangeEnd)) return;
                        var realSize = getRealSize(dexBase, rangeEnd);
                        saveDex(dexBase, realSize, "deep");
                        hit++;
                    });
                } catch (e) {}
            });
        }
        U.ok("[DEXFINDER] done: " + hit + " matches, " + dexCount + " unique DEX");
    }

    global.DexFinder = {
        scan: scan,
        getDumpedCount: function () { return dexCount; },
    };

    U.info("dex_finder.js ready (deepSearch=" + CONFIG.deepSearch + " autoDump=" + CONFIG.autoDump + ")");
    console.log("");

    // 输出目录优先 app 私有目录（/data/local/tmp 属 root，app 进程无写权限）
    // 注意：必须在 Java 就绪后解析（顶层 Java.perform 异步，currentApplication 未就绪）
    function resolveOutputDir() {
        var appDumpDir = U.getDumpDir(CONFIG.useExternalDir);
        if (appDumpDir) CONFIG.outputDir = appDumpDir;
        U.ensureDir(CONFIG.outputDir);
    }

    setTimeout(function () { resolveOutputDir(); scan(); }, 3000);

})(this);