/**
 * codeitem_dump.js - 抽取壳（二代壳）主动加载 + 整 DEX Dump
 * 原理：抽取壳的方法体在运行时首次解析时回填到 DEX 内存的 code_off 槽位（槽位按原始 DEX 布局）。
 *       主动 loadClass 全部类触发回填后，整 DEX dump 即得到完整 DEX。无需 ArtMethod 布局，版本无关。
 * 模式：
 *   mode:"whole"（默认）   → 主动 loadClass 全部类 → 整 DEX dump（Android 10+ 无需调偏移）
 *   mode:"loadmethod"      → 备选：hook ClassLinker::LoadMethod 逐方法提取 CodeItem + dex_rebuilder.py 重组
 * 对比 frida-dexdump：frida-dexdump 对抽取壳只能拿到"骨架 + return-void"；本模块主动触发回填后拿到完整 DEX
 * 局限：对"按方法执行粒度回填"的高级壳（loadClass 不触发回填）无效，需 AOSP 版 FART 或 native 逆向
 * 加载：frida -U -f com.app -l scripts/core/utils.js -l scripts/utils/codeitem_dump.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) { console.log("[-] codeitem_dump requires utils.js (load it first)"); return; }

    var CONFIG = U.mergeConfig('codeitem_dump', {
        // whole（整 DEX dump，推荐）| loadmethod（逐方法 CodeItem 提取，备选）
        mode: "whole",
        // 输出目录（设备上）
        outputDir: "/data/local/tmp/fart/",
        // 写外部私有目录（/sdcard/Android/data/<pkg>/files/dump/）：无 root / Gadget 时可 adb pull
        useExternalDir: false,
        // 启动后自动触发主动 loadClass
        autoFart: true,
        // autoFart=false 时仍枚举 DexCache 整包 dump（不触发 loadClass）
        dumpOnly: false,
        // 只处理含这些关键字的类，空 = 全部
        classFilter: [],
        // 主动 loadClass 分批大小（防高级壳检测异常调用模式自杀）
        batchSize: 100,
        // 每批间隔 ms
        batchDelay: 300,
        // 每 N 批增量落盘一次（0 = 只落盘一次；中途被杀时保住已有产物）
        dumpEveryBatches: 15,
        // loadmethod 模式专用：ArtMethod 布局偏移（Android 6-9 默认）
        artMethodCodeItemOffset: 8,     // dex_code_item_offset_
        artMethodMethodIndexOffset: 12, // dex_method_index_
    });

    var dumpedDecFiles = {};  // dexBase -> true
    var dexCount = 0;

    function dumpWholeDex(dexPtr, dexSize, tag) {
        if (!dexPtr || dexPtr.isNull() || dexSize <= 0 || dexSize > 0x40000000) return;
        var key = dexPtr.toString();
        if (dumpedDecFiles[key]) return;
        dumpedDecFiles[key] = true;
        dexCount++;

        try {
            var data = U.readDexMemory(dexPtr, dexSize);
            if (!data) { U.fail("[FART:WHOLE] " + dexPtr + " read failed"); return; }
            var outputPath = CONFIG.outputDir + "whole_" + dexSize + "_" + dexCount + ".dex";
            var f = new File(outputPath, "wb");
            f.write(dexPtr.readByteArray(dexSize));
            f.close();
            U.ok("[FART:WHOLE] " + outputPath + " (" + (dexSize / 1024 / 1024).toFixed(2) + " MB)");
        } catch (e) {
            U.fail("[FART:WHOLE] " + dexPtr + " failed: " + e.message);
        }
    }

    // ==================== mode: whole（主动 loadClass → 整 DEX dump） ====================

    // 收集单个 loader 的所有类名（含 classFilter 过滤）
    function collectClassesFromLoader(loader, out) {
        try {
            var baseCls = Java.cast(loader, Java.use("dalvik.system.BaseDexClassLoader"));
            var pathList = Java.cast(baseCls.pathList.value, Java.use("dalvik.system.DexPathList"));
            var dexElements = pathList.dexElements.value;
            for (var i = 0; i < dexElements.length; i++) {
                var element = Java.cast(dexElements[i], Java.use("dalvik.system.DexPathList$Element"));
                var dexFile = Java.cast(element.dexFile.value, Java.use("dalvik.system.DexFile"));
                var classes = dexFile.entries();
                while (classes.hasMoreElements()) {
                    var className = classes.nextElement().toString();
                    if (CONFIG.classFilter.length === 0) {
                        out.push({ loader: loader, className: className });
                    } else {
                        for (var j = 0; j < CONFIG.classFilter.length; j++) {
                            if (className.indexOf(CONFIG.classFilter[j]) !== -1) {
                                out.push({ loader: loader, className: className });
                                break;
                            }
                        }
                    }
                }
            }
        } catch (e) {}
    }

    // 分批 loadClass
    var batchCount = 0;

    function loadClassesInBatch(items, index) {
        var end = Math.min(index + CONFIG.batchSize, items.length);
        for (var i = index; i < end; i++) {
            try {
                items[i].loader.loadClass(items[i].className);
            } catch (e) {}
        }
        batchCount++;
        U.info("[FART] loadClass " + (index + 1) + "-" + end + " / " + items.length);
        if (end < items.length) {
            if (CONFIG.dumpEveryBatches > 0 && (batchCount % CONFIG.dumpEveryBatches) === 0) {
                U.info("[FART] incremental dump @" + end + " / " + items.length);
                dumpAllDexFiles(false);
            }
            setTimeout(function () { loadClassesInBatch(items, end); }, CONFIG.batchDelay);
        } else {
            dumpAllDexFiles(true);
        }
    }

    // 回填完成后枚举 DexCache 整 DEX dump（final=false 时不发完成标记，供增量落盘）
    function dumpAllDexFiles(final) {
        if (!Java.available) { U.fail("Java not available"); return; }
        Java.perform(function () {
            try {
                Java.choose("java.lang.DexCache", {
                    onMatch: function (instance) {
                        try {
                            var dexFile = instance.dexFile.value;
                            var location = instance.location.value;
                            var dexPtr = ptr(dexFile).add(Process.pointerSize).readPointer();
                            var dexSize = ptr(dexFile).add(Process.pointerSize * 2).readU32();
                            dumpWholeDex(dexPtr, dexSize, location);
                        } catch (e) {}
                    },
                    onComplete: function () {
                        if (final !== false) {
                            U.ok("[FART] whole-dex dump done, " + dexCount + " unique DEX");
                        }
                    }
                });
            } catch (e) {
                U.fail("[FART] DexCache enumeration failed: " + e.message);
            }
        });
    }

    function fartWhole() {
        if (!Java.available) { U.fail("Java not available"); return; }
        Java.perform(function () {
            var items = [];
            Java.enumerateClassLoaders({
                onMatch: function (loader) { collectClassesFromLoader(loader, items); },
                onComplete: function () {
                    U.info("[FART] collected " + items.length + " classes");
                    if (items.length > 0) {
                        loadClassesInBatch(items, 0);
                    } else {
                        dumpAllDexFiles();
                    }
                }
            });
        });
    }

    // ==================== mode: loadmethod（逐方法 CodeItem 提取，备选） ====================

    var artmethodMaps = {};   // artmethodPtr -> { dexFile, artmethodPtr }
    var skeletonDumped = {};  // dexBase -> true
    var dumpedCodeItems = {}; // artmethodPtr -> true
    var insFile = null;
    var insCount = 0;

    function uleb128(ptr) {
        var result = 0, shift = 0, size = 0;
        while (true) {
            var b = ptr.add(size).readU8();
            result |= (b & 0x7f) << shift;
            size++;
            if ((b & 0x80) === 0) break;
            shift += 7;
        }
        return { value: result, size: size };
    }

    function sleb128(ptr) {
        var r = uleb128(ptr);
        var value = r.value;
        if (value & (1 << (r.size * 7 - 1))) value -= (1 << (r.size * 7));
        return { value: value, size: r.size };
    }

    function computeCodeItemLength(codeItem) {
        var insnsSize = codeItem.add(12).readU32();
        var triesSize = codeItem.add(6).readU16();
        var size = 16 + insnsSize * 2;
        if (triesSize > 0) {
            if (insnsSize % 2 === 1) size += 2;
            size += triesSize * 8;
            var handlersPtr = codeItem.add(size);
            var hs = uleb128(handlersPtr);
            size += hs.size;
            for (var i = 0; i < hs.value; i++) {
                var sz = sleb128(handlersPtr);
                size += sz.size;
                var absSz = Math.abs(sz.value);
                for (var j = 0; j < absSz; j++) {
                    size += uleb128(handlersPtr).size;
                    size += uleb128(handlersPtr).size;
                }
                if (sz.value <= 0) {
                    size += uleb128(handlersPtr).size;
                }
            }
        }
        return size;
    }

    function dumpSkeleton(dexFile) {
        var base = dexFile.add(Process.pointerSize).readPointer();
        var size = dexFile.add(Process.pointerSize * 2).readU32();
        if (skeletonDumped[base.toString()]) return;
        skeletonDumped[base.toString()] = true;
        if (!base || base.isNull() || size <= 0) return;
        try {
            var data = U.readDexMemory(base, size);
            if (!data) { U.fail("[FART:SKELETON] " + base + " read failed"); return; }
            var outputPath = CONFIG.outputDir + size + "_loadMethod.dex";
            var f = new File(outputPath, "wb");
            f.write(base.readByteArray(size));
            f.close();
            U.ok("[FART:SKELETON] " + outputPath + " (size=" + size + ")");
        } catch (e) {
            U.fail("[FART:SKELETON] " + base + " failed: " + e.message);
        }
    }

    function dumpCodeItem(artmethodObj) {
        try {
            var key = artmethodObj.artmethodPtr.toString();
            if (dumpedCodeItems[key]) return;
            var dexBase = artmethodObj.dexFile.add(Process.pointerSize).readPointer();
            var artmethodPtr = artmethodObj.artmethodPtr;
            var codeItemOff = artmethodPtr.add(CONFIG.artMethodCodeItemOffset).readU32();
            var methodIndex = artmethodPtr.add(CONFIG.artMethodMethodIndexOffset).readU32();
            if (codeItemOff <= 0) return;

            var codeItemAddr = dexBase.add(codeItemOff);
            var codeItemLen = computeCodeItemLength(codeItemAddr);
            if (codeItemLen <= 0 || codeItemLen > 0x100000) return;

            var b64 = U.bytesToBase64(U.readDexMemory(codeItemAddr, codeItemLen));
            insFile.write("{name:method_" + methodIndex + ",method_idx:" + methodIndex +
                ",offset:" + codeItemOff + ",code_item_len:" + codeItemLen +
                ",ins:" + b64 + "};\n");
            dumpedCodeItems[key] = true;
            insCount++;
        } catch (e) {}
    }

    function dumpAllCodeItems() {
        for (var key in artmethodMaps) {
            dumpCodeItem(artmethodMaps[key]);
        }
        U.ok("[FART] dumped " + insCount + " CodeItems to .bin");
    }

    function hookLoadMethod() {
        var libart = Process.findModuleByName("libart.so");
        if (!libart) { U.fail("libart.so not found"); return; }

        var addrLoadMethod = null;
        var symbols = Module.enumerateSymbols("libart.so");
        for (var i = 0; i < symbols.length; i++) {
            var name = symbols[i].name;
            // Android 9-10 符号含 ClassAccessor，Android 6-8 含 ClassDataItemIterator
            if (name.indexOf("ClassLinker") >= 0 &&
                name.indexOf("LoadMethod") >= 0 &&
                name.indexOf("DexFile") >= 0) {
                addrLoadMethod = symbols[i].address;
                break;
            }
        }

        if (!addrLoadMethod) {
            U.fail("LoadMethod symbol not found (check libart.so on this API level)");
            return;
        }

        U.ok("[FART] LoadMethod @ " + addrLoadMethod);
        Interceptor.attach(addrLoadMethod, {
            onEnter: function (args) {
                try {
                    this.dexFilePtr = args[1];
                    this.artMethodPtr = args[4];
                } catch (e) {}
            },
            onLeave: function () {
                try {
                    if (!this.dexFilePtr || !this.artMethodPtr) return;
                    dumpSkeleton(this.dexFilePtr);
                    artmethodMaps[this.artMethodPtr.toString()] = {
                        dexFile: this.dexFilePtr,
                        artmethodPtr: this.artMethodPtr,
                    };
                } catch (e) {}
            }
        });
    }

    function loadClassesInBatchLM(items, index) {
        var end = Math.min(index + CONFIG.batchSize, items.length);
        for (var i = index; i < end; i++) {
            try {
                items[i].loader.loadClass(items[i].className);
            } catch (e) {}
        }
        U.info("[FART] loadClass " + (index + 1) + "-" + end + " / " + items.length);
        if (end < items.length) {
            setTimeout(function () { loadClassesInBatchLM(items, end); }, CONFIG.batchDelay);
        } else {
            dumpAllCodeItems();
        }
    }

    function fartLoadMethod() {
        if (!Java.available) { U.fail("Java not available"); return; }
        Java.perform(function () {
            dumpAllCodeItems();
            var items = [];
            Java.enumerateClassLoaders({
                onMatch: function (loader) { collectClassesFromLoader(loader, items); },
                onComplete: function () {
                    U.info("[FART] collected " + items.length + " classes");
                    if (items.length > 0) {
                        loadClassesInBatchLM(items, 0);
                    }
                }
            });
        });
    }

    // ==================== 初始化 ====================
    // 输出目录优先 app 私有目录（/data/local/tmp 属 root，app 进程无写权限）
    // 注意：必须在 Java 就绪后解析（顶层 Java.perform 异步，currentApplication 未就绪）
    function resolveOutputDir() {
        var appDumpDir = U.getDumpDir(CONFIG.useExternalDir);
        if (appDumpDir) CONFIG.outputDir = appDumpDir;
        U.ensureDir(CONFIG.outputDir);
    }

    // loadmethod 模式初始化：ins.bin 打开 + hookLoadMethod
    // 必须在目录就绪后执行（顶层 Java 未就绪，目录解析失败）
    function initLoadMethod() {
        try {
            var f = new File(CONFIG.outputDir + "ins.bin", "wb");
            f.close();
            insFile = new File(CONFIG.outputDir + "ins.bin", "ab");
            hookLoadMethod();
        } catch (e) {
            U.fail("cannot open output dir: " + CONFIG.outputDir + " - " + e.message);
        }
    }

    if (CONFIG.autoFart) {
        setTimeout(function () {
            resolveOutputDir();
            if (CONFIG.mode === "loadmethod") {
                initLoadMethod();
                fartLoadMethod();
            } else {
                fartWhole();
            }
        }, 5000);
    } else if (CONFIG.dumpOnly) {
        // 温和模式：不 loadClass，只枚举 DexCache 整包 dump（对脆弱的加固 App）
        setTimeout(function () {
            resolveOutputDir();
            dumpAllDexFiles(true);
        }, 1000);
    }

    global.FartDump = {
        fart: CONFIG.mode === "loadmethod" ? fartLoadMethod : fartWhole,
        getDumpCount: function () { return dexCount; },
        getCodeItemCount: function () { return insCount; },
    };

    U.info("codeitem_dump.js ready (mode=" + CONFIG.mode + " autoFart=" + CONFIG.autoFart +
        " batch=" + CONFIG.batchSize + ")");
    console.log("");

})(this);