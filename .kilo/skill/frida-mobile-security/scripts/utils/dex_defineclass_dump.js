/**
 * dex_defineclass_dump.js - DEX 被动拦截 Dump（hook ClassLinker::DefineClass）
 * 用途：hook art::ClassLinker::DefineClass，每加载一个类就 dump 它所在的 DexFile（不依赖 magic，精确）
 * 互补：frida-dexdump 扫内存可能漏掉延迟加载的 DEX；本模块在壳解密瞬间的加载路径上捕获
 * 局限：必须等壳真的加载类才触发，延迟加载需操作 App 多点页面
 * 加载：frida -U -f com.app -l scripts/core/utils.js -l scripts/utils/dex_defineclass_dump.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) { console.log("[-] dex_defineclass_dump requires utils.js (load it first)"); return; }

    var CONFIG = U.mergeConfig('dex_defineclass_dump', {
        // 输出目录（设备上）
        outputDir: "/data/local/tmp/dex_dump/",
        // 写外部私有目录（/sdcard/Android/data/<pkg>/files/dump/）：无 root / Gadget 时可 adb pull
        useExternalDir: false,
        // 是否 dump（false 只打印清单）
        autoDump: true,
        // 只 dump 含这些包名的 DEX（读 class_defs 时校验），空 = 全部
        filterPackage: [],
    });

    var dumped = {};   // base -> size
    var dexCount = 0;
    var writeCount = 0;   // 实际写盘序号（独立于捕获计数，避免补写重名）
    var pendingDexes = [];   // 目录未就绪时缓存的 DexFile，就绪后补 dump

    function saveDex(dexPtr, dexSize) {
        if (!dexPtr || dexPtr.isNull() || dexSize <= 0 || dexSize > 0x40000000) return;
        var key = dexPtr.toString();
        if (dumped[key]) return;
        dumped[key] = dexSize;
        dexCount++;

        U.info("[DEFINECLASS] DexFile base=" + dexPtr + " size=" + dexSize +
            " (" + (dexSize / 1024 / 1024).toFixed(2) + " MB)");

        if (!CONFIG.autoDump) return;
        if (!outputDirResolved) {
            // 目录未就绪，缓存待补写
            pendingDexes.push({ base: dexPtr, size: dexSize });
            resolveOutputDir();
            return;
        }
        writeDex(dexPtr, dexSize);
    }

    function writeDex(dexPtr, dexSize) {
        try {
            var data = U.readDexMemory(dexPtr, dexSize);
            if (!data) { U.fail("[DEFINECLASS:DUMP] " + dexPtr + " read failed"); return; }
            writeCount++;
            var outputPath = CONFIG.outputDir + "defineclass_" + writeCount + ".dex";
            var f = new File(outputPath, "wb");
            f.write(data);
            f.close();
            U.ok("[DEFINECLASS:DUMP] " + outputPath);
        } catch (e) {
            U.fail("[DEFINECLASS:DUMP] " + dexPtr + " failed: " + e.message);
        }
    }

    function hookDefineClass() {
        var libart = Process.findModuleByName("libart.so");
        if (!libart) { U.fail("libart.so not found"); return; }

        var addrDefineClass = null;
        var symbols = Module.enumerateSymbols("libart.so");
        for (var i = 0; i < symbols.length; i++) {
            var name = symbols[i].name;
            // _ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileE...
            if (name.indexOf("ClassLinker") >= 0 &&
                name.indexOf("DefineClass") >= 0 &&
                name.indexOf("Thread") >= 0 &&
                name.indexOf("DexFile") >= 0) {
                addrDefineClass = symbols[i].address;
                break;
            }
        }

        if (!addrDefineClass) {
            U.fail("DefineClass symbol not found (check libart.so on this API level)");
            return;
        }

        U.ok("[DEFINECLASS] DefineClass @ " + addrDefineClass);
        Interceptor.attach(addrDefineClass, {
            onEnter: function (args) {
                try {
                    var dexFile = args[5];   // DexFile*
                    var base = dexFile.add(Process.pointerSize).readPointer();
                    var size = dexFile.add(Process.pointerSize * 2).readU32();
                    saveDex(base, size);
                } catch (e) {}
            }
        });
    }

    global.DefineClassDump = {
        getDumpedCount: function () { return dexCount; },
    };

    U.info("dex_defineclass_dump.js ready (autoDump=" + CONFIG.autoDump + ")");
    console.log("");

    // 输出目录优先 app 私有目录（/data/local/tmp 属 root，app 进程无写权限）
    // 惰性解析：hook 需尽早挂但 Java 未就绪，首次 dump 时再解析；未就绪则重试
    var outputDirResolved = false;
    var outputDirRetries = 0;
    function resolveOutputDir() {
        if (outputDirResolved) return;
        var appDumpDir = U.getDumpDir(CONFIG.useExternalDir);
        if (appDumpDir) {
            CONFIG.outputDir = appDumpDir;
            U.ensureDir(CONFIG.outputDir);
            outputDirResolved = true;
            // 补写目录就绪前捕获的 DexFile
            for (var i = 0; i < pendingDexes.length; i++) {
                writeDex(pendingDexes[i].base, pendingDexes[i].size);
            }
            pendingDexes = [];
            return;
        }
        // Java 未就绪（Application 未创建），延迟重试
        outputDirRetries++;
        if (outputDirRetries < 20) {
            setTimeout(resolveOutputDir, 500);
        }
    }

    hookDefineClass();

})(this);