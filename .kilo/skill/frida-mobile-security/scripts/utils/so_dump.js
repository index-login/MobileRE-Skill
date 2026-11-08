/**
 * so_dump.js - SO 内存 Dump 工具模块
 * 用途：从内存中 dump 已加载的 SO 文件（包括壳解密后的 SO），修复 ELF 头
 * 覆盖：简易 dump / 按段精确 dump / JNI_OnLoad 时机 dump / mprotect 监控 / 解密函数捕获
 * 来源：整合自 Frida 学习笔记 · SO Dump 与内存 Dump
 * 加载方式：frida -U -f com.app -l utils.js -l so_dump.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) { console.log("[-] so_dump requires utils.js (load it first)"); return; }

    var CONFIG = U.mergeConfig('so_dump', {
        // 输出目录（设备上）
        outputDir: "/data/local/tmp/",
        // 是否自动 dump 所有 /data/app/ 路径下的 SO
        autoDumpAppSo: false,
        // 是否在 JNI_OnLoad 时机 dump
        dumpOnJniOnLoad: false,
        // 监控 mprotect 调用
        monitorMprotect: false,
        // 捕获解密函数（通过异常处理定位）
        catchDecryptRoutine: false,
    });

    // ==================== 公共函数 ====================
    function padHex(n, width) {
        var s = n.toString(16);
        while (s.length < width) s = "0" + s;
        return s;
    }

    function getSoBase(name) {
        try {
            var m = Process.findModuleByName(name);
            return m ? { base: m.base, size: m.size, path: m.path } : null;
        } catch (e) { return null; }
    }

    /**
     * 简易 SO dump — 直接读整个模块内存
     * @param {string} soName - SO 文件名
     * @param {string} outputName - 输出文件名（可选，默认同名）
     */
    function dumpSimple(soName, outputName) {
        var info = getSoBase(soName);
        if (!info) { U.fail("SO not found: " + soName); return false; }

        outputName = outputName || soName;
        var outputPath = CONFIG.outputDir + outputName;

        try {
            // 确保内存可读
            Memory.protect(info.base, info.size, 'rwx');
            var data = info.base.readByteArray(info.size);
            var f = new File(outputPath, "wb");
            f.write(data);
            f.close();
            U.ok("[SO_DUMP] " + soName + " → " + outputPath + " (" + (info.size / 1024).toFixed(1) + " KB)");
            return true;
        } catch (e) {
            U.fail("[SO_DUMP] " + soName + " failed: " + e.message);
            return false;
        }
    }

    /**
     * 精确 SO dump — 按 ELF 段枚举，只 dump 实际加载的段
     * 解决了简易 dump 的 0xCC 填充问题
     * @param {string} soName - SO 文件名
     * @param {string} outputName - 输出文件名
     */
    /**
     * 按段精确 dump — 以 program header 计算文件大小，并补上运行时新增的匿名段
     *
     * 关键：加固壳常把解密代码映射到**文件之外的匿名段**（file=null），
     * 这类内容不在 p_offset..p_offset+p_filesz 范围内，只按 program header
     * 截断会丢掉整块解密代码（实测某加固 SO 丢 191456 字节）。
     * 因此最终尺寸取 max(program header 推算值, 模块实际 size)。
     *
     * @param {string} soName - SO 文件名
     * @param {string} outputName - 输出文件名
     * @param {boolean} fullModule - true 时强制按模块实际大小 dump（默认 false）
     */
    function dumpPrecise(soName, outputName, fullModule) {
        var info = getSoBase(soName);
        if (!info) { U.fail("SO not found: " + soName); return false; }

        outputName = outputName || soName;
        var outputPath = CONFIG.outputDir + outputName;

        try {
            var e_phoff = (Process.pointerSize === 8)
                ? info.base.add(0x20).readU64()
                : info.base.add(0x1C).readU32();
            var e_phnum = info.base.add(Process.pointerSize === 8 ? 0x38 : 0x2C).readU16();
            var e_phentsize = info.base.add(Process.pointerSize === 8 ? 0x36 : 0x2A).readU16();

            U.info("[SO_DUMP] ELF: " + e_phnum + " program headers, phoff=0x" + e_phoff.toString(16));

            var maxEnd = 0;
            for (var i = 0; i < e_phnum; i++) {
                var phdr = info.base.add(e_phoff + i * e_phentsize);
                var p_type = phdr.readU32();
                if (p_type !== 1 /* PT_LOAD */) continue;
                var p_offset = (Process.pointerSize === 8) ? phdr.add(0x8).readU64() : phdr.add(0x4).readU32();
                var p_filesz = (Process.pointerSize === 8) ? phdr.add(0x20).readU64() : phdr.add(0x10).readU32();
                var end = p_offset.add(p_filesz);
                if (end.compare(maxEnd) > 0) maxEnd = end;
            }

            U.info("[SO_DUMP] PT_LOAD 推算大小: " + (maxEnd.toNumber() / 1024).toFixed(1) + " KB");
            U.info("[SO_DUMP] 模块实际大小:   " + (info.size / 1024).toFixed(1) + " KB");

            var anon = detectAnonSegments(info);
            if (anon.total > 0) {
                U.alert("[SO_DUMP] 检测到 " + anon.count + " 个匿名段，共 "
                    + (anon.total / 1024).toFixed(1) + " KB（壳解密区，不在文件映射内）");
            }

            var realSize = fullModule ? info.size : Math.max(maxEnd.toNumber(), info.size);
            realSize = Math.min(realSize, info.size);

            U.info("[SO_DUMP] dump 尺寸: " + (realSize / 1024).toFixed(1) + " KB");

            Memory.protect(info.base, realSize, 'rwx');
            var data = info.base.readByteArray(realSize);
            var f = new File(outputPath, "wb");
            f.write(data);
            f.close();
            U.ok("[SO_DUMP:PRECISE] " + soName + " → " + outputPath + " (" + (realSize / 1024).toFixed(1) + " KB)");

            if (anon.total > 0 && !fullModule) {
                U.info("[SO_DUMP] 提示：本 so 含匿名解密段，若解析异常请用 fullModule=true 重 dump");
            }
            return true;
        } catch (e) {
            U.fail("[SO_DUMP:PRECISE] " + soName + " failed: " + e.message);
            U.info("[SO_DUMP] Falling back to simple dump...");
            return dumpSimple(soName, outputName);
        }
    }

    /**
     * 检测模块内的匿名段（file=null）——加固壳的解密区特征
     * @returns {{count:number, total:number, ranges:Array}}
     */
    function detectAnonSegments(info) {
        var ranges = [];
        var total = 0;
        try {
            Process.enumerateRanges('r--').forEach(function (r) {
                var rEnd = r.base.add(r.size);
                if (rEnd.compare(info.base) <= 0) return;
                if (r.base.compare(info.base.add(info.size)) >= 0) return;
                if (r.file) return;
                var off = r.base.sub(info.base).toInt32();
                var size = Math.min(r.size, info.size - off);
                ranges.push({ offset: off, size: size, protection: r.protection });
                total += size;
            });
        } catch (e) { /* enumerateRanges 失败时静默 */ }
        ranges.sort(function (a, b) { return a.offset - b.offset; });
        return { count: ranges.length, total: total, ranges: ranges };
    }

    /**
     * JNI_OnLoad 时机 dump — 在 SO 的 JNI_OnLoad 执行后立即 dump
     * 适用于壳解密 SO 后、检测代码执行前的窗口
     * @param {string} soName - 要 dump 的 SO 文件名
     * @param {string} outputName - 输出文件名
     */
    function dumpOnJniOnLoad(soName, outputName) {
        outputName = outputName || soName.replace(".so", "_decrypted.so");

        var libdl = Process.findModuleByName("libdl.so");
        if (!libdl) { U.fail("libdl.so not found"); return; }

        var dlopen = libdl.findExportByName("android_dlopen_ext") || libdl.findExportByName("dlopen");
        if (!dlopen) { U.fail("dlopen not found"); return; }

        Interceptor.attach(dlopen, {
            onEnter: function (args) {
                try {
                    var path = args[0].readCString();
                    if (path && path.indexOf(soName) !== -1) {
                        this.targetPath = path;
                        this.targetSo = soName;
                    }
                } catch (e) {}
            },
            onLeave: function (retval) {
                if (!this.targetSo || retval.isNull()) return;
                U.info("[SO_DUMP:JNI] " + this.targetSo + " loaded, waiting for JNI_OnLoad...");

                // 在 JNI_OnLoad 之后 dump（延迟 500ms 让壳解密完成）
                var soName = this.targetSo;
                var outName = outputName;
                setTimeout(function () {
                    dumpPrecise(soName, outName);
                }, 500);
            }
        });

        U.ok("[SO_DUMP:JNI] Waiting for " + soName + " to load via dlopen...");
    }

    /**
     * 监控 mprotect 调用 — 追踪 SO 解密时的内存权限变更
     */
    function monitorMprotect() {
        var mprotectAddr = Module.findExportByName("libc.so", "mprotect");
        if (!mprotectAddr) { U.fail("mprotect not found"); return; }

        Interceptor.attach(mprotectAddr, {
            onEnter: function (args) {
                this.addr = args[0];
                this.len = args[1].toInt32();
                this.prot = args[2].toInt32();

                var protStr = "";
                if (this.prot & 1) protStr += "R";
                if (this.prot & 2) protStr += "W";
                if (this.prot & 4) protStr += "X";
                if (!protStr) protStr = "NONE";

                // 只关注 PROT_EXEC 的变更（解密 + 执行）
                if (this.prot & 4) {
                    var mod = Process.findModuleByAddress(this.addr);
                    var modName = mod ? mod.name : "???";
                    var offset = mod ? this.addr.sub(mod.base) : ptr(0);
                    U.alert("[MPROTECT] " + modName + " + 0x" + offset.toString(16) +
                        " len=" + (this.len / 1024).toFixed(1) + "KB prot=" + protStr);
                    U.logBacktrace(this.context, 8);
                }
            }
        });
        U.ok("mprotect monitor active");
    }

    /**
     * 捕获解密函数 — 通过设置异常处理，在 SO 解密代码执行时捕获上下文
     * 原理：在目标 SO 的 .text 段设置 PROT_NONE（不可读），利用 SIGSEGV handler 捕获解密函数
     * @param {string} soName - 目标 SO 文件名
     */
    function catchDecryptRoutine(soName) {
        var info = getSoBase(soName);
        if (!info) { U.fail("SO not found: " + soName); return; }

        // 找到 .text 段
        var e_phoff = (Process.pointerSize === 8)
            ? info.base.add(0x20).readU64()
            : info.base.add(0x1C).readU32();
        var e_phnum = info.base.add(Process.pointerSize === 8 ? 0x38 : 0x2C).readU16();
        var e_phentsize = info.base.add(Process.pointerSize === 8 ? 0x36 : 0x2A).readU16();

        var textStart = null;
        var textEnd = null;

        for (var i = 0; i < e_phnum; i++) {
            var phdr = info.base.add(e_phoff + i * e_phentsize);
            var p_type = phdr.readU32();
            if (p_type !== 1 /* PT_LOAD */) continue;
            var p_flags = phdr.add(Process.pointerSize === 8 ? 0x4 : 0x18).readU32();
            if (!(p_flags & 1 /* PF_X */)) continue; // 只关注可执行段

            var p_vaddr = (Process.pointerSize === 8) ? phdr.add(0x10).readU64() : phdr.add(0x8).readU32();
            var p_memsz = (Process.pointerSize === 8) ? phdr.add(0x28).readU64() : phdr.add(0x14).readU32();
            textStart = info.base.add(p_vaddr);
            textEnd = textStart.add(p_memsz);
            break;
        }

        if (!textStart) {
            U.fail("[SO_DUMP:DECRYPT] No executable segment found in " + soName);
            return;
        }

        U.info("[SO_DUMP:DECRYPT] .text: " + textStart + " - " + textEnd + " (" + (textEnd.sub(textStart) / 1024).toFixed(1) + " KB)");

        // 设置 .text 为 PROT_NONE，捕获解密函数
        Process.setExceptionHandler(function (details) {
            if (details.type === "access-violation") {
                var addr = details.address;
                if (addr.compare(textStart) >= 0 && addr.compare(textEnd) < 0) {
                    U.alert("[SO_DUMP:DECRYPT] Caught access to encrypted .text at " + addr);
                    U.logBacktrace(details.context, 12);

                    // 恢复 .text 为 rwx（让解密函数完成工作）
                    Memory.protect(textStart, textEnd.sub(textStart).toInt32(), 'rwx');

                    // 延迟后 dump
                    var soName_ = soName;
                    setTimeout(function () {
                        dumpPrecise(soName_, soName_.replace(".so", "_decrypted.so"));
                    }, 1000);

                    return true; // 已处理
                }
            }
            return false; // 未处理，继续传播
        });

        // 将 .text 设为不可访问
        Memory.protect(textStart, textEnd.sub(textStart).toInt32(), '---');
        U.ok("[SO_DUMP:DECRYPT] .text set to PROT_NONE, waiting for decrypt routine...");
    }

    // ==================== 自动 dump 所有 App SO ====================
    if (CONFIG.autoDumpAppSo) {
        Process.enumerateModules().forEach(function (mod) {
            if (mod.path.indexOf("/data/app/") !== -1 && mod.path.endsWith(".so")) {
                dumpPrecise(mod.name);
            }
        });
    }

    if (CONFIG.monitorMprotect) {
        monitorMprotect();
    }

    // ==================== 导出 API ====================
    global.SoDump = {
        dumpSimple: dumpSimple,
        dumpPrecise: dumpPrecise,
        dumpOnJniOnLoad: dumpOnJniOnLoad,
        monitorMprotect: monitorMprotect,
        catchDecryptRoutine: catchDecryptRoutine,
    };

    U.info("so_dump.js ready (autoDump=" + CONFIG.autoDumpAppSo +
        " mprotect=" + CONFIG.monitorMprotect +
        " jniOnLoad=" + CONFIG.dumpOnJniOnLoad + ")");
    console.log("");

})(this);