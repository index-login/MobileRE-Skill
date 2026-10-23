/**
 * so_audit_prep.java — SO 静态审计前置（Ghidra，通用）
 *
 * 解决两件"不做就没法审"的事（本次实战踩过的 G1/G2）：
 *   1) PLT 导入桩命名：反编译里 `func_0x…` 不可读 → 读重定位表 + 扫 PLT，建同名函数
 *   2) 原型批量回填：`JNIEnv*`/`jobject` 被当 undefined1[16]、参数错位 → 按规格文件批量应用
 *
 * 不做的（避免与既有能力重复）：
 *   - 函数边界异常诊断 → 用 MCP `ghidra_find_code_gaps` / `ghidra_analyze_function_completeness`
 *   - 单函数原型设置 → 用 MCP `ghidra_set_function_prototype`（本脚本只做**批量**）
 *
 * 用法（Ghidra MCP：把本文件内容作为 code 传入 run_script_inline）：
 *   args: [--no-plt] [--proto <file>]
 *   例：args = "--proto C:/path/protos.txt"
 *
 * 原型规格文件（每行一条，# 注释）：
 *   0x103eb0|long|void*,void*,void*,void*
 *   0x104898|void|void*,void*,long,void*,int,int,int,int,int,int
 *   地址 = Ghidra 地址（**含 image base**，如 base 0x100000 时要写 0x104898）
 *
 * 备注：
 *   - 本脚本是 **inline body**（无 class 声明），供 run_script_inline 使用；
 *     放进 ghidra_scripts 当菜单脚本需自行包一层 GhidraScript 类。
 *   - G1 可重复执行（幂等）：同名函数已存在则跳过。
 *   - 原型来源：Java 侧 `private native ...` 声明（jadx 可见）→ 按行写进规格文件。
 */

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.util.parser.FunctionSignatureParser;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

boolean doPlt = true;
String protoFile = null;

String[] args = getScriptArgs();
if (args != null) {
    for (int i = 0; i < args.length; i++) {
        String a = args[i];
        if ("--no-plt".equals(a)) doPlt = false;
        else if ("--proto".equals(a) && i + 1 < args.length) protoFile = args[++i];
    }
}
println("[prep] program=" + currentProgram.getName() + " imageBase=" + currentProgram.getImageBase()
        + " plt=" + doPlt + " proto=" + protoFile);

// ---------------- 1) PLT 导入桩命名 ----------------
if (doPlt) {
    Map<Long, String> gotName = new HashMap<Long, String>();
    Iterator<Relocation> it = currentProgram.getRelocationTable().getRelocations();
    while (it.hasNext()) {
        Relocation r = it.next();
        String s = null;
        try {
            Object o = Relocation.class.getMethod("getSymbolName").invoke(r);
            if (o != null) s = o.toString();
        } catch (Throwable t) { }
        if (s != null && s.length() > 0) gotName.put(r.getAddress().getOffset(), s);
    }

    int created = 0, renamed = 0, skipped = 0, unresolved = 0;
    for (MemoryBlock blk : currentProgram.getMemory().getBlocks()) {
        if (!blk.getName().toLowerCase().contains("plt")) continue;

        Address a = blk.getStart();
        Address end = blk.getEnd();
        while (a.compareTo(end) <= 0) {
            Instruction ins = getInstructionAt(a);
            if (ins == null || !"ldr".equals(ins.getMnemonicString())) { a = a.add(4); continue; }

            // 注意：ldr 的位移在 getOpObjects(1) 的 Scalar 元素里；getScalar(1) 返回 null
            long disp = -1;
            for (Object o : ins.getOpObjects(1)) {
                if (o instanceof Scalar) disp = ((Scalar) o).getUnsignedValue();
            }
            if (disp < 0) { unresolved++; a = a.add(4); continue; }

            // 注意：adrp 的页值在 getScalar(1)，且**已含 image base**
            long page = -1;
            Instruction prev = getInstructionAt(a.subtract(4));
            if (prev != null && "adrp".equals(prev.getMnemonicString())) {
                for (Object o : prev.getOpObjects(1)) {
                    if (o instanceof Scalar) page = ((Scalar) o).getUnsignedValue();
                }
            }
            if (page < 0) { unresolved++; a = a.add(4); continue; }

            String name = gotName.get((page & ~0xfffL) + disp);
            if (name == null) { skipped++; a = a.add(4); continue; }

            Address stub = a.subtract(4);
            Function f = getFunctionAt(stub);
            if (f == null) {
                try { f = createFunction(stub, name); if (f != null) created++; }
                catch (Throwable t) { }
            } else if (!name.equals(f.getName())) {
                try { f.setName(name, SourceType.IMPORTED); renamed++; }
                catch (Throwable t) { }
            }
            a = a.add(4);
        }
    }
    println("[plt] relocSymbols=" + gotName.size() + " created=" + created + " renamed=" + renamed
            + " notInRelocMap=" + skipped + " unresolved=" + unresolved);
}

// ---------------- 2) 原型批量回填 ----------------
if (protoFile != null) {
    int applied = 0, failed = 0;
    BufferedReader br = null;
    try {
        br = new BufferedReader(new FileReader(protoFile));
        FunctionSignatureParser parser = new FunctionSignatureParser(currentProgram.getDataTypeManager(), null);
        String line;
        while ((line = br.readLine()) != null) {
            line = line.trim();
            if (line.length() == 0 || line.startsWith("#")) continue;

            String[] parts = line.split("\\|");
            if (parts.length < 2) { failed++; continue; }

            String addrStr = parts[0].trim();
            String ret = parts[1].trim();
            String argStr = parts.length > 2 ? parts[2].trim() : "";
            String fnName = parts.length > 3 ? parts[3].trim() : "fn";
            String proto = ret + " " + fnName + "(" + argStr + ")";

            try {
                Address addr = toAddr(addrStr);
                Object sig = parser.parse(null, proto);
                ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                        addr, (ghidra.program.model.data.FunctionDefinition) sig, SourceType.USER_DEFINED);
                if (cmd.applyTo(currentProgram, monitor)) applied++;
                else { failed++; println("[proto] FAIL " + addrStr + "  " + proto); }
            } catch (Throwable t) {
                failed++;
                println("[proto] ERR " + addrStr + " :: " + t);
            }
        }
    } catch (Throwable t) {
        println("[proto] open/parse error: " + t);
    } finally {
        try { if (br != null) br.close(); } catch (Throwable t) { }
    }
    println("[proto] applied=" + applied + " failed=" + failed + " file=" + protoFile);
}

println("[prep] done");
