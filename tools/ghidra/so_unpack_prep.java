/**
 * so_unpack_prep.java — 加固 SO 内存镜像分析前置（Ghidra，通用）
 *
 * 解决的问题（脱壳镜像实战踩坑）：
 *   脱壳重建出的 ELF 常有三个问题，导致 Ghidra 里"看不到函数/伪代码"：
 *     G1) 代码块未标记可执行 → disassemble 大面积失败
 *     G2) section 表被代码覆盖 → Ghidra 按 segment_N.M 建块，找不到 .text
 *     G3) 无导出符号 → 自动分析只认出个位数函数
 *
 * 三步修复（顺序不可颠倒）：
 *   1) set-exec    给代码区补 X 权限
 *   2) disasm      逐 4 字节反汇编（ARM64 固定长度，失败率 ~50% 属正常，数据段会失败）
 *   3) funcs       三策略建函数：bl/b 目标 → adrp 目标 → 严格入口形态
 *
 * 不做的（避免与既有能力重复）：
 *   - PLT 桩命名 / 原型回填 → 用 so_audit_prep.java
 *   - 字符串交叉引用查询 → 用 MCP ghidra_get_xrefs_to（本脚本只负责把字符串数据建出来）
 *
 * 用法（Ghidra MCP：把本文件内容作为 code 传入 run_script_inline）：
 *   args: [--start 0x142000] [--end 0x1EFFFF] [--step all|exec|disasm|funcs]
 *   默认：自动从 PT_LOAD 的 RX 段推断范围，跑全部三步
 *
 *   例：args = "--step funcs"
 *       args = "--start 0x142000 --end 0x1effff"
 *
 * 备注：
 *   - 本脚本是 inline body（无 class 声明），供 run_script_inline 使用
 *   - 幂等：可重复执行，已建函数/已反汇编位置会跳过
 *   - 失败率高的区域通常是 .text 中夹杂的字面量池，属正常
 */

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

// ---------- 参数解析 ----------
String argStep = "all";
long argStart = -1, argEnd = -1;
if (args != null && !args.trim().isEmpty()) {
    String[] parts = args.trim().split("\\s+");
    for (int i = 0; i < parts.length; i++) {
        if (parts[i].equals("--step") && i + 1 < parts.length) argStep = parts[++i];
        else if (parts[i].equals("--start") && i + 1 < parts.length) argStart = Long.decode(parts[++i]);
        else if (parts[i].equals("--end") && i + 1 < parts.length) argEnd = Long.decode(parts[++i]);
    }
}

Memory mem = currentProgram.getMemory();
Listing listing = currentProgram.getListing();
FunctionManager fm = currentProgram.getFunctionManager();

// ---------- 范围推断：优先参数，其次 RX 段 ----------
Address start, end;
if (argStart >= 0 && argEnd >= 0) {
    start = toAddr(argStart);
    end = toAddr(argEnd);
    println("[i] range from args: " + start + " .. " + end);
} else {
    long lo = Long.MAX_VALUE, hi = Long.MIN_VALUE;
    for (MemoryBlock b : mem.getBlocks()) {
        if (!b.isInitialized() || b.getSize() == 0) continue;
        // 只取"体积大且原本是 RX"的块
        if (b.getSize() < 0x10000) continue;
        if (b.getStart().getOffset() < 0x100000) continue;   // 跳过 ELF header 区
        lo = Math.min(lo, b.getStart().getOffset());
        hi = Math.max(hi, b.getEnd().getOffset());
    }
    if (lo == Long.MAX_VALUE) { println("[-] cannot infer code range; pass --start/--end"); return; }
    start = toAddr(lo);
    end = toAddr(hi);
    println("[i] range inferred from blocks: " + start + " .. " + end);
}

// ---------- 步骤 1：补执行权限 ----------
if (argStep.equals("all") || argStep.equals("exec")) {
    int n = 0;
    for (MemoryBlock b : mem.getBlocks()) {
        if (!b.isInitialized()) continue;
        long s = b.getStart().getOffset();
        if (s < start.getOffset() || s > end.getOffset()) continue;
        // 数据类块（.data/.bss/.dynamic/字符串表）不设 X
        String nm = b.getName();
        if (nm.contains("data") || nm.contains("bss") || nm.contains("dynamic")
            || nm.contains("strtab") || nm.contains("dynstr") || nm.contains("dynsym")
            || nm.startsWith("unallocated")) continue;
        if (!b.isExecute()) {
            try { b.setExecute(true); n++; println("  [X] " + nm + " " + b.getStart() + ".." + b.getEnd()); }
            catch (Exception e) { println("  [-] " + nm + ": " + e.getMessage()); }
        }
    }
    println("[1] exec flags set on " + n + " block(s)");
}

// ---------- 步骤 2：逐 4 字节反汇编 ----------
if (argStep.equals("all") || argStep.equals("disasm")) {
    long ok = 0, fail = 0;
    Address a = start;
    while (a.compareTo(end) < 0) {
        Instruction insn = listing.getInstructionAt(a);
        if (insn != null) { ok++; a = a.add(insn.getLength()); continue; }
        boolean done = false;
        try {
            disassemble(a);
            insn = listing.getInstructionAt(a);
            if (insn != null) { done = true; ok++; a = a.add(insn.getLength()); }
        } catch (Exception e) { }
        if (!done) { fail++; a = a.add(4); }
    }
    println("[2] disassembled=" + ok + " failed=" + fail
        + String.format(" (%.1f%% success)", 100.0 * ok / Math.max(1, ok + fail)));
}

// ---------- 步骤 3：三策略建函数 ----------
if (argStep.equals("all") || argStep.equals("funcs")) {
    int total = 0;

    // 3a. bl/b 目标
    Set<Address> callTargets = new TreeSet<>();
    InstructionIterator it = listing.getInstructions(new AddressSet(start, end), true);
    while (it.hasNext()) {
        Instruction insn = it.next();
        String mn = insn.getMnemonicString();
        if (!mn.equals("bl") && !mn.equals("b")) continue;
        Address[] flows = insn.getFlows();
        if (flows == null) continue;
        for (Address t : flows)
            if (t.compareTo(start) >= 0 && t.compareTo(end) <= 0) callTargets.add(t);
    }
    int c1 = 0;
    for (Address t : callTargets) {
        if (getFunctionAt(t) != null) continue;
        if (listing.getInstructionAt(t) == null) continue;
        try { createFunction(t, null); c1++; } catch (Exception e) { }
    }
    total += c1;
    println("[3a] from bl/b targets: +" + c1 + " (targets=" + callTargets.size() + ")");

    // 3b. adrp 指向代码区
    Set<Address> adrpCand = new TreeSet<>();
    it = listing.getInstructions(new AddressSet(start, end), true);
    while (it.hasNext()) {
        Instruction insn = it.next();
        if (!insn.getMnemonicString().equals("adrp")) continue;
        Object[] op = insn.getOpObjects(1);
        if (op.length == 0) continue;
        long page;
        try { page = ((Scalar) op[0]).getUnsignedValue(); } catch (Exception e) { continue; }
        if (page >= start.getOffset() && page <= end.getOffset()) adrpCand.add(insn.getAddress());
    }
    int c2 = 0;
    for (Address t : adrpCand) {
        if (getFunctionContaining(t) != null) continue;
        if (listing.getInstructionAt(t) == null) continue;
        try { createFunction(t, null); c2++; } catch (Exception e) { }
    }
    total += c2;
    println("[3b] from adrp: +" + c2 + " (candidates=" + adrpCand.size() + ")");

    // 3c. 严格入口形态
    int c3 = 0;
    Address a = start;
    while (a.compareTo(end) < 0) {
        Instruction insn = listing.getInstructionAt(a);
        if (insn == null) { a = a.add(4); continue; }
        if (getFunctionContaining(a) == null) {
            String mn = insn.getMnemonicString();
            String s = insn.toString();
            boolean entry = mn.equals("bti") || mn.equals("pacibsp")
                || (mn.equals("stp") && s.contains("x29, x30") && s.contains("]!"));
            // sub sp,sp,#N 且下一条是 stp x29,x30 → 典型帧建立
            if (!entry && mn.equals("sub") && s.contains("sp, sp")) {
                Instruction nx = listing.getInstructionAt(a.add(insn.getLength()));
                if (nx != null && nx.getMnemonicString().equals("stp")
                    && nx.toString().contains("x29, x30")) entry = true;
            }
            if (entry) { try { createFunction(a, null); c3++; } catch (Exception e) { } }
        }
        Address next = a.add(insn.getLength());
        a = (next.compareTo(a) <= 0) ? a.add(4) : next;
    }
    total += c3;
    println("[3c] from entry pattern: +" + c3);
    println("[3] created total: " + total);
}

// ---------- 报告 ----------
long covered = 0;
int nf = 0;
for (Function f : fm.getFunctions(true)) {
    Address ea = f.getEntryPoint();
    if (ea.compareTo(start) >= 0 && ea.compareTo(end) <= 0) {
        covered += f.getBody().getNumAddresses();
        nf++;
    }
}
long span = end.getOffset() - start.getOffset() + 1;
println("=== result ===");
println("  functions total: " + fm.getFunctionCount() + " (in range " + nf + ")");
println(String.format("  code covered: %d / %d (%.1f%%)", covered, span, 100.0 * covered / span));
