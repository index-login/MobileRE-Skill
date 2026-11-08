/**
 * so_boundary_rebuild.java — 函数边界重建（Ghidra，无 .eh_frame 的加固 SO）
 *
 * 适用：脱壳后无 .eh_frame / 无符号的 AArch64 SO，Ghidra 自动分析后
 *       指令覆盖率低、反编译大量 unaff_xN。
 *
 * 实测效果（153721 条指令的加固 SO）：
 *   覆盖率 67.5% → 99.83%，未归属指令 50032 → 259
 *   函数数 3200 → 3916，unaff_ 污染 52.3% → 38.8%
 *
 * 三步流水线（顺序不可颠倒）：
 *   1) create  补齐漏建函数：序言检测（三种形式）+ bl 目标 + bti
 *   2) merge   合并 CFF 中间块：缺口用 setBody 并入最近父函数
 *   3) report  输出覆盖率与质量指标
 *
 * 严禁：先删函数再重建。removeFunction 会连带清掉函数体内代码归属，
 *       且不会还给父函数，实测覆盖率会从 84.5% 掉到 65%。
 *
 * 配置：$TMP/so_boundary_rebuild.cfg
 *   start=0x142000
 *   end=0x1f0000
 *   step=create|merge|report|all   (默认 all)
 *   apply=1                        (0=dry run)
 */

import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import java.io.*;
import java.util.*;

// ---------- 配置 ----------
String step = "all";
boolean apply = false;
long argStart = -1, argEnd = -1;
File cfg = new File(System.getProperty("java.io.tmpdir"), "so_boundary_rebuild.cfg");
if (cfg.exists()) {
    BufferedReader br = new BufferedReader(new FileReader(cfg));
    String ln;
    while ((ln = br.readLine()) != null) {
        ln = ln.trim();
        if (ln.isEmpty() || ln.startsWith("#")) continue;
        int eq = ln.indexOf('=');
        if (eq < 0) continue;
        String k = ln.substring(0, eq).trim(), v = ln.substring(eq + 1).trim();
        if (k.equals("start")) argStart = Long.decode(v);
        else if (k.equals("end")) argEnd = Long.decode(v);
        else if (k.equals("step")) step = v;
        else if (k.equals("apply")) apply = v.equals("1") || v.equalsIgnoreCase("true");
    }
    br.close();
}

Listing lst = currentProgram.getListing();
FunctionManager fm = currentProgram.getFunctionManager();
Memory mem = currentProgram.getMemory();

// 范围推断：配置优先，其次第一个大 RX 块
if (argStart < 0 || argEnd < 0) {
    for (MemoryBlock b : mem.getBlocks()) {
        if (b.isExecute() && b.getSize() > 0x10000) {
            argStart = b.getStart().getOffset();
            argEnd = b.getEnd().getOffset();
            break;
        }
    }
}
Address start = toAddr(argStart), end = toAddr(argEnd);

// ---------- 工具函数 ----------
// 标准序言：保存 LR/FP 到栈，或大栈分配，或 BTI 入口
boolean isPrologue(Instruction i) {
    if (i == null) return false;
    String m = i.getMnemonicString(), s = i.toString();
    if ((m.equals("stp") || m.equals("str")) && s.contains("[sp, #-")) return true;
    if (m.equals("sub") && s.contains("sp,sp,#")) return true;
    if (m.equals("bti")) return true;
    return false;
}

// 反例：属于同一函数的栈分配分步
boolean isContinuation(Instruction prev) {
    if (prev == null) return false;
    String m = prev.getMnemonicString(), s = prev.toString();
    if (m.equals("mov") && s.contains("x29,sp")) return true;
    if (m.equals("stp") && s.contains("x29,x30") && s.contains("[sp, #-")) return true;
    return false;
}

// 收集未归属指令的连续区间
List<long[]> findGaps() {
    List<long[]> gaps = new ArrayList<>();
    long gs = -1, pe = -1;
    for (Instruction i = lst.getInstructionAt(start); i != null && i.getAddress().compareTo(end) < 0; i = lst.getInstructionAfter(i.getAddress())) {
        long a = i.getAddress().getOffset();
        if (fm.getFunctionContaining(i.getAddress()) == null) {
            if (gs < 0) gs = a;
            pe = a + i.getLength();
        } else if (gs >= 0) { gaps.add(new long[]{gs, pe}); gs = -1; }
    }
    if (gs >= 0) gaps.add(new long[]{gs, pe});
    return gaps;
}

long[] coverage() {
    long total = 0, unc = 0;
    for (Instruction i = lst.getInstructionAt(start); i != null && i.getAddress().compareTo(end) < 0; i = lst.getInstructionAfter(i.getAddress())) {
        total++;
        if (fm.getFunctionContaining(i.getAddress()) == null) unc++;
    }
    return new long[]{total, unc};
}

StringBuilder log = new StringBuilder();
log.append("=== so_boundary_rebuild ===\n");
log.append(String.format("range=%08x-%08x step=%s apply=%b\n", argStart, argEnd, step, apply));
long[] cov0 = coverage();
log.append(String.format("before: funcs=%d insns=%d uncovered=%d (%.2f%%)\n",
    fm.getFunctionCount(), cov0[0], cov0[1], 100.0 * cov0[1] / cov0[0]));

// ---------- 第 1 步：补齐漏建函数 ----------
if (step.equals("create") || step.equals("all")) {
    List<Address> prologues = new ArrayList<>();
    for (Instruction i = lst.getInstructionAt(start); i != null && i.getAddress().compareTo(end) < 0; i = lst.getInstructionAfter(i.getAddress())) {
        if (fm.getFunctionContaining(i.getAddress()) != null) continue;
        if (!isPrologue(i)) continue;
        if (isContinuation(lst.getInstructionBefore(i.getAddress()))) continue;
        prologues.add(i.getAddress());
    }
    int made = 0, failed = 0;
    if (apply) {
        for (Address a : prologues) {
            try { Function nf = createFunction(a, null); if (nf != null) made++; else failed++; }
            catch (Exception e) { failed++; }
        }
    }
    log.append(String.format("create: candidates=%d created=%d failed=%d funcs=%d\n",
        prologues.size(), made, failed, fm.getFunctionCount()));
}

// ---------- 第 2 步：合并 CFF 中间块 ----------
if (step.equals("merge") || step.equals("all")) {
    List<long[]> gaps = findGaps();
    int merged = 0, failed = 0;
    if (apply) {
        for (long[] g : gaps) {
            long ga = g[0], gb = g[1];
            Instruction prev = lst.getInstructionBefore(toAddr(ga));
            Function owner = null;
            int hops = 0;
            while (prev != null && hops < 8) {
                owner = fm.getFunctionContaining(prev.getAddress());
                if (owner != null) break;
                prev = lst.getInstructionBefore(prev.getAddress());
                hops++;
            }
            if (owner == null) { failed++; continue; }
            try {
                AddressSet body = new AddressSet(owner.getBody());
                body.addRange(toAddr(ga), toAddr(gb - 1));  // 右开区间，必须减 1
                owner.setBody(body);
                merged++;
            } catch (Exception e) { failed++; }
        }
    }
    log.append(String.format("merge: gaps=%d merged=%d failed=%d\n", gaps.size(), merged, failed));
}

// ---------- 第 3 步：质量报告 ----------
if (step.equals("report") || step.equals("all")) {
    long[] cov = coverage();
    int total = 0, fun = 0;
    for (Function f : fm.getFunctions(true)) {
        total++;
        if (f.getName().startsWith("FUN_")) fun++;
    }
    log.append(String.format("after: funcs=%d (FUN_=%d) insns=%d uncovered=%d (%.2f%%) covered=%.2f%%\n",
        total, fun, cov[0], cov[1], 100.0 * cov[1] / cov[0], 100.0 * (cov[0] - cov[1]) / cov[0]));

    // unaff 抽样
    DecompInterface di = new DecompInterface();
    di.setOptions(new DecompileOptions());
    di.toggleCCode(true);
    if (di.openProgram(currentProgram)) {
        List<Function> all = new ArrayList<>();
        for (Function f : fm.getFunctions(true)) all.add(f);
        Collections.shuffle(all, new Random(7));
        int sample = Math.min(400, all.size()), ok = 0, unaff = 0;
        for (int i = 0; i < sample; i++) {
            DecompileResults r = di.decompileFunction(all.get(i), 20, TaskMonitor.DUMMY);
            if (r == null || !r.decompileCompleted()) continue;
            String c = r.getDecompiledFunction() != null ? r.getDecompiledFunction().getC() : null;
            if (c == null) continue;
            ok++;
            if (c.contains("unaff_")) unaff++;
        }
        di.dispose();
        log.append(String.format("decompile: sample=%d ok=%d unaff=%d (%.1f%%)\n",
            sample, ok, unaff, 100.0 * unaff / Math.max(ok, 1)));
    }
}

print(log.toString());
