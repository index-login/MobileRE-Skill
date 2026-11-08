/**
 * so_vm_opcodes.java — VM opcode 分派表标注（Ghidra）
 *
 * 适用：栈式字节码 VM 的 so，已知 opcode 分派表地址。
 *
 * 做什么：
 *   1) 读分派表（256 项 × 8 字节指针）
 *   2) 统计唯一 handler 及其对应 opcode 集合
 *   3) 按指令序列模式推断 handler 语义类别
 *   4) 给 handler 加标签（vmop_<opcodes>）+ plate 注释（语义类别）
 *
 * 为什么不建成函数：
 *   VM handler 大多是 switch case 块，同一函数内的分支目标。
 *   强行 createFunction 会破坏 switch 结构，导致反编译退化。
 *   加标签 + 注释即可在伪代码里看到语义名。
 *
 * 实测（表 @0x1f3af0）：
 *   228 个唯一 handler，全部标注成功
 *   分类：arith_add 62 / arith_sub 50 / compare 22 / load 31 /
 *         shift 14 / muldiv 10 / xor 2 / store 2 / other 35
 *
 * 配置：$TMP/so_vm_opcodes.cfg
 *   table=0x1f3af0     # 分派表 VA
 *   count=256          # 表项数
 *   apply=1
 */

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

// ---------- 配置 ----------
long tableVa = -1;
int count = 256;
boolean apply = true;
File cfg = new File(System.getProperty("java.io.tmpdir"), "so_vm_opcodes.cfg");
if (cfg.exists()) {
    BufferedReader br = new BufferedReader(new FileReader(cfg));
    String ln;
    while ((ln = br.readLine()) != null) {
        ln = ln.trim();
        if (ln.isEmpty() || ln.startsWith("#")) continue;
        int eq = ln.indexOf('=');
        if (eq < 0) continue;
        String k = ln.substring(0, eq).trim(), v = ln.substring(eq + 1).trim();
        if (k.equals("table")) tableVa = Long.decode(v);
        else if (k.equals("count")) count = Integer.parseInt(v);
        else if (k.equals("apply")) apply = v.equals("1");
    }
    br.close();
}
if (tableVa < 0) { print("ERROR: table not configured"); return; }

Listing lst = currentProgram.getListing();
FunctionManager fm = currentProgram.getFunctionManager();
Memory mem = currentProgram.getMemory();
SymbolTable st = currentProgram.getSymbolTable();
AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();

// ---------- 读分派表 ----------
long[] handlers = new long[count];
for (int i = 0; i < count; i++) {
    try { handlers[i] = mem.getLong(sp.getAddress(tableVa + i * 8L)) & 0xffffffffffffL; }
    catch (Exception e) { handlers[i] = -1; }
}

Map<Long, List<Integer>> byHandler = new TreeMap<>();
for (int i = 0; i < count; i++) {
    if (handlers[i] < 0) continue;
    byHandler.computeIfAbsent(handlers[i], k -> new ArrayList<>()).add(i);
}

// ---------- 语义分类 ----------
Map<String, Integer> counts = new TreeMap<>();
int labeled = 0, annotated = 0, skipped = 0;

for (Map.Entry<Long, List<Integer>> e : byHandler.entrySet()) {
    long addr = e.getKey();
    List<Integer> ops = e.getValue();
    Address a = sp.getAddress(addr);

    // 收集指令序列用于分类
    StringBuilder seq = new StringBuilder();
    Address c = a;
    int n = 0;
    while (c != null && n < 10) {
        Instruction x = lst.getInstructionAt(c);
        if (x == null) break;
        String m = x.getMnemonicString();
        if (m.equals("ldr") || m.equals("str") || m.equals("ldrb") || m.equals("strb")
            || m.equals("add") || m.equals("sub") || m.equals("eor") || m.equals("and")
            || m.equals("orr") || m.equals("lsl") || m.equals("asr") || m.equals("cmp")
            || m.equals("mul") || m.equals("sdiv") || m.equals("udiv")) {
            seq.append(m).append(" ");
        }
        c = c.add(x.getLength());
        n++;
    }
    String s = seq.toString();
    String cls;
    if (s.contains("mul") || s.contains("sdiv") || s.contains("udiv")) cls = "arithmetic_muldiv";
    else if (s.contains("eor")) cls = "bitwise_xor";
    else if (s.contains("and") && s.contains("orr")) cls = "bitwise_andor";
    else if (s.contains("lsl") || s.contains("asr")) cls = "shift";
    else if (s.contains("cmp")) cls = "compare";
    else if (s.contains("sub")) cls = "arith_sub";
    else if (s.contains("add")) cls = "arith_add";
    else if (s.startsWith("ldr ldr ldr str")) cls = "store";
    else if (s.startsWith("ldr ldr ldr ldr")) cls = "load";
    else cls = "other";
    counts.merge(cls, 1, Integer::sum);

    if (!apply) { labeled++; continue; }

    // 命名：vmop_<前4个opcode hex>
    StringBuilder name = new StringBuilder("vmop_");
    int lim = Math.min(ops.size(), 4);
    for (int i = 0; i < lim; i++) {
        if (i > 0) name.append("_");
        name.append(String.format("%02x", ops.get(i)));
    }
    try {
        Function f = fm.getFunctionAt(a);
        if (f != null) {
            if (f.getName().startsWith("FUN_") || f.getName().startsWith("cff_")
                || f.getName().startsWith("leaf_") || f.getName().startsWith("caseD_")) {
                f.setName(name.toString(), SourceType.USER_DEFINED);
                labeled++;
            } else skipped++;
        } else {
            Symbol ex = st.getPrimarySymbol(a);
            if (ex == null) { st.createLabel(a, name.toString(), SourceType.USER_DEFINED); labeled++; }
            else if (ex.getName().startsWith("LAB_") || ex.getName().startsWith("caseD_")) {
                ex.setName(name.toString(), SourceType.USER_DEFINED);
                labeled++;
            } else skipped++;
        }
        lst.setComment(a, CommentType.PLATE,
            "VM opcode handler: " + cls + " (opcodes " + ops + ")");
        annotated++;
    } catch (Exception ex2) { skipped++; }
}

StringBuilder log = new StringBuilder();
log.append("=== so_vm_opcodes ===\n");
log.append("table=").append(String.format("%x", tableVa)).append(" count=").append(count).append("\n");
log.append("distinctHandlers=").append(byHandler.size()).append("\n");
log.append("labeled=").append(labeled).append(" annotated=").append(annotated).append(" skipped=").append(skipped).append("\n");
log.append("=== semantic classes ===\n");
for (Map.Entry<String, Integer> e : counts.entrySet()) {
    log.append(String.format("  %-22s %d\n", e.getKey(), e.getValue()));
}
print(log.toString());
