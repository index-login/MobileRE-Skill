// so_vm_analyze_handlers.java — 批量反编译 VM handler 并导出语义特征
//
// 对 opcode 跳转表里的每个 handler：
//   1) 反编译，提取伪代码
//   2) 统计关键特征：栈读写、内存访问、调用、pc 推进、比较分支
//   3) 输出 JSON 到 $TMP/vm_handlers.json
//
// 输出字段：
//   entry      handler 入口
//   opcodes    共用该 handler 的 opcode 列表
//   size       字节大小
//   pc_delta   从伪代码/汇编推断的 pc 推进
//   features   特征标志（stack_push/stack_pop/mem_load/mem_store/call/compare/...）
//   pseudo     伪代码（截断）
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import java.io.File;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.util.*;

public class so_vm_analyze_handlers extends GhidraScript {

    private long cfgLong(Properties p, String k, long dflt) {
        String v = p.getProperty(k);
        if (v == null || v.trim().isEmpty()) return dflt;
        v = v.trim();
        if (v.startsWith("0x") || v.startsWith("0X")) return Long.parseLong(v.substring(2), 16);
        return Long.parseLong(v);
    }

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(' ');
                    else b.append(c);
            }
        }
        return b.toString();
    }

    @Override
    public void run() throws Exception {
        String tmp = System.getenv("TMP");
        if (tmp == null) tmp = System.getProperty("java.io.tmpdir");
        File cfgf = new File(tmp, "so_vm_analyze.cfg");
        Properties cfg = new Properties();
        if (cfgf.isFile()) {
            try (java.io.InputStream in = Files.newInputStream(cfgf.toPath())) {
                cfg.load(in);
            }
        }

        long tableVa = cfgLong(cfg, "table_va", 0x1f3af0L);
        int tableN = (int) cfgLong(cfg, "table_n", 256);
        long rangeHi = cfgLong(cfg, "range_hi", 0x1c474fL);

        Memory mem = currentProgram.getMemory();
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing lst = currentProgram.getListing();

        TreeMap<Long, List<Integer>> m = new TreeMap<>();
        for (int i = 0; i < tableN; i++) {
            long v;
            try {
                v = mem.getLong(toAddr(tableVa + i * 8L));
            } catch (Exception e) {
                continue;
            }
            m.computeIfAbsent(v, k -> new ArrayList<>()).add(i);
        }
        println("handlers: " + m.size());

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);

        StringBuilder json = new StringBuilder();
        json.append("[\n");
        int n = 0, ok = 0;
        List<Long> keys = new ArrayList<>(m.keySet());
        for (int ki = 0; ki < keys.size(); ki++) {
            long va = keys.get(ki);
            List<Integer> ops = m.get(va);
            Address a = toAddr(va);
            Function f = fm.getFunctionAt(a);
            long nextVa = (ki + 1 < keys.size()) ? keys.get(ki + 1) : rangeHi;
            long size = nextVa - va;

            // 汇编特征扫描
            Set<String> feat = new TreeSet<>();
            int pcDelta = -1;
            int insnCount = 0;
            Instruction ins = lst.getInstructionAt(a);
            long scanEnd = Math.min(nextVa, va + 512);
            while (ins != null && ins.getAddress().getOffset() < scanEnd) {
                insnCount++;
                String mn = ins.getMnemonicString().toLowerCase();
                String op = ins.toString().toLowerCase();
                if (mn.equals("ldr") || mn.equals("ldur")) {
                    if (op.contains("[sp") || op.contains("x20")) feat.add("mem_load");
                }
                if (mn.equals("str") || mn.equals("stur")) {
                    if (op.contains("[sp") || op.contains("x20")) feat.add("mem_store");
                }
                if (mn.equals("blr")) feat.add("call");
                if (mn.startsWith("b.") || mn.equals("cbz") || mn.equals("cbnz")
                        || mn.equals("tbz") || mn.equals("tbnz")) feat.add("branch");
                if (mn.equals("cmp") || mn.equals("cmn") || mn.equals("tst")) feat.add("compare");
                if (mn.equals("eor") || mn.equals("and") || mn.equals("orr")) feat.add("bitop");
                if (mn.equals("add") || mn.equals("sub") || mn.equals("mul")
                        || mn.equals("sdiv") || mn.equals("udiv")) feat.add("arith");
                if (mn.equals("fadd") || mn.equals("fsub") || mn.equals("fmul")
                        || mn.equals("fdiv") || mn.equals("fcmp")) feat.add("float");
                if (mn.equals("sxtb") || mn.equals("sxth") || mn.equals("sxtw")
                        || mn.equals("uxtb") || mn.equals("uxth") || mn.equals("uxtw")) feat.add("extend");
                if (mn.equals("ret")) feat.add("ret");
                if (mn.equals("br")) feat.add("indirect_br");
                // pc 推进：add x?,x?,#N  后紧跟 str ...,[sp,#0x820]
                if (mn.equals("add") && op.contains("#")) {
                    // 粗略：记录最后一个 add 立即数
                }
                ins = ins.getNext();
            }

            // 反编译
            String pseudo = "";
            if (f != null) {
                try {
                    DecompileResults dr = dec.decompileFunction(f, 60, monitor);
                    if (dr != null && dr.decompileCompleted() && dr.getDecompiledFunction() != null) {
                        pseudo = dr.getDecompiledFunction().getC();
                        ok++;
                    }
                } catch (Exception e) {
                    pseudo = "";
                }
            }

            // 从伪代码提取 pc 推进（+0x820 相关）
            int pcD = -1;
            if (!pseudo.isEmpty()) {
                java.util.regex.Matcher mm = java.util.regex.Pattern
                        .compile("0x820[^;]*?\\+\\s*(0x[0-9a-fA-F]+|\\d+)").matcher(pseudo);
                if (mm.find()) {
                    try {
                        pcD = Integer.parseInt(mm.group(1).replace("0x", ""), 16);
                    } catch (Exception ignored) {
                    }
                }
            }

            if (n > 0) json.append(",\n");
            json.append("  {\"entry\":").append(String.format("\"0x%x\"", va));
            json.append(",\"opcodes\":").append(ops.toString());
            json.append(",\"size\":").append(size);
            json.append(",\"insns\":").append(insnCount);
            json.append(",\"func\":").append(f == null ? "null" : "\"" + esc(f.getName()) + "\"");
            json.append(",\"features\":[");
            int fi = 0;
            for (String s : feat) {
                if (fi++ > 0) json.append(",");
                json.append("\"").append(s).append("\"");
            }
            json.append("]");
            json.append(",\"pseudo\":\"").append(esc(pseudo)).append("\"}");
            n++;
        }
        json.append("\n]\n");

        File out = new File(tmp, "vm_handlers.json");
        try (PrintWriter pw = new PrintWriter(out, "UTF-8")) {
            pw.print(json);
        }
        println(String.format("导出 %d 个 handler，反编译成功 %d，输出 %s", n, ok, out));
    }
}
