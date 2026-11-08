// so_vm_name_handlers.java — 按 opcode 跳转表给 VM handler 函数命名 + 语义注释
//
// 前置：so_vm_split_handlers.java 已把大函数按表项拆成独立函数。
// 本脚本用 opcode 跳转表反查「handler -> opcode 列表」，重命名为 vm_op_<hex>，
// 并把语义名写进 plate comment（语义名来自 profile 的 opcodes 字段）。
//
// 参数（$TMP/so_vm_name.cfg）：
//   table_va    跳转表 vaddr
//   table_n     表项数
//   names       opcode->语义名，格式 "0x39=ld64,0x3f=st64,..."
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import java.io.File;
import java.nio.file.Files;
import java.util.*;

public class so_vm_name_handlers extends GhidraScript {

    private long cfgLong(Properties p, String k, long dflt) {
        String v = p.getProperty(k);
        if (v == null || v.trim().isEmpty()) return dflt;
        v = v.trim();
        if (v.startsWith("0x") || v.startsWith("0X")) return Long.parseLong(v.substring(2), 16);
        return Long.parseLong(v);
    }

    @Override
    public void run() throws Exception {
        String tmp = System.getenv("TMP");
        if (tmp == null) tmp = System.getProperty("java.io.tmpdir");
        File cfgf = new File(tmp, "so_vm_name.cfg");
        Properties cfg = new Properties();
        if (cfgf.isFile()) {
            try (java.io.InputStream in = Files.newInputStream(cfgf.toPath())) {
                cfg.load(in);
            }
        }

        long tableVa = cfgLong(cfg, "table_va", 0x1f3af0L);
        int tableN = (int) cfgLong(cfg, "table_n", 256);

        // 语义名表：0x39=ld64,0x3f=st64,...
        Map<Integer, String> sem = new HashMap<>();
        String namesSpec = cfg.getProperty("names", "");
        for (String part : namesSpec.split(",")) {
            part = part.trim();
            if (part.isEmpty()) continue;
            int eq = part.indexOf('=');
            if (eq <= 0) continue;
            String k = part.substring(0, eq).trim();
            String v = part.substring(eq + 1).trim();
            try {
                int op = k.startsWith("0x") || k.startsWith("0X")
                        ? Integer.parseInt(k.substring(2), 16)
                        : Integer.parseInt(k);
                sem.put(op, v);
            } catch (NumberFormatException ignored) {
            }
        }
        println("语义名条数: " + sem.size());

        Memory mem = currentProgram.getMemory();
        FunctionManager fm = currentProgram.getFunctionManager();

        // handler -> opcode 列表
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

        int renamed = 0, missing = 0;
        for (Map.Entry<Long, List<Integer>> e : m.entrySet()) {
            Address a = toAddr(e.getKey());
            Function f = fm.getFunctionAt(a);
            if (f == null) {
                missing++;
                continue;
            }
            List<Integer> ops = e.getValue();
            // 名字取第一个有语义名的 opcode；没有就用第一个
            Integer pick = null;
            for (Integer op : ops) {
                if (sem.containsKey(op)) {
                    pick = op;
                    break;
                }
            }
            if (pick == null) pick = ops.get(0);
            String sname = sem.getOrDefault(pick, "");
            String nm = sname.isEmpty()
                    ? String.format("vm_op_%02x", pick)
                    : String.format("vm_%s_op%02x", sname, pick);
            try {
                f.setName(nm, SourceType.USER_DEFINED);
            } catch (Exception ex) {
                continue;
            }
            StringBuilder c = new StringBuilder();
            c.append("VM opcode handler\n");
            c.append("opcodes: ");
            for (int i = 0; i < ops.size(); i++) {
                int op = ops.get(i);
                if (i > 0) c.append(", ");
                c.append(String.format("0x%02x", op));
                String s = sem.get(op);
                if (s != null) c.append("(").append(s).append(")");
            }
            c.append("\nentry: ").append(String.format("%#x", e.getKey()));
            try {
                f.setComment(c.toString());
            } catch (Exception ignored) {
            }
            renamed++;
        }
        println(String.format("已命名 handler %d 个，未找到函数 %d 个", renamed, missing));
    }
}
