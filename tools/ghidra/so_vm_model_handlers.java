// so_vm_model_handlers.java -- extract VM handler instruction model to JSON
//
// For each handler in the opcode table, statically scan and extract:
//   pc_delta    pc advance amount (add xN,xN,#N)
//   key_src     stack slot used as key source (handler-private temp slot)
//   key_const   whether key is forced to 0x3b
//   exit        dispatch / vm_exit / indirect
//   opcodes     opcodes sharing this handler
//
// Output: $TMP/vm_handler_model.json
//
// Prerequisite: so_vm_split_handlers.java already ran
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.*;
import java.util.regex.*;

public class so_vm_model_handlers extends GhidraScript {

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
        File cfgf = new File(tmp, "so_vm_model.cfg");
        Properties cfg = new Properties();
        if (cfgf.isFile()) {
            try (InputStream in = new FileInputStream(cfgf)) {
                cfg.load(in);
            }
        }

        long tableVa = cfgLong(cfg, "table_va", 0x1f3af0L);
        int tableN = (int) cfgLong(cfg, "table_n", 256);
        long rangeHi = cfgLong(cfg, "range_hi", 0x1c474fL);

        Memory mem = currentProgram.getMemory();
        Listing lst = currentProgram.getListing();

        TreeMap<Long, List<Integer>> m = new TreeMap<>();
        for (int i = 0; i < tableN; i++) {
            long v;
            try {
                v = mem.getLong(toAddr(tableVa + i * 8L));
            } catch (Exception e) {
                continue;
            }
            if (v < 0x1bd000L || v > rangeHi) continue;
            m.computeIfAbsent(v, k -> new ArrayList<>()).add(i);
        }
        List<Long> keys = new ArrayList<>(m.keySet());
        println("handlers: " + keys.size());

        Pattern pAdd = Pattern.compile("add x(\\d+),x(\\d+),#0x([0-9a-f]+)");
        Pattern pLdrb = Pattern.compile("ldrb w\\d+,\\[sp, #0x([0-9a-f]+)\\]");
        Pattern pMov = Pattern.compile("mov w9,#0x3b");
        Pattern pB = Pattern.compile("^b\\s+0x([0-9a-f]+)");

        StringBuilder json = new StringBuilder("[\n");
        Map<Integer, Integer> hist = new TreeMap<>();
        int n = 0;

        for (int i = 0; i < keys.size(); i++) {
            long va = keys.get(i);
            long end = (i + 1 < keys.size()) ? keys.get(i + 1) : rangeHi;
            int delta = -1;
            long srcOff = -1;
            boolean keyConst = false;
            String exit = "unknown";
            int insnCount = 0;

            Instruction ins = lst.getInstructionAt(toAddr(va));
            int guard = 0;
            while (ins != null && guard++ < 500) {
                long a = ins.getAddress().getOffset();
                if (a >= end + 0x100) break;
                insnCount++;
                String s = ins.toString().toLowerCase();
                String mn = ins.getMnemonicString().toLowerCase();

                // pc 推进：add xN,xN,#M（源/目标同一寄存器）且随后紧跟
                // b <dispatch|vm_exit>。其它 add（栈调整、key 计算）不算。
                Matcher ma = pAdd.matcher(s);
                if (delta < 0 && ma.find() && ma.group(1).equals(ma.group(2))) {
                    int cand = Integer.parseInt(ma.group(3), 16);
                    Instruction nx = ins.getNext();
                    if (nx != null && nx.getMnemonicString().equalsIgnoreCase("b")) {
                        Matcher mb = pB.matcher(nx.toString().toLowerCase());
                        if (mb.find()) {
                            long tgt = Long.parseLong(mb.group(1), 16);
                            if (tgt == 0x1bd8acL || tgt == 0x1c46e8L) delta = cand;
                        }
                    }
                }
                Matcher ml = pLdrb.matcher(s);
                if (ml.find() && srcOff < 0) {
                    long off = Long.parseLong(ml.group(1), 16);
                    if (off != 0x81c && off != 0x820 && off != 0x82c) srcOff = off;
                }
                if (pMov.matcher(s).find()) keyConst = true;
                if (mn.equals("b")) {
                    String t = s.replace("b ", "").replace("0x", "").trim();
                    try {
                        long tgt = Long.parseLong(t, 16);
                        if (tgt == 0xbd8acL) exit = "dispatch";
                        else if (tgt == 0xc46e8L) exit = "vm_exit";
                    } catch (Exception ignored) {
                    }
                }
                if (mn.equals("br")) exit = "indirect";
                ins = ins.getNext();
            }
            if (delta >= 0) hist.merge(delta, 1, Integer::sum);

            if (n > 0) json.append(",\n");
            json.append(String.format(
                "  {\"entry\":\"0x%x\",\"opcodes\":%s,\"size\":%d,\"insns\":%d,"
                + "\"pc_delta\":%d,\"key_src\":\"%s\",\"key_const\":%s,\"exit\":\"%s\"}",
                va, m.get(va), end - va, insnCount, delta,
                srcOff < 0 ? "-" : String.format("0x%x", srcOff),
                keyConst ? "\"0x3b\"" : "null", exit));
            n++;
        }
        json.append("\n]\n");

        File out = new File(tmp, "vm_handler_model.json");
        try (PrintWriter pw = new PrintWriter(out, "UTF-8")) {
            pw.print(json);
        }
        println("pc_delta hist: " + hist);
        println(String.format("wrote %d handlers -> %s", n, out));
    }
}
