// so_split_pointer_targets.java -- 按指针表补建漏掉的函数边界
//
// 问题：Ghidra 自动分析按序言（stp x29,x30 / sub sp,sp,#N）识别函数起点。
// FFI 桩的"第二入口"没有独立序言——它们紧跟在上一段的 ret 之后，只以
// `ldr xN,[x0]` 开头，因此被并入前一个函数的 body。指针表却直接指向它们。
//
// 判据（三条同时满足才拆）：
//   1. 该地址被某个指针表引用
//   2. 该地址落在已有函数 body 内部（不是入口）
//   3. 该地址的首条指令是函数起点特征：
//      ldr xN,[x0]（取第 1 参数）或 stp x30 / str x30,[sp,#-N]!（标准序言）
//
// 拆法：createFunction(addr) 会从该地址起重新界定 body，
// 原函数 body 自动在 addr 前截断。不需要先删原函数。
//
// Config: $TMP/so_split_targets.cfg
//   in=<tsv>      每行 addr<TAB>note（addr 为 Ghidra VA）
//   apply=1       0 = dry run
//   min_gap=8     新入口与原函数入口的最小距离（防止把序言误拆）
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.SourceType;
import java.io.*;
import java.util.*;

public class so_split_pointer_targets extends GhidraScript {

    private String cfg(String key, String dflt) {
        String tmp = System.getenv("TMP");
        if (tmp == null) tmp = System.getProperty("java.io.tmpdir");
        File f = new File(tmp, "so_split_targets.cfg");
        if (!f.isFile()) return dflt;
        Properties p = new Properties();
        try (InputStream in = new FileInputStream(f)) { p.load(in); } catch (Exception e) { return dflt; }
        return p.getProperty(key, dflt);
    }

    /** 函数起点特征：取第 1 参数作帧指针，或标准栈帧序言。 */
    private boolean looksLikeEntry(Instruction ins) {
        if (ins == null) return false;
        String m = ins.getMnemonicString();
        String s = ins.toString().replace(" ", "");
        if (m.equals("ldr") && s.contains(",[x0]")) return true;          // 取 arg0
        if ((m.equals("stp") || m.equals("str")) && s.contains("x30") && s.contains("[sp,#-")) return true;
        if (m.equals("sub") && s.contains("sp,sp,#")) return true;
        if (m.equals("bti")) return true;
        return false;
    }

    @Override
    public void run() throws Exception {
        String inPath = cfg("in", null);
        boolean apply = "1".equals(cfg("apply", "0"));
        long minGap = Long.decode(cfg("min_gap", "8"));

        if (inPath == null) {
            println("ERROR: 缺少配置 in=<tsv>");
            return;
        }

        int total = 0, created = 0, skippedEntry = 0, skippedNoFunc = 0,
                skippedNotEntry = 0, skippedGap = 0, failed = 0;

        BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(inPath), "UTF-8"));
        String line;
        List<String> log = new ArrayList<>();
        while ((line = br.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] p = line.split("\t", -1);
            if (p.length < 1) continue;
            total++;

            Address a;
            try { a = toAddr(Long.parseLong(p[0].trim(), 16)); }
            catch (Exception e) { failed++; continue; }

            Function existing = getFunctionAt(a);
            if (existing != null) { skippedEntry++; continue; }   // 已经是函数入口

            Function owner = getFunctionContaining(a);
            if (owner == null) { skippedNoFunc++; continue; }

            long gap = a.getOffset() - owner.getEntryPoint().getOffset();
            if (gap < minGap) { skippedGap++; continue; }

            Instruction ins = getInstructionAt(a);
            if (!looksLikeEntry(ins)) {
                skippedNotEntry++;
                if (log.size() < 20) log.add(String.format("  notEntry 0x%x in %s: %s",
                        a.getOffset(), owner.getName(), ins == null ? "<no insn>" : ins.toString()));
                continue;
            }

            if (!apply) { created++; continue; }
            try {
                String nm = String.format("ptr_%x", a.getOffset());
                Function nf = createFunction(a, nm);
                if (nf != null) {
                    nf.setName(nm, SourceType.USER_DEFINED);
                    created++;
                } else failed++;
            } catch (Exception e) {
                failed++;
                if (log.size() < 20) log.add("  fail 0x" + Long.toHexString(a.getOffset()) + ": " + e.getMessage());
            }
        }
        br.close();

        println(String.format(
                "so_split_pointer_targets: total=%d created=%d alreadyEntry=%d noOwner=%d notEntry=%d tooClose=%d failed=%d apply=%b",
                total, created, skippedEntry, skippedNoFunc, skippedNotEntry, skippedGap, failed, apply));
        for (String s : log) println(s);
    }
}
