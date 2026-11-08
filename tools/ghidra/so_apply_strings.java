// so_apply_strings.java -- turn plaintext strings in .data into Ghidra symbols
//
// The unpacked image already contains the decrypted strings (ijm_decrypt_strings
// ran during JNI_OnLoad and wrote them into .data). But Ghidra has neither a
// label nor a string data type there, so the decompiler prints
// `DAT_00100b08` instead of `"goldfish"`.
//
// This script walks a data range, finds runs of printable bytes, and for each:
//   - creates a label `g_str_<slug>` (deduplicated)
//   - applies a `char[N]` / `TerminatedStringDataType` at the address
//   - adds an EOL comment with the original text
//
// The decompiler then renders the literal directly, which makes the detection
// functions (`check_qemu_socket`, `dbg_ddm_check`, ...) readable at a glance.
//
// Config: $TMP/so_apply_strings.cfg
//   apply=1
//   lo=0x100000       range start (ELF VA)
//   hi=0x101400       range end   (ELF VA)
//   min_len=3         shortest string to convert
//   prefix=g_str_     label prefix
//   skip_existing=1   do not touch addresses that already have a symbol
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.*;

public class so_apply_strings extends GhidraScript {

    private long cfgLong(Properties p, String k, long dflt) {
        String v = p.getProperty(k);
        if (v == null || v.trim().isEmpty()) return dflt;
        v = v.trim();
        if (v.startsWith("0x") || v.startsWith("0X")) return Long.parseLong(v.substring(2), 16);
        return Long.parseLong(v);
    }

    private String slug(String s) {
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (Character.isLetterOrDigit(c)) b.append(Character.toLowerCase(c));
            else if (b.length() > 0 && b.charAt(b.length() - 1) != '_') b.append('_');
        }
        String r = b.toString();
        while (r.endsWith("_")) r = r.substring(0, r.length() - 1);
        while (r.startsWith("_")) r = r.substring(1);
        if (r.length() > 36) r = r.substring(0, 36);
        return r.isEmpty() ? "str" : r;
    }

    @Override
    public void run() throws Exception {
        String tmp = System.getenv("TMP");
        if (tmp == null) tmp = System.getProperty("java.io.tmpdir");
        Properties cfg = new Properties();
        File cfgf = new File(tmp, "so_apply_strings.cfg");
        if (cfgf.isFile()) {
            try (InputStream in = new FileInputStream(cfgf)) { cfg.load(in); }
        }
        boolean apply = "1".equals(cfg.getProperty("apply", "0"));
        long lo = cfgLong(cfg, "lo", 0x100000L);
        long hi = cfgLong(cfg, "hi", 0x101400L);
        int minLen = (int) cfgLong(cfg, "min_len", 3);
        String prefix = cfg.getProperty("prefix", "g_str_");
        boolean skipExisting = "1".equals(cfg.getProperty("skip_existing", "1"));

        Memory mem = currentProgram.getMemory();
        Listing lst = currentProgram.getListing();
        SymbolTable st = currentProgram.getSymbolTable();
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        // collect candidate strings
        List<long[]> runs = new ArrayList<>();   // {va, len}
        List<String> texts = new ArrayList<>();
        long va = lo;
        while (va < hi) {
            byte b;
            try { b = mem.getByte(toAddr(va)); } catch (Exception e) { va++; continue; }
            if (b < 32 || b >= 127) { va++; continue; }
            long start = va;
            StringBuilder sb = new StringBuilder();
            while (va < hi) {
                byte c;
                try { c = mem.getByte(toAddr(va)); } catch (Exception e) { break; }
                if (c < 32 || c >= 127) break;
                sb.append((char) (c & 0xFF));
                va++;
            }
            // only accept NUL-terminated runs -- fragments inside a longer
            // encrypted blob look printable but are noise
            boolean terminated = false;
            try { terminated = (mem.getByte(toAddr(va)) == 0); } catch (Exception ignored) { }
            // drop runs whose first bytes are non-ASCII junk glued onto a
            // real string (e.g. "FhM" + "ro.yunos.build.version"),
            // and drop fragments that start inside another string
            String text = sb.toString();
            boolean glued = false;
            if (start > 0) {
                try {
                    byte pb = mem.getByte(toAddr(start - 1));
                    glued = (pb >= 32 && pb < 127);   // previous byte printable => fragment
                } catch (Exception ignored) { }
            }
            if (!glued && text.matches("^[A-Za-z0-9_/.(\\[].*")) {
                if (sb.length() >= minLen && terminated) {
                    runs.add(new long[]{start, sb.length()});
                    texts.add(text);
                }
            }
            // 跳过整条串，避免把长串切碎成多个 16 字节块
            if (terminated) va++;
        }
        println("候选字符串: " + runs.size());

        if (!apply) {
            for (int i = 0; i < Math.min(runs.size(), 40); i++) {
                println(String.format("  %#x  len=%-3d %s",
                        runs.get(i)[0], runs.get(i)[1], texts.get(i)));
            }
            println("dry run -- set apply=1 in $TMP/so_apply_strings.cfg");
            return;
        }

        // 先把整个区间清空，避免残留的 16 字节碎块干扰
        try {
            Address alo = toAddr(lo);
            Address ahi = toAddr(hi - 1);
            Data firstData = lst.getDataContaining(alo);
            if (firstData != null && firstData.getAddress().compareTo(alo) < 0) {
                alo = firstData.getAddress();
            }
            lst.clearCodeUnits(alo, ahi, false);
            println("cleared range " + alo + ".." + ahi);
        } catch (Exception e) {
            println("clear range failed: " + e);
        }

        Set<String> used = new HashSet<>();
        int made = 0, skipped = 0, failed = 0;
        List<String> errs = new ArrayList<>();

        for (int i = 0; i < runs.size(); i++) {
            long start = runs.get(i)[0];
            int len = (int) runs.get(i)[1];
            String text = texts.get(i);
            Address a = toAddr(start);

            Symbol existing = st.getPrimarySymbol(a);
            if (skipExisting && existing != null
                    && existing.getName().startsWith("g_str_")) {
                skipped++;
                continue;
            }

            String name = prefix + slug(text);
            int dup = 2;
            String base = name;
            while (used.contains(name)) name = base + "_" + (dup++);
            used.add(name);

            try {
                // clear whatever Ghidra thinks is here, then lay down a string
                Data old = lst.getDataAt(a);
                if (old != null) lst.clearCodeUnits(a, old.getMaxAddress(), false);
                // also clear any stale unit that starts before us and overlaps
                Data prev = lst.getDataContaining(a);
                if (prev != null && prev.getAddress().compareTo(a) < 0) {
                    lst.clearCodeUnits(prev.getAddress(), prev.getMaxAddress(), false);
                }

                // 建 char[len] 数据（Ghidra 会据此推断出字符串语义），
                // 但符号本身保持 g_str_* 形式，反编译器打印 g_str_xxx
                DataType dt = new ArrayDataType(CharDataType.dataType, len, 1, dtm);
                lst.createData(a, dt);
                // Ghidra auto-creates `s_<text>_<addr>`; rename it to the clean
                // `s_<slug>` form so the decompiler prints a readable identifier
                Symbol auto = st.getPrimarySymbol(a);
                if (auto != null) {
                    try { auto.setName(name, SourceType.USER_DEFINED); } catch (Exception ignored) { }
                } else {
                    try { st.createLabel(a, name, SourceType.USER_DEFINED); } catch (Exception ignored) { }
                }
                lst.setComment(a, CommentType.EOL, "decrypted string");
                made++;
            } catch (Exception e) {
                failed++;
                if (errs.size() < 10) errs.add(String.format("%#x %s: %s", start, text, e.getMessage()));
            }
        }

        println(String.format("created=%d skipped=%d failed=%d", made, skipped, failed));
        for (String s : errs) println("  " + s);
    }
}
