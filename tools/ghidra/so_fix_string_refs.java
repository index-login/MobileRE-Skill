// so_fix_string_refs.java -- convert mid-string DAT_* references to string symbols
//
// Problem: the string decryption routine writes plaintext in place, so after
// decryption the .data region holds real strings ("AnoymousDex", "classes.dex",
// ...). Ghidra's analyzer only recognized some of them as strings; references
// that land in the MIDDLE of a string (e.g. DAT_00209ce1 -> "ex") stay as raw
// DAT_ labels and make pseudocode unreadable.
//
// Strategy:
//   1) Scan every defined data item; for each address referenced from code that
//      is NOT already a string, check whether it falls inside a printable run
//      (>= 4 chars) in the raw bytes.
//   2) Create a proper string data type at the run start, then add a label at
//      the referenced address naming it after the enclosing string.
//
// Config: $TMP/so_fix_strings.cfg
//   apply=1
//   min_len=4
//   region_lo=0x1f0000   Ghidra VA lower bound to scan
//   region_hi=0x21c000   Ghidra VA upper bound
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.*;

public class so_fix_string_refs extends GhidraScript {

    private long cfgLong(Properties p, String k, long dflt) {
        String v = p.getProperty(k);
        if (v == null || v.trim().isEmpty()) return dflt;
        v = v.trim();
        if (v.startsWith("0x") || v.startsWith("0X")) return Long.parseLong(v.substring(2), 16);
        return Long.parseLong(v);
    }

    private boolean printable(byte b) {
        return b >= 0x20 && b < 0x7f;
    }

    @Override
    public void run() throws Exception {
        String tmp = System.getenv("TMP");
        if (tmp == null) tmp = System.getProperty("java.io.tmpdir");
        Properties cfg = new Properties();
        File cfgf = new File(tmp, "so_fix_strings.cfg");
        if (cfgf.isFile()) {
            try (InputStream in = new FileInputStream(cfgf)) { cfg.load(in); }
        }
        boolean apply = "1".equals(cfg.getProperty("apply", "0"));
        int minLen = Integer.parseInt(cfg.getProperty("min_len", "4"));
        long lo = cfgLong(cfg, "region_lo", 0x1f0000L);
        long hi = cfgLong(cfg, "region_hi", 0x21c000L);

        Memory mem = currentProgram.getMemory();
        Listing lst = currentProgram.getListing();
        ReferenceManager rm = currentProgram.getReferenceManager();

        // 1) find all addresses referenced from code that are not strings
        Set<Long> targets = new TreeSet<>();
        for (MemoryBlock blk : mem.getBlocks()) {
            if (!blk.isExecute()) continue;
            for (Address a = blk.getStart(); a != null && a.compareTo(blk.getEnd()) <= 0; ) {
                for (Reference r : rm.getReferencesFrom(a)) {
                    long t = r.getToAddress().getOffset();
                    if (t >= lo && t < hi) targets.add(t);
                }
                Address nxt = a.next();
                if (nxt == null || nxt.compareTo(a) <= 0) break;
                a = nxt;
            }
        }
        println("code-referenced addresses in region: " + targets.size());

        int insideStr = 0, created = 0, labeled = 0;
        List<String> samples = new ArrayList<>();

        for (long t : targets) {
            Address ta = toAddr(t);
            Data d = lst.getDefinedDataAt(ta);
            if (d != null && d.getDataType() instanceof StringDataType) continue;

            // walk backwards to find printable run start
            long start = t;
            long limit = Math.max(lo, t - 512);
            try {
                while (start > limit) {
                    byte b = mem.getByte(toAddr(start - 1));
                    if (!printable(b)) break;
                    start--;
                }
            } catch (Exception e) { continue; }

            // measure run
            long end = t;
            try {
                while (end < hi) {
                    byte b = mem.getByte(toAddr(end));
                    if (!printable(b)) break;
                    end++;
                }
            } catch (Exception e) { continue; }

            long len = end - start;
            if (len < minLen) continue;
            insideStr++;
            String s;
            try {
                byte[] raw = new byte[(int) len];
                mem.getBytes(toAddr(start), raw);
                s = new String(raw, "US-ASCII");
            } catch (Exception e) { continue; }

            if (apply) {
                try {
                    Data existing = lst.getDefinedDataAt(toAddr(start));
                    boolean needCreate = true;
                    if (existing != null) {
                        String tn = existing.getDataType().getName();
                        if (tn.startsWith("string") || tn.startsWith("char")) needCreate = false;
                    }
                    if (needCreate) {
                        // clear whatever placeholder (undefined8/undefined4/...) is there
                        lst.clearCodeUnits(toAddr(start), toAddr(start + len - 1), false);
                        lst.createData(toAddr(start), new StringDataType(), (int) len);
                        created++;
                    }
                    if (t != start) {
                        String lbl = "s_" + s.replaceAll("[^A-Za-z0-9_]", "_");
                        if (lbl.length() > 60) lbl = lbl.substring(0, 60);
                        createLabel(toAddr(t), lbl + "_" + Long.toHexString(t - start), true,
                                SourceType.USER_DEFINED);
                        labeled++;
                    }
                } catch (Exception ignored) {
                }
            } else if (samples.size() < 40) {
                samples.add(String.format("%#x -> \"%s\" (offset +%d, len %d)", t, s, t - start, len));
            }
        }

        println(String.format("insideString=%d created=%d labeled=%d apply=%s",
                insideStr, created, labeled, apply));
        for (String s : samples) println("  " + s);
    }
}
