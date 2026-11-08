// so_name_from_strings.java -- name functions from the strings they reference
//
// Most remaining FUN_/leaf_/frag_ functions have no symbol but do reference
// distinctive string literals. Naming them from the strongest anchor turns a
// wall of FUN_0014xxxx into something readable.
//
// The first version of this script produced noise (load_libc_1..9) because it
// accepted any string reference. This version only accepts anchors that carry
// information, and rejects anchors already claimed by another function.
//
// Accepted anchors, highest value first:
//   proc path        /proc/... /sys/... -> proc_<tail>
//   library name     libfoo.so          -> load_<foo>       (only if distinctive)
//   dlsym target     a real symbol name -> dlsym_<sym>
//   java class path  com/foo/Bar        -> jni_<Bar>
//   log tag          FOO_TAG             -> tag_<foo>
//
// Rejected: libc/libm/libdl/libart/libdvm/liblog (too common), format strings,
// single words under 5 chars, strings already used as another function's name.
//
// Config: $TMP/so_name_from_strings.cfg
//   apply=1
//   min_score=5
//   min_refs=1     how many string refs a function must have
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.*;
import java.util.regex.*;

public class so_name_from_strings extends GhidraScript {

    /** Libraries whose name alone says nothing about the caller. */
    private static final Set<String> GENERIC_LIBS = new HashSet<>(Arrays.asList(
            "libc", "libm", "libdl", "libart", "libdvm", "liblog", "libz",
            "libstdc++", "libutils", "libcutils", "libbinder", "libandroid"));

    private static final Pattern PROC = Pattern.compile("^/(proc|sys)/([A-Za-z0-9_./-]{3,})$");
    private static final Pattern LIB  = Pattern.compile("^(lib)?([A-Za-z0-9_+-]{3,})\\.so$");
    private static final Pattern JAVA = Pattern.compile("^(L)?([a-z][A-Za-z0-9_]*(/[A-Za-z0-9_$]+){2,});?$");
    private static final Pattern TAG  = Pattern.compile("^[A-Z][A-Z0-9_]{4,24}$");
    private static final Pattern SYM  = Pattern.compile("^[A-Za-z_][A-Za-z0-9_]{5,40}$");

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
        if (r.length() > 30) r = r.substring(0, 30);
        return r;
    }

    private boolean isGenerated(String n) {
        return n.startsWith("FUN_") || n.startsWith("leaf_") || n.startsWith("frag_")
                || n.startsWith("tail_") || n.startsWith("cff_") || n.startsWith("dl_");
    }

    private String anchor(String s, int minScore) {
        if (s == null) return null;
        s = s.trim();
        if (s.length() < minScore || s.length() > 120) return null;
        if (s.contains("%s") || s.contains("%d")) return null;
        if (s.matches("^[0-9a-fA-F ,:./-]+$")) return null;

        Matcher m;
        if ((m = PROC.matcher(s)).matches()) {
            String tail = m.group(2).replace('/', '_');
            String sl = slug(tail);
            return sl.length() >= 3 ? "proc_" + sl : null;
        }
        if ((m = LIB.matcher(s)).matches()) {
            String base = m.group(2).toLowerCase();
            if (GENERIC_LIBS.contains("lib" + base) || GENERIC_LIBS.contains(base)) return null;
            String sl = slug(base);
            return sl.length() >= 4 ? "load_" + sl : null;
        }
        if ((m = JAVA.matcher(s)).matches()) {
            String path = m.group(2);
            if (path.startsWith("java/") || path.startsWith("android/")) return null;
            String tail = path.substring(path.lastIndexOf('/') + 1).replace("$", "_");
            String sl = slug(tail);
            return sl.length() >= 4 ? "jni_" + sl : null;
        }
        if (TAG.matcher(s).matches()) {
            String sl = slug(s);
            return sl.length() >= 4 ? "tag_" + sl : null;
        }
        return null;
    }

    @Override
    public void run() throws Exception {
        String tmp = System.getenv("TMP");
        if (tmp == null) tmp = System.getProperty("java.io.tmpdir");
        Properties cfg = new Properties();
        File cfgf = new File(tmp, "so_name_from_strings.cfg");
        if (cfgf.isFile()) {
            try (InputStream in = new FileInputStream(cfgf)) { cfg.load(in); }
        }
        boolean apply = "1".equals(cfg.getProperty("apply", "0"));
        int minScore = (int) cfgLong(cfg, "min_score", 5);

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing lst = currentProgram.getListing();

        Map<Long, String> anchors = new HashMap<>();
        DataIterator di = lst.getDefinedData(true);
        int scanned = 0;
        while (di.hasNext()) {
            Data d = di.next();
            if (!(d.getValue() instanceof String)) continue;
            scanned++;
            String s;
            try { s = (String) d.getValue(); } catch (Exception e) { continue; }
            String nm = anchor(s, minScore);
            if (nm != null) anchors.put(d.getAddress().getOffset(), nm);
        }
        println("string data scanned=" + scanned + " anchors=" + anchors.size());

        int renamed = 0, considered = 0, failed = 0, noAnchor = 0;
        Set<String> used = new HashSet<>();
        for (Function f : fm.getFunctions(true)) used.add(f.getName());

        List<String> samples = new ArrayList<>();
        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.isExternal() || f.isThunk()) continue;
            String cur = f.getName();
            if (!isGenerated(cur)) continue;
            considered++;

            // count distinct anchors referenced from the body
            Map<String, Integer> hits = new HashMap<>();
            Instruction ins = lst.getInstructionAt(f.getEntryPoint());
            int guard = 0;
            while (ins != null && guard++ < 4000 && f.getBody().contains(ins.getAddress())) {
                for (Reference r : ins.getReferencesFrom()) {
                    String cand = anchors.get(r.getToAddress().getOffset());
                    if (cand != null) hits.merge(cand, 1, Integer::sum);
                }
                ins = ins.getNext();
            }
            if (hits.isEmpty()) { noAnchor++; continue; }

            // pick the anchor with the most references, tie-break on longer name
            String best = null;
            int bestN = -1;
            for (Map.Entry<String, Integer> e : hits.entrySet()) {
                if (e.getValue() > bestN ||
                        (e.getValue() == bestN && best != null && e.getKey().length() > best.length())) {
                    best = e.getKey();
                    bestN = e.getValue();
                }
            }
            String name = best;
            int dup = 2;
            while (used.contains(name)) name = best + "_" + (dup++);
            used.add(name);

            if (samples.size() < 30) {
                samples.add(String.format("%-22s -> %-30s (%d refs)", cur, name, bestN));
            }
            if (!apply) { renamed++; continue; }
            try {
                f.setName(name, SourceType.USER_DEFINED);
                renamed++;
            } catch (Exception e) {
                failed++;
            }
        }

        println(String.format("considered=%d renamed=%d no_anchor=%d failed=%d apply=%s",
                considered, renamed, noAnchor, failed, apply));
        for (String s : samples) println("  " + s);
    }
}
