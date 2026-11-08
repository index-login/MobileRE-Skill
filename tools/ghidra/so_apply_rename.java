// so_apply_rename.java -- batch apply rename proposals from tools/so_ledger.py
//
// Input: a TSV produced by `so_ledger.py --rename`, columns:
//   addr<TAB>old<TAB>new<TAB>reason
// Only mechanical (non-semantic) renames belong here: FFI bridges, thunks,
// tail-calls, single-instruction stubs. Never feed it a name that asserts
// business meaning you have not verified.
//
// Config: $TMP/so_apply_rename.cfg
//   in=<path>        rename TSV (required)
//   apply=1          0 = dry run (default)
//   prefix=<str>     optional, only rename entries whose new name starts with it
//   max_lowconf=0.20 abort if (empty_* + one_*) share of the batch exceeds this
//   max_share=0.30   abort if the batch renames more than this share of all functions
//   force=1          bypass both guards (deliberate full sweep)
//
// Behaviour:
//   - skips rows whose current name already equals the proposed name
//   - skips rows where the current name is NOT a placeholder (guards semantic names
//     that a later pass established)
//   - guards against low-confidence bulk renames: a batch that is mostly
//     `empty_*` / `one_*`, or that touches too large a share of the program,
//     usually means the ledger was built from a packed (non-decrypted) image
//   - reports counts; on apply=1 sets SourceType.USER_DEFINED
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.io.*;
import java.util.*;
import java.util.regex.Pattern;

public class so_apply_rename extends GhidraScript {

    // Placeholder names emitted by the decompiler: safe to batch-rename.
    private static final List<String> PLACEHOLDER = Arrays.asList(
            "FUN_", "leaf_", "frag_", "cff_", "sprintf_inline_", "mprot_");

    // Only "<prefix>_<hex>" counts as a placeholder; "vm_push" is a real name.
    private static final Pattern ADDR_ONLY =
            Pattern.compile("^(vm|dl|ptr|cff|thunk|tail|one)_[0-9a-fA-F]{6,}$");

    private static boolean isPlaceholder(String n) {
        for (String p : PLACEHOLDER) if (n.startsWith(p)) return true;
        return ADDR_ONLY.matcher(n).matches();
    }

    private String cfg(String key, String dflt) {
        String tmp = System.getenv("TMP");
        if (tmp == null) tmp = System.getProperty("java.io.tmpdir");
        File f = new File(tmp, "so_apply_rename.cfg");
        if (!f.isFile()) return dflt;
        Properties p = new Properties();
        try (InputStream in = new FileInputStream(f)) { p.load(in); } catch (Exception e) { return dflt; }
        return p.getProperty(key, dflt);
    }

    @Override
    public void run() throws Exception {
        String inPath = cfg("in", null);
        boolean apply = "1".equals(cfg("apply", "0"));
        boolean force = "1".equals(cfg("force", "0"));
        String prefix = cfg("prefix", "");
        double maxLowConf = Double.parseDouble(cfg("max_lowconf", "0.20"));
        double maxShare = Double.parseDouble(cfg("max_share", "0.30"));

        if (inPath == null) {
            println("ERROR: 缺少配置 in=<rename.tsv>");
            return;
        }

        // ---- pass 1: read + filter, collect stats ----
        List<String[]> rows = new ArrayList<>();
        int total = 0, skippedPrefix = 0, lowConf = 0;
        BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(inPath), "UTF-8"));
        String line = br.readLine();  // header
        while ((line = br.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) continue;
            String[] p = line.split("\t", -1);
            if (p.length < 3) continue;
            total++;
            String newName = p[2].trim();
            if (newName.isEmpty()) continue;
            if (!prefix.isEmpty() && !newName.startsWith(prefix)) { skippedPrefix++; continue; }
            if (newName.startsWith("empty_") || newName.startsWith("one_")) lowConf++;
            rows.add(p);
        }
        br.close();

        int funcTotal = getCurrentProgram().getFunctionManager().getFunctionCount();
        double lowConfShare = rows.isEmpty() ? 0.0 : (double) lowConf / rows.size();
        double batchShare = funcTotal == 0 ? 0.0 : (double) rows.size() / funcTotal;

        println(String.format(
                "so_apply_rename: batch=%d lowconf=%d(%.0f%%) program=%d share=%.0f%%",
                rows.size(), lowConf, lowConfShare * 100, funcTotal, batchShare * 100));

        boolean blocked = false;
        if (!force && lowConfShare > maxLowConf) {
            println(String.format(
                    "ABORT: empty_*/one_* 占 %.0f%% > %.0f%% —— 台账很可能来自未解密的镜像"
                    + "（.text 是密文，函数全被判成桩）。确认无误用 force=1 越过。",
                    lowConfShare * 100, maxLowConf * 100));
            blocked = true;
        }
        if (!force && batchShare > maxShare) {
            println(String.format(
                    "ABORT: 本次改名 %d 条占全部函数 %.0f%% > %.0f%%。首次全量命名可设 force=1。",
                    rows.size(), batchShare * 100, maxShare * 100));
            blocked = true;
        }
        if (blocked) return;

        // ---- pass 2: apply ----
        int renamed = 0, skippedSame = 0, skippedSemantic = 0, skippedMissing = 0, failed = 0;
        for (String[] p : rows) {
            String addrStr = p[0].trim();
            String newName = p[2].trim();

            Address a;
            try {
                a = toAddr(Long.parseLong(addrStr, 16));
            } catch (Exception e) { failed++; continue; }

            Function f = getFunctionAt(a);
            if (f == null) { skippedMissing++; continue; }

            String cur = f.getName();
            if (cur.equals(newName)) { skippedSame++; continue; }
            if (!isPlaceholder(cur)) { skippedSemantic++; continue; }

            if (!apply) { renamed++; continue; }
            try {
                f.setName(newName, SourceType.USER_DEFINED);
                renamed++;
            } catch (Exception e) {
                failed++;
                if (failed <= 5) println("  fail " + addrStr + " -> " + newName + ": " + e.getMessage());
            }
        }

        println(String.format(
                "so_apply_rename: total=%d renamed=%d same=%d semanticGuard=%d missing=%d prefixSkip=%d failed=%d apply=%b",
                total, renamed, skippedSame, skippedSemantic, skippedMissing, skippedPrefix, failed, apply));
    }
}
