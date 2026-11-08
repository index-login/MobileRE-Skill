// ===== REJECTED（已否决，仅留档复核）=====
// 否决原因：碎片合并会过度 —— 实测把 0x1bd8a8..0x1c474f（26 KB）整块并成一个函数，
// 之后必须按跳转表重新拆分。正确做法是先 createFunction 再让原函数自动截断。
// 结论见 references/so-analysis-pipeline.md >「失败方案（不要重走）」。
// so_merge_orphan_frags.java -- merge orphan basic-block fragments back into parents
//
// Problem: so_boundary_rebuild.java over-split some functions, creating
// standalone "frag_*" functions from interior basic blocks. These fragments
// have no prologue, so Ghidra decompiles them with unaff_x19/x24/x29 noise
// (registers inherited from the parent).
//
// Strategy:
//   1) Find functions whose entry has NO prologue (no stp x29/x30, no sub sp,sp,
//      no str x30) AND whose only references come from a single parent function
//      that DOES have a prologue.
//   2) Remove the fragment function and extend the parent's body to cover it.
//   3) Skip true leaves (bti/br/cbz-only, no incoming refs from a prologued fn)
//      and CFF dispatch blocks (referenced from multiple parents).
//
// Config: $TMP/so_merge_frags.cfg
//   apply=1        dry run when 0
//   max_gap=0x40   max byte gap allowed between parent body and fragment
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.*;

public class so_merge_orphan_frags extends GhidraScript {

    private boolean hasPrologue(Listing lst, Address entry) {
        Instruction ins = lst.getInstructionAt(entry);
        int k = 0;
        while (ins != null && k < 4) {
            String s = ins.toString();
            if (s.startsWith("stp") && s.contains("x29") && s.contains("x30")) return true;
            if (s.startsWith("sub") && s.contains("sp,sp,")) return true;
            if (s.startsWith("str") && s.contains("x30")) return true;
            if (s.startsWith("bti") || s.startsWith("nop")) { ins = ins.getNext(); k++; continue; }
            break;
        }
        return false;
    }

    @Override
    public void run() throws Exception {
        String tmp = System.getenv("TMP");
        if (tmp == null) tmp = System.getProperty("java.io.tmpdir");
        Properties cfg = new Properties();
        File cfgf = new File(tmp, "so_merge_frags.cfg");
        if (cfgf.isFile()) {
            try (InputStream in = new FileInputStream(cfgf)) { cfg.load(in); }
        }
        boolean apply = "1".equals(cfg.getProperty("apply", "0"));
        long maxGap = Long.parseLong(cfg.getProperty("max_gap", "0x40").replace("0x", ""), 16);

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing lst = currentProgram.getListing();
        ReferenceManager rm = currentProgram.getReferenceManager();

        // collect orphans
        List<Function> orphans = new ArrayList<>();
        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (hasPrologue(lst, f.getEntryPoint())) continue;
            orphans.add(f);
        }
        println("orphan candidates (no prologue): " + orphans.size());

        int merged = 0, skippedMulti = 0, skippedNoParent = 0, skippedFar = 0, failed = 0;
        List<String> done = new ArrayList<>();

        for (Function f : orphans) {
            if (f.isExternal() || f.isThunk()) continue;
            Address entry = f.getEntryPoint();

            // find candidate parents: prologued functions referencing this entry
            Set<Function> parents = new LinkedHashSet<>();
            for (Reference r : rm.getReferencesTo(entry)) {
                Function pf = fm.getFunctionContaining(r.getFromAddress());
                if (pf == null || pf.equals(f)) continue;
                if (hasPrologue(lst, pf.getEntryPoint())) parents.add(pf);
            }
            if (parents.isEmpty()) { skippedNoParent++; continue; }
            if (parents.size() > 1) { skippedMulti++; continue; }

            Function parent = parents.iterator().next();
            long gap = 0;
            long pMax = parent.getBody().getMaxAddress().getOffset();
            long fMin = f.getBody().getMinAddress().getOffset();
            if (fMin > pMax) gap = fMin - pMax;
            if (gap > maxGap) { skippedFar++; continue; }

            // merge: remove fragment, then extend parent body over the union
            try {
                Address lo = parent.getBody().getMinAddress();
                Address hi = parent.getBody().getMaxAddress();
                Address flo = f.getBody().getMinAddress();
                Address fhi = f.getBody().getMaxAddress();
                if (flo.getOffset() < lo.getOffset()) lo = flo;
                if (fhi.getOffset() > hi.getOffset()) hi = fhi;

                if (apply) {
                    String fname = f.getName();
                    fm.removeFunction(entry);
                    try {
                        parent.setBody(new ghidra.program.model.address.AddressSet(lo, hi));
                    } catch (Exception e) {
                        // overlapping another function: skip silently
                        failed++;
                        continue;
                    }
                    done.add(parent.getName() + " <- " + fname);
                }
                merged++;
            } catch (Exception e) {
                failed++;
            }
        }

        println(String.format(
            "merged=%d skippedNoParent=%d skippedMulti=%d skippedFar=%d failed=%d apply=%s",
            merged, skippedNoParent, skippedMulti, skippedFar, failed, apply));
        println("functions now: " + fm.getFunctionCount());
        for (int i = 0; i < Math.min(done.size(), 40); i++) println("  " + done.get(i));
    }
}
