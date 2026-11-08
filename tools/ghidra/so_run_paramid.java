// so_run_paramid.java -- run Decompiler Parameter ID on selected functions
//
// Decompiler Parameter ID is the Ghidra analyzer that infers parameters and
// locals from call sites + decompiler output. In this project it is DISABLED,
// which is why many functions show `unaff_x19`, `in_stack_...` noise.
//
// Running full auto-analysis would redo function boundaries and clobber the
// carefully rebuilt VM handler split. Instead we use
// ghidra.app.cmd.function.DecompilerParameterIdCmd on a chosen function set.
//
// Selection rules:
//   - skip vm_* handlers (they read the interpreter frame via fixed offsets,
//     so they legitimately take no params)
//   - skip frag_/leaf_/tail_/cff_ (register use comes from the parent frame)
//   - skip functions without a prologue
//   - process the rest
//
// Config: $TMP/so_paramid.cfg
//   apply=1
//   min_size=64
//   include_fun=1
//@category MobileRE

import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.*;

public class so_run_paramid extends GhidraScript {

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

    private boolean skipByName(String n) {
        return n.startsWith("vm_") || n.startsWith("frag_") || n.startsWith("leaf_")
            || n.startsWith("tail_") || n.startsWith("cff_") || n.startsWith("thunk_")
            || n.startsWith("LAB_") || n.startsWith("switchD_");
    }

    @Override
    public void run() throws Exception {
        String tmp = System.getenv("TMP");
        if (tmp == null) tmp = System.getProperty("java.io.tmpdir");
        Properties cfg = new Properties();
        File cfgf = new File(tmp, "so_paramid.cfg");
        if (cfgf.isFile()) {
            try (InputStream in = new FileInputStream(cfgf)) { cfg.load(in); }
        }
        boolean apply = "1".equals(cfg.getProperty("apply", "0"));
        int minSize = Integer.parseInt(cfg.getProperty("min_size", "64"));
        boolean includeFun = "1".equals(cfg.getProperty("include_fun", "1"));
        int offset = Integer.parseInt(cfg.getProperty("offset", "0"));
        int limit = Integer.parseInt(cfg.getProperty("limit", "0"));

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing lst = currentProgram.getListing();

        List<Function> picked = new ArrayList<>();
        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.isExternal() || f.isThunk()) continue;
            if (f.getBody().getNumAddresses() < minSize) continue;
            String n = f.getName();
            if (skipByName(n)) continue;
            if (!includeFun && n.startsWith("FUN_")) continue;
            if (!hasPrologue(lst, f.getEntryPoint())) continue;
            picked.add(f);
        }
        // paginate so each run stays inside the MCP timeout
        if (offset > 0 || limit > 0) {
            int to = (limit > 0) ? Math.min(picked.size(), offset + limit) : picked.size();
            int from = Math.min(offset, picked.size());
            picked = new ArrayList<>(picked.subList(from, to));
        }
        println("candidates: " + picked.size() + " (offset=" + offset + " limit=" + limit + ")  apply=" + apply);

        if (!apply) {
            for (int i = 0; i < Math.min(picked.size(), 50); i++) {
                Function f = picked.get(i);
                println(String.format("  %-45s %s  %d bytes",
                        f.getName(), f.getEntryPoint(), f.getBody().getNumAddresses()));
            }
            return;
        }

        int ok = 0, fail = 0, changed = 0;
        List<String> detail = new ArrayList<>();
        for (Function f : picked) {
            try {
                int before = f.getParameterCount();
                DecompilerParameterIdCmd cmd = new DecompilerParameterIdCmd(
                        "Decompiler Parameter ID",
                        new ghidra.program.model.address.AddressSet(f.getEntryPoint()),
                        ghidra.program.model.symbol.SourceType.ANALYSIS,
                        true,    // commit to database
                        true,    // analysis mode
                        60);     // decompile timeout
                boolean done = cmd.applyTo(currentProgram, monitor);
                int after = f.getParameterCount();
                if (after != before) {
                    changed++;
                    if (detail.size() < 60) detail.add(f.getName() + "  " + before + " -> " + after);
                }
                if (done) ok++; else fail++;
            } catch (Throwable t) {
                fail++;
                if (detail.size() < 60) detail.add("FAIL " + f.getName() + ": " + t.getMessage());
            }
        }
        println(String.format("done ok=%d fail=%d changed=%d", ok, fail, changed));
        for (String s : detail) println("  " + s);
    }
}
