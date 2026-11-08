// so_vm_frame_vars.java -- give the shared VM interpreter frame named variables
//
// All VM opcode handlers are fragments of vm_interpreter: they are entered by
// `br x9` from the dispatch site, so they have no prologue and no own frame.
// Ghidra therefore renders every shared slot as `in_stack_XXXXXXXX`.
//
// Dynamically measured layout (Unicorn, JNI_OnLoad sel=2 @ dispatch):
//   +0x000  stack_ptr        current operand stack pointer (grows up)
//   +0x008  stack_ptr_alt    same value (second copy used by pop-style ops)
//   +0x010  frame_base       operand stack base
//   +0x018  const_pool_lo    tbl2 (0x1135d0) -- local variable table
//   +0x020  const_pool_hi    tbl1 (0x1135b0)
//   +0x028  frame_base_plus4 frame_base + 4
//   +0x030  frame_base2      frame_base
//   +0x038  stack_ptr2       current operand stack pointer (third copy)
//   +0x040  stack_ptr3       current operand stack pointer (fourth copy)
//   +0x048  stack_ptr_plus4  stack_ptr + 4
//   +0x050  local_base       locals area base
//   +0x058  saved_lr         -1 sentinel
//   +0x060  scratch60        per-opcode temp
//   +0x068..0x080            per-opcode temps (u32 pairs)
//   +0x81c  prev_opcode      key carried from the previous instruction
//   +0x820  pc               current bytecode pointer
//   +0x82c  opcode           decoded opcode for the current instruction
//   +0x830  dispatch_table   opcode -> handler table (0x1f3af0 at runtime)
//   +0x838  cont_table       continuation table (0x1f3f40 at runtime)
//
// The 0x830..0x1288 region is the copy of the handler dispatch + continuation
// tables (memcpy of 0x1288 bytes at vm_interpreter entry).
//
// Config: $TMP/so_vm_frame_vars.cfg
//   apply=1        really create the variables (default 0 = dry run)
//   entry_lo=0x1bd760
//   entry_hi=0x1c474f
//   range_lo=0x1bd000
//   range_hi=0x1c4800
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.*;

public class so_vm_frame_vars extends GhidraScript {

    // offset -> {name, typeName}
    private static final Object[][] SLOTS = {
        {0x000L, "vm_sp",            "void *"},
        {0x008L, "vm_sp_alt",        "void *"},
        {0x010L, "vm_frame_base",    "void *"},
        {0x018L, "vm_tbl2",          "void *"},
        {0x020L, "vm_tbl1",          "void *"},
        {0x028L, "vm_frame_base_4",  "void *"},
        {0x030L, "vm_frame_base2",   "void *"},
        {0x038L, "vm_sp2",           "void *"},
        {0x040L, "vm_sp3",           "void *"},
        {0x048L, "vm_sp_plus4",      "void *"},
        {0x050L, "vm_local_base",    "void *"},
        {0x058L, "vm_saved_lr",      "long"},
        {0x060L, "vm_tmp60",         "undefined8"},
        {0x068L, "vm_tmp68",         "undefined8"},
        {0x070L, "vm_tmp70",         "undefined8"},
        {0x078L, "vm_tmp78",         "undefined8"},
        {0x080L, "vm_tmp80",         "undefined8"},
        {0x81cL, "vm_prev_opcode",   "undefined1"},
        {0x820L, "vm_pc",            "void *"},
        {0x82cL, "vm_opcode",        "undefined1"},
        {0x830L, "vm_handler_tbl",   "void *"},
        {0x838L, "vm_cont_tbl",      "void *"},
    };

    private long cfgLong(Properties p, String k, long dflt) {
        String v = p.getProperty(k);
        if (v == null || v.trim().isEmpty()) return dflt;
        v = v.trim();
        if (v.startsWith("0x") || v.startsWith("0X")) return Long.parseLong(v.substring(2), 16);
        return Long.parseLong(v);
    }

    private DataType resolve(String typeName, DataTypeManager dtm) {
        DataType dt = dtm.getDataType("/" + typeName);
        if (dt != null) return dt;
        dt = dtm.getDataType(typeName);
        if (dt != null) return dt;
        switch (typeName) {
            case "void *":   return new PointerDataType(dtm.getDataType("/void"));
            case "long":     return dtm.getDataType("/long");
            case "undefined8": return dtm.getDataType("/undefined8");
            case "undefined1": return dtm.getDataType("/undefined1");
            default:         return dtm.getDataType("/undefined8");
        }
    }

    @Override
    public void run() throws Exception {
        String tmp = System.getenv("TMP");
        if (tmp == null) tmp = System.getProperty("java.io.tmpdir");
        Properties cfg = new Properties();
        File cfgf = new File(tmp, "so_vm_frame_vars.cfg");
        if (cfgf.isFile()) {
            try (InputStream in = new FileInputStream(cfgf)) { cfg.load(in); }
        }
        boolean apply = "1".equals(cfg.getProperty("apply", "0"));
        long rangeLo = cfgLong(cfg, "range_lo", 0x1bd000L);
        long rangeHi = cfgLong(cfg, "range_hi", 0x1c4800L);

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        FunctionManager fm = currentProgram.getFunctionManager();

        int funcs = 0, created = 0, failed = 0, skipped = 0;
        List<String> errs = new ArrayList<>();

        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.isExternal() || f.isThunk()) continue;
            long ep = f.getEntryPoint().getOffset();
            if (ep < rangeLo || ep > rangeHi) continue;
            funcs++;

            if (!apply) continue;

            StackFrame sf = f.getStackFrame();
            // make sure the frame can hold the highest slot
            long need = 0x840L;
            if (sf.getFrameSize() < need) {
                try { sf.setLocalSize((int) need); } catch (Exception ignored) { }
            }

            for (Object[] slot : SLOTS) {
                long off = (Long) slot[0];
                String nm = (String) slot[1];
                String tn = (String) slot[2];
                DataType dt = resolve(tn, dtm);
                if (dt == null) { failed++; continue; }
                try {
                    Variable exist = sf.getVariableContaining((int) off);
                    if (exist != null && exist.getName().equals(nm)) { skipped++; continue; }
                    sf.createVariable(nm, (int) off, dt, SourceType.USER_DEFINED);
                    created++;
                } catch (Exception e) {
                    failed++;
                    if (errs.size() < 12) {
                        errs.add(String.format("%s +%#x %s: %s",
                                f.getName(), off, nm, e.getMessage()));
                    }
                }
            }
        }

        println(String.format("handler funcs=%d created=%d skipped=%d failed=%d apply=%s",
                funcs, created, skipped, failed, apply));
        for (String s : errs) println("  " + s);
        if (!apply) println("dry run: set apply=1 in $TMP/so_vm_frame_vars.cfg to write");
    }
}
