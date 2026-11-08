/**
 * Build vm_runtime from DYNAMIC evidence.
 *
 * Method: tools/probe_struct.py hooks vm_interpreter (0xbd624) and dumps the
 * rt pointer.  Observed at runtime (JNI_OnLoad path, Android 10 emulation):
 *
 *   rt = 0x10413fd0
 *   +0x00  self        0x0000000010413fd0   (points to itself)
 *   +0x08  stack_top   0x0000000010014010   (harness stack region)
 *   +0x10  heap_alt    0x0000000010214000   (second mmap)
 *   +0x18  heap_size   0x0000000000200000   (2 MB)
 *   +0x20  heap_base   0x0000000010014000   (first mmap)
 *   +0x28  heap_alt2   0x0000000000200000   (duplicate of heap_size)
 *
 * Matches vm_runtime_alloc() in the binary:
 *   puVar4 = mmap(0, len, ...);          // heap_alt
 *   puVar5 = mmap(0, len, ...);          // heap_base
 *   rt = puVar5 + (len - 0x30);          // rt sits at the TAIL of the 2nd mmap
 *   rt[0] = rt;  rt[1] = puVar4;  rt[2] = len; ...
 */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.SourceType;

public class vm_runtime_from_dyn extends GhidraScript {

    @Override
    public void run() throws Exception {
        DataTypeManager m = currentProgram.getDataTypeManager();
        DataType ptr = new PointerDataType(m);
        DataType u64 = UnsignedLongDataType.dataType;

        Structure s = new StructureDataType("vm_runtime", 0, m);
        s.add(ptr, "self",       "points to itself (dyn +0x00 = rt)");
        s.add(ptr, "stack_top",  "VM value stack top (dyn +0x08)");
        s.add(ptr, "heap_alt",   "second mmap base (dyn +0x10 = 0x10214000)");
        s.add(u64, "heap_size",  "mmap length, 2 MB (dyn +0x18 = 0x200000)");
        s.add(ptr, "heap_base",  "first mmap base (dyn +0x20 = 0x10014000)");
        s.add(u64, "heap_alt2",  "duplicate of heap_size (dyn +0x28)");
        m.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER);

        // 应用类型：vm_runtime_alloc 返回值 + vm_push/vm_pop/vm_dispatch_entry/vm_interpreter 首参
        long[] fns = {0x1e2d48L, 0x1e2e10L, 0x1e7fa0L, 0x1e2e00L, 0x1bd624L};
        DataType rtPtr = m.getPointer(s);
        int ok = 0;
        for (long a : fns) {
            Function fn = getFunctionAt(toAddr(a));
            if (fn == null) continue;
            try {
                if (a == 0x1e2d48L) {
                    fn.setReturnType(rtPtr, SourceType.USER_DEFINED);
                } else {
                    Parameter[] ps = fn.getParameters();
                    if (ps.length > 0) {
                        ps[0].setDataType(rtPtr, SourceType.USER_DEFINED);
                        ps[0].setName("rt", SourceType.USER_DEFINED);
                    }
                }
                ok++;
            } catch (Exception e) {
                println("skip " + fn.getName() + ": " + e.getMessage());
            }
        }
        println("vm_runtime created (" + s.getLength() + " B), applied to " + ok + "/5 functions");
    }
}
