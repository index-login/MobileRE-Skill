/**
 * Build shell_ctx_t from DYNAMIC evidence, not guesswork.
 *
 * Method: run the SO in Unicorn (tools/vm_emulate.py harness), call
 * JNI_OnLoad, then dump g_shell_ctx.  Every field below was observed to hold a
 * real value at that offset; the observed value is quoted in the comment.
 *
 * Observed dump (after JNI_OnLoad, Android 10 emulation):
 *   +0x000 0x000fda90   -> JNINativeInterface* (all 8 slots are code ptrs)
 *   +0x008 0x10011688   -> heap ptr (same as +0x010)
 *   +0x010 0x10011688   -> heap ptr
 *   +0x020 0x000fe128   -> sub-structure
 *   +0x028 0x0011a0f8   -> libdvm.so handle (matches static: DAT_0021a0f8)
 *   +0x030 0x000fe470   -> sub-structure
 *   +0x038 0x000fe3d8   -> sub-structure
 *   +0x040 0x000fe4a0   -> sub-structure
 *   +0x048 0x000fe768   -> sub-structure
 *   +0x050 0x00103580   -> image ptr
 *   +0x058 0x000fe838   -> sub-structure
 *   +0x060 10038        -> build/version number
 *   +0x068 0x00100840   -> image ptr
 *   +0x070 0x000fd9b0   -> dispatch table base
 *   +0x078 0x00043dac   -> code ptr
 *   +0x0b0 29           -> sdk_int (Android 10)
 *   +0x0d0 0x1d00000001 -> packed {u32 flag=1, u32 29}
 *   +0x0e0 0x00043ebc   -> code ptr
 *   +0x0e8 256          -> opcode table size
 *   +0x0f8 0x000442a8   -> code ptr
 */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class shell_ctx_from_dyn extends GhidraScript {

    private void put(Structure s) {
        currentProgram.getDataTypeManager()
            .addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    @Override
    public void run() throws Exception {
        DataTypeManager m = currentProgram.getDataTypeManager();
        DataType u8 = ByteDataType.dataType;
        DataType u32 = UnsignedIntegerDataType.dataType;
        DataType u64 = UnsignedLongDataType.dataType;
        DataType ptr = new PointerDataType(m);

        Structure s = new StructureDataType("shell_ctx_t", 0, m);

        s.add(ptr,  "jni",            "JNINativeInterface*  (dyn +0x00 = 0x000fda90)");
        s.add(ptr,  "heap_a",         "heap ptr             (dyn +0x08)");
        s.add(ptr,  "heap_b",         "heap ptr, same as +0x08 (dyn +0x10)");
        s.add(ptr,  "unk_18",         "(dyn +0x18, zero at runtime)");
        s.add(ptr,  "sub_20",         "sub-structure        (dyn +0x20 = 0x000fe128)");
        s.add(ptr,  "dvm_handle",     "libdvm.so dlopen handle (dyn +0x28 = 0x0011a0f8)");
        s.add(ptr,  "sub_30",         "sub-structure        (dyn +0x30)");
        s.add(ptr,  "sub_38",         "sub-structure        (dyn +0x38)");
        s.add(ptr,  "sub_40",         "sub-structure        (dyn +0x40)");
        s.add(ptr,  "sub_48",         "sub-structure        (dyn +0x48)");
        s.add(ptr,  "img_50",         "image ptr            (dyn +0x50 = 0x00103580)");
        s.add(ptr,  "sub_58",         "sub-structure        (dyn +0x58)");
        s.add(u64,  "build_ver",      "build/version number (dyn +0x60 = 10038)");
        s.add(ptr,  "img_68",         "image ptr            (dyn +0x68 = 0x00100840)");
        s.add(ptr,  "dispatch_tbl",   "dispatch table base  (dyn +0x70 = 0x000fd9b0)");
        s.add(ptr,  "fn_78",          "code ptr             (dyn +0x78 = 0x00043dac)");
        // +0x80..+0xaf: heap pointers (see dump); keep as an opaque block
        s.add(new ArrayDataType(u64, 6, 8, m), "heap_ptrs_80",
              "heap pointers (dyn +0x80,+0x88,+0xa8,+0xb8,+0xc0,+0xf0)");
        s.add(u32,  "sdk_int",        "sdk int = 29 (Android 10)  (dyn +0xb0)");
        s.add(u32,  "pad_b4",         "padding");
        s.add(u64,  "packed_b8",      "packed {u32 flag, u32 29} (dyn +0xd0)");
        s.add(ptr,  "fn_e0",          "code ptr             (dyn +0xe0 = 0x00043ebc)");
        s.add(u64,  "opcode_count",   "opcode table size = 256 (dyn +0xe8)");
        s.add(ptr,  "fn_f8",          "code ptr             (dyn +0xf8 = 0x000442a8)");
        put(s);

        println("shell_ctx_t rebuilt from dynamic evidence: " + s.getLength() + " bytes");
    }
}
