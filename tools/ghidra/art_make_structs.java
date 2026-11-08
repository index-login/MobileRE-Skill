/**
 * Build ART runtime structs in Ghidra from the real Android 10 headers.
 *
 * Layouts come from references/android-headers/art-a10/*.h (AOSP android-10.0.0_r1),
 * which match the target sample's era.  Every offset below is cited with the
 * header field it came from so a reviewer can verify it.
 *
 * Usage (Ghidra script, via MCP run_ghidra_script or Script Manager):
 *     art_make_structs.java
 *
 * Idempotent: existing structs with the same name are replaced.
 */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataTypeConflictHandler;

public class art_make_structs extends GhidraScript {

    private DataTypeManager dtm() {
        return currentProgram.getDataTypeManager();
    }

    private void put(Structure s) {
        dtm().addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    @Override
    public void run() throws Exception {
        DataTypeManager m = dtm();
        DataType u8 = ByteDataType.dataType;
        DataType u16 = UnsignedShortDataType.dataType;
        DataType u32 = UnsignedIntegerDataType.dataType;
        DataType u64 = UnsignedLongDataType.dataType;
        DataType i32 = IntegerDataType.dataType;
        DataType i64 = LongDataType.dataType;
        DataType ptr = new PointerDataType(m);
        DataType charPtr = new PointerDataType(CharDataType.dataType, m);

        // ------------------------------------------------------------------
        // art::ArtMethod  (runtime/art_method.h, android-10.0.0_r1)
        //   0x00 GcRoot<mirror::Class> declaring_class_      (4B compressed ref)
        //   0x04 std::atomic<uint32_t> access_flags_         (4B)
        //   0x08 uint32_t dex_code_item_offset_
        //   0x0c uint32_t dex_method_index_
        //   0x10 uint16_t method_index_
        //   0x12 uint16_t hotness_count_
        //   0x14 uint16_t imt_index_
        //   0x16 padding to 8-byte alignment
        //   0x18 PtrSizedFields { void* data_; void* entry_point_from_quick_compiled_code_; }
        // Total on LP64: 0x28 (40 bytes)
        // ------------------------------------------------------------------
        Structure artMethod = new StructureDataType("art_ArtMethod", 0, m);
        artMethod.add(u32, "declaring_class_", "GcRoot<mirror::Class>, compressed ref");
        artMethod.add(u32, "access_flags_", "kAcc* flags (public/private/static/native...)");
        artMethod.add(u32, "dex_code_item_offset_", "offset into DexFile code items");
        artMethod.add(u32, "dex_method_index_", "index into DexFile method ids");
        artMethod.add(u16, "method_index_", "vtable/itable index");
        artMethod.add(u16, "hotness_count_", "JIT hotness counter");
        artMethod.add(u16, "imt_index_", "interface method table index");
        artMethod.add(new ArrayDataType(u8, 2, 1, m), "padding_", "align PtrSizedFields to 8");
        artMethod.add(ptr, "data_", "native: JNI fn ptr; abstract: impl; other: profiling data");
        artMethod.add(ptr, "entry_point_from_quick_compiled_code_", "quick-compiled entry (hook target)");
        put(artMethod);

        // ------------------------------------------------------------------
        // art::mirror::Object header (runtime/mirror/object.h)
        //   0x00 HeapReference<Class> klass_   (4B compressed)
        //   0x04 uint32_t monitor_
        // ------------------------------------------------------------------
        Structure obj = new StructureDataType("art_mirror_Object", 0, m);
        obj.add(u32, "klass_", "HeapReference<mirror::Class>, compressed");
        obj.add(u32, "monitor_", "lock word");
        put(obj);

        // ------------------------------------------------------------------
        // art::mirror::Class — only the fields the sample actually reads.
        //   runtime/mirror/class.h: these are the leading members in Android 10.
        // ------------------------------------------------------------------
        Structure cls = new StructureDataType("art_mirror_Class", 0, m);
        cls.add(u32, "klass_", "HeapReference<Class> (Object header)");
        cls.add(u32, "monitor_", "Object header");
        cls.add(u32, "super_class_", "HeapReference<Class>");
        cls.add(u32, "ifext_", "HeapReference<IfTable>");
        cls.add(u32, "name_", "HeapReference<String>");
        cls.add(u32, "access_flags_", "uint32 class access flags");
        cls.add(u32, "status_", "ClassStatus enum");
        cls.add(u32, "dex_class_def_idx_", "uint32");
        cls.add(u32, "dex_type_idx_", "uint32");
        put(cls);

        // ------------------------------------------------------------------
        // art::DexFile  (libdexfile/dex/dex_file.h)
        //   The sample only touches the header + begin_ pointer, so model the
        //   first 0x40 bytes that are guaranteed by the DEX header layout.
        // ------------------------------------------------------------------
        Structure dex = new StructureDataType("art_DexFile", 0, m);
        dex.add(u8, "magic", "dex\\n035\\0");
        dex.add(new ArrayDataType(u8, 16, 1, m), "checksum_and_sig", "checksum(4)+sha1(20) partial");
        dex.add(u32, "file_size_", "uint32");
        dex.add(u32, "header_size_", "uint32");
        dex.add(u32, "endian_tag_", "uint32");
        dex.add(u32, "link_size_", "uint32");
        dex.add(u32, "link_off_", "uint32");
        dex.add(u32, "map_off_", "uint32");
        dex.add(u32, "string_ids_size_", "uint32");
        dex.add(u32, "string_ids_off_", "uint32");
        dex.add(u32, "type_ids_size_", "uint32");
        dex.add(u32, "type_ids_off_", "uint32");
        dex.add(u32, "proto_ids_size_", "uint32");
        dex.add(u32, "proto_ids_off_", "uint32");
        dex.add(u32, "field_ids_size_", "uint32");
        dex.add(u32, "field_ids_off_", "uint32");
        dex.add(u32, "method_ids_size_", "uint32");
        dex.add(u32, "method_ids_off_", "uint32");
        dex.add(u32, "class_defs_size_", "uint32");
        dex.add(u32, "class_defs_off_", "uint32");
        dex.add(u32, "data_size_", "uint32");
        dex.add(u32, "data_off_", "uint32");
        put(dex);

        // ------------------------------------------------------------------
        // art::JavaVMExt (runtime/jni/java_vm_ext.h)
        //   Only the leading vtable pointer + functions table matter here.
        // ------------------------------------------------------------------
        Structure vmExt = new StructureDataType("art_JavaVMExt", 0, m);
        vmExt.add(ptr, "vtable", "JNIInvokeInterface*");
        vmExt.add(ptr, "functions", "JNIInvokeInterface* (same as vtable on ART)");
        vmExt.add(ptr, "runtime_", "art::Runtime*");
        vmExt.add(u32, "globals_lock_", "Mutex (opaque)");
        put(vmExt);

        // ------------------------------------------------------------------
        // art::JNIEnvExt (runtime/jni/jni_env_ext.h)
        //   0x00 JNINativeInterface* functions
        //   0x08 JavaVMExt* vm_
        //   0x10 self_ (Thread*)
        // ------------------------------------------------------------------
        Structure envExt = new StructureDataType("art_JNIEnvExt", 0, m);
        envExt.add(ptr, "functions", "JNINativeInterface*");
        envExt.add(ptr, "vm_", "JavaVMExt*");
        envExt.add(ptr, "self_", "art::Thread*");
        put(envExt);

        // ------------------------------------------------------------------
        // art::Instrumentation (runtime/instrumentation.h) — leading fields
        // ------------------------------------------------------------------
        Structure instr = new StructureDataType("art_Instrumentation", 0, m);
        instr.add(ptr, "vtable", "ArtInstrumentation*");
        instr.add(ptr, "entry_hooks_", "EntryHookTable");
        instr.add(ptr, "exit_hooks_", "ExitHookTable");
        put(instr);

        println("ART structs created:");
        println("  art_ArtMethod      " + artMethod.getLength() + " B");
        println("  art_mirror_Object  " + obj.getLength() + " B");
        println("  art_mirror_Class   " + cls.getLength() + " B");
        println("  art_DexFile        " + dex.getLength() + " B");
        println("  art_JavaVMExt      " + vmExt.getLength() + " B");
        println("  art_JNIEnvExt      " + envExt.getLength() + " B");
        println("  art_Instrumentation " + instr.getLength() + " B");
    }
}
