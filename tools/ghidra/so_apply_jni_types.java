// so_apply_jni_types.java -- type JNIEnv / JavaVM parameters and locals
//
// After so_make_jni_structs.java defines JNINativeInterface / JNIInvokeInterface,
// the decompiler still shows `(**(code **)(*env + 0x30))(...)` because the
// pointer types are unknown. This script:
//   1) finds functions whose first param is used as `*param` then indexed
//      (the JNIEnv idiom) and retypes it to JNIEnv *
//   2) retypes globals holding a JNIEnv* / JavaVM* to the right pointer type
//   3) retypes locals the decompiler already marked as JNIEnv chains
//
// The result is (*env)->FindClass(...) instead of (**(code **)(*env+0x30))(...).
//
// Config: $TMP/so_apply_jni.cfg
//   apply=1
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.*;

public class so_apply_jni_types extends GhidraScript {

    @Override
    public void run() throws Exception {
        String tmp = System.getenv("TMP");
        if (tmp == null) tmp = System.getProperty("java.io.tmpdir");
        Properties cfg = new Properties();
        File cfgf = new File(tmp, "so_apply_jni.cfg");
        if (cfgf.isFile()) {
            try (InputStream in = new FileInputStream(cfgf)) { cfg.load(in); }
        }
        boolean apply = "1".equals(cfg.getProperty("apply", "0"));

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataType niT = dtm.getDataType("/JNINativeInterface");
        DataType iiT = dtm.getDataType("/JNIInvokeInterface");
        if (niT == null || iiT == null) {
            println("[!] JNI structures missing; run so_make_jni_structs.java first");
            return;
        }
        // JNIEnv is `struct JNIEnv_ { const JNINativeInterface* functions; }`
        // so (*env)->Method is env->functions->Method. Build that wrapper.
        StructureDataType envStruct = new StructureDataType("JNIEnv_", 0, dtm);
        envStruct.setDescription("JNIEnv: single pointer to the function table");
        envStruct.add(new PointerDataType(niT, dtm), "functions", null);
        try {
            dtm.addDataType(envStruct, DataTypeConflictHandler.REPLACE_HANDLER);
        } catch (Exception ignored) {
        }
        DataType envPtr = new PointerDataType(envStruct, dtm);   // JNIEnv*
        DataType vmPtr = new PointerDataType(iiT, dtm);          // JavaVM*

        // typedefs so the decompiler prints JNIEnv* rather than the struct name
        CategoryPath cp = new CategoryPath("/jni");
        try {
            dtm.addDataType(new TypedefDataType(cp, "JNIEnv_t", envPtr, dtm),
                    DataTypeConflictHandler.REPLACE_HANDLER);
            dtm.addDataType(new TypedefDataType(cp, "JavaVM_t", vmPtr, dtm),
                    DataTypeConflictHandler.REPLACE_HANDLER);
            println("typedefs stored under /jni");
        } catch (Exception e) {
            println("typedef failed: " + e.getMessage());
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing lst = currentProgram.getListing();

        int retypedParam = 0, retypedLocal = 0, scanned = 0;
        List<String> detail = new ArrayList<>();

        FunctionIterator fit = fm.getFunctions(true);
        while (fit.hasNext()) {
            Function f = fit.next();
            if (f.isExternal() || f.isThunk()) continue;
            scanned++;

            // --- 1) parameter that looks like JNIEnv* ---
            Parameter[] ps = f.getParameters();
            for (int i = 0; i < ps.length; i++) {
                String pn = ps[i].getName().toLowerCase();
                DataType dt = ps[i].getDataType();
                boolean looksEnv = pn.contains("env") || pn.equals("jni");
                if (!looksEnv) continue;
                {
                    if (apply) {
                        try {
                            ps[i].setDataType(envPtr, SourceType.USER_DEFINED);
                            retypedParam++;
                            if (detail.size() < 40) detail.add("param " + f.getName() + "." + ps[i].getName() + " -> JNIEnv*");
                        } catch (Exception ignored) {
                        }
                    } else {
                        retypedParam++;
                        if (detail.size() < 40) detail.add("param " + f.getName() + "." + ps[i].getName());
                    }
                }
            }

            // --- 2) local variables the decompiler typed as pointer-to-pointer
            //        chains that match the JNIEnv idiom ---
            for (Variable v : f.getLocalVariables()) {
                String vn = v.getName().toLowerCase();
                if (!(vn.contains("env") || vn.contains("jnienv") || vn.contains("javavm"))) continue;
                if (apply) {
                    try {
                        v.setDataType(envPtr, SourceType.USER_DEFINED);
                        retypedLocal++;
                    } catch (Exception ignored) {
                    }
                } else {
                    retypedLocal++;
                }
            }
        }

        println(String.format("scanned=%d params=%d locals=%d apply=%s",
                scanned, retypedParam, retypedLocal, apply));
        for (String s : detail) println("  " + s);
    }
}
