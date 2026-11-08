// so_name_jni_params.java -- name JNI function parameters by the JNI contract
//
// Every JNI native method has a fixed leading parameter list:
//
//   static native  (JNIEnv *env, jclass clazz, ...)
//   instance native(JNIEnv *env, jobject thiz, ...)
//
// Ghidra renders them as `param_1`, `param_2`, ... because the prologue is
// flattened by the packer. This script renames them so the pseudocode reads
// like the Java declaration.
//
// It also names the trailing parameters of the functions whose Java signature
// is known from the shell's string table (`jni_dexpathlist`, `jni_dexfile`,
// `jni_inmemorydexclassloader`, ...).
//
// Config: $TMP/so_name_jni_params.cfg
//   apply=1
//   range_lo=0x140000
//   range_hi=0x1f0000
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.SourceType;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.*;

public class so_name_jni_params extends GhidraScript {

    /** function name -> trailing parameter names (after env/clazz or env/thiz) */
    private static final Map<String, String[]> TAIL = new LinkedHashMap<>();
    static {
        TAIL.put("jni_dexpathlist",              new String[]{"dexPathListObj", "loaderObj", "extra", "flag"});
        TAIL.put("jni_dexpathlist_4",            new String[]{"dexPathListObj", "elementObj", "flag"});
        TAIL.put("jni_dexpathlist_5",            new String[]{"dexPathListObj", "elementObj"});
        TAIL.put("jni_dexpathlist_6",            new String[]{"dexPathListObj"});
        TAIL.put("jni_dexpathlist_7",            new String[]{"dexPathListObj", "elementsArr"});
        TAIL.put("jni_dexpathlist_8",            new String[]{"dexPathListObj"});
        TAIL.put("jni_dexpathlist_9",            new String[]{"dexPathListObj", "elementObj"});
        TAIL.put("jni_dexfile",                  new String[]{"dexFileObj"});
        TAIL.put("jni_dexfile_2",                new String[]{"dexFileObj", "begin", "end"});
        TAIL.put("jni_dexfile_3",                new String[]{"dexFileObj", "begin"});
        TAIL.put("jni_dexfile_4",                new String[]{"dexFileObj", "cookie"});
        TAIL.put("jni_inmemorydexclassloader",   new String[]{"byteBufferObj", "parentLoader", "flag"});
        TAIL.put("jni_bundleinfo",               new String[]{"bundleObj"});
        TAIL.put("jni_nativetool",               new String[]{"obj"});
        TAIL.put("jni_context",                  new String[]{"contextObj"});
        TAIL.put("jni_contextwrapper",           new String[]{"wrapperObj"});
        TAIL.put("jni_string",                   new String[]{"strObj"});
        TAIL.put("jni_file",                     new String[]{"fileObj"});
        TAIL.put("jni_util",                     new String[]{"obj"});
        TAIL.put("jni_weakreference",            new String[]{"refObj"});
        TAIL.put("jni_basedexclassloader",       new String[]{"loaderObj"});
        TAIL.put("jni_dexpathlist_2",            new String[]{"dexPathListObj", "elementObj"});
        TAIL.put("jni_dexpathlist_3",            new String[]{"dexPathListObj", "elementObj"});
    }

    private long cfgLong(Properties p, String k, long dflt) {
        String v = p.getProperty(k);
        if (v == null || v.trim().isEmpty()) return dflt;
        v = v.trim();
        if (v.startsWith("0x") || v.startsWith("0X")) return Long.parseLong(v.substring(2), 16);
        return Long.parseLong(v);
    }

    @Override
    public void run() throws Exception {
        String tmp = System.getenv("TMP");
        if (tmp == null) tmp = System.getProperty("java.io.tmpdir");
        Properties cfg = new Properties();
        File cfgf = new File(tmp, "so_name_jni_params.cfg");
        if (cfgf.isFile()) {
            try (InputStream in = new FileInputStream(cfgf)) { cfg.load(in); }
        }
        boolean apply = "1".equals(cfg.getProperty("apply", "0"));
        long lo = cfgLong(cfg, "range_lo", 0x140000L);
        long hi = cfgLong(cfg, "range_hi", 0x1f0000L);

        FunctionManager fm = currentProgram.getFunctionManager();
        int funcs = 0, renamed = 0, failed = 0;
        List<String> errs = new ArrayList<>();

        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.isExternal() || f.isThunk()) continue;
            long ep = f.getEntryPoint().getOffset();
            if (ep < lo || ep > hi) continue;
            String n = f.getName();
            if (!n.startsWith("jni_")) continue;
            funcs++;

            Parameter[] ps = f.getParameters();
            if (ps.length < 2) continue;

            // JNI contract: p0 = JNIEnv*, p1 = jclass or jobject
            List<String> plan = new ArrayList<>();
            plan.add("env");
            plan.add(n.endsWith("_static") ? "clazz" : "thiz");

            String[] tail = TAIL.get(n);
            for (int i = 2; i < ps.length; i++) {
                String nm;
                if (tail != null && (i - 2) < tail.length) nm = tail[i - 2];
                else nm = "arg" + (i - 2);
                plan.add(nm);
            }

            if (!apply) {
                println(String.format("%-28s %s", n, plan));
                renamed++;
                continue;
            }
            try {
                for (int i = 0; i < ps.length; i++) {
                    String nm = plan.get(i);
                    if (!nm.equals(ps[i].getName())) {
                        ps[i].setName(nm, SourceType.USER_DEFINED);
                    }
                }
                renamed++;
            } catch (Exception e) {
                failed++;
                if (errs.size() < 10) errs.add(n + ": " + e.getMessage());
            }
        }

        println(String.format("jni funcs=%d renamed=%d failed=%d apply=%s",
                funcs, renamed, failed, apply));
        for (String s : errs) println("  " + s);
    }
}
