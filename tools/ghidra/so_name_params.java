// so_name_params.java -- give inferred parameters meaningful names
//
// After so_run_paramid.java, functions have parameters but they are named
// param_1..param_N. This script renames them based on:
//   1) the function's semantic name (e.g. jni_get_activity_thread -> env)
//   2) the data type inferred (pointer vs scalar)
//   3) common JNI/context patterns (first param of a jni_* fn is JNIEnv*)
//
// Config: $TMP/so_name_params.cfg
//   apply=1
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.SourceType;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.*;

public class so_name_params extends GhidraScript {

    // name -> ordered parameter names
    private static final Map<String, String[]> RULES = new LinkedHashMap<>();
    static {
        RULES.put("jni_", new String[]{"env", "clazz", "obj", "arg1", "arg2", "arg3", "arg4", "arg5"});
        RULES.put("get_device_info", new String[]{"ctx"});
        RULES.put("get_app_info", new String[]{"env", "appInfoObj"});
        RULES.put("get_system_properties", new String[]{"ctx"});
        RULES.put("get_sdk_int_cached", new String[]{"ctx"});
        RULES.put("check_ptrace_wchan", new String[]{"ctx"});
        RULES.put("check_qemu_socket", new String[0]);
        RULES.put("make_target_writable", new String[]{"addr", "prot"});
        RULES.put("inline_hook_install", new String[]{"target", "hook", "orig"});
        RULES.put("hexdump_print", new String[]{"data", "len", "tag", "arg3", "arg4", "arg5", "arg6", "arg7"});
        RULES.put("sleep_ms", new String[]{"ms"});
        RULES.put("thread_create_wrapper", new String[]{"fn", "arg"});
        RULES.put("parse_maps_line", new String[]{"line", "out", "arg2", "arg3"});
        RULES.put("proc_read", new String[]{"path", "buf", "len", "arg3"});
        RULES.put("proc_maps_pid", new String[]{"pid", "out", "arg2"});
        RULES.put("read_proc_self_maps", new String[]{"out", "arg1"});
        RULES.put("get_proc_status_name", new String[]{"out"});
        RULES.put("zip_extract_dex", new String[]{"zipPath", "entry", "out"});
        RULES.put("load_secondary_dex", new String[]{"env", "path", "arg2"});
        RULES.put("dexfile_open_native", new String[]{"env", "clazz", "arg2", "arg3"});
        RULES.put("art_symbol_resolver", new String[]{"name", "out", "arg2"});
        RULES.put("resolve_dumpHprof", new String[]{"handle", "out", "arg2"});
        RULES.put("resolve_dvm", new String[]{"handle", "out", "arg2"});
        RULES.put("resolve_get_codeitem", new String[]{"handle", "out", "arg2"});
        RULES.put("ijm_decrypt_strings", new String[0]);
        RULES.put("sprintf_inline", new String[]{"dst", "fmt", "a1", "a2", "a3", "a4", "a5", "a6"});
        RULES.put("strlen_inline", new String[]{"s"});
        RULES.put("memcpy_inline", new String[]{"dst", "src", "n"});
        RULES.put("check_manifest", new String[]{"ctx", "arg1", "arg2"});
        RULES.put("check_emulator_dev", new String[]{"ctx"});
        RULES.put("frida_fd_probe", new String[]{"ctx", "arg1"});
        RULES.put("debugdata_probe", new String[]{"ctx", "arg1"});
        RULES.put("dbg_ddm_check", new String[]{"ctx"});
        RULES.put("hook_open_fd_check", new String[]{"ctx"});
        RULES.put("app_process_probe", new String[]{"ctx"});
        RULES.put("vmdebug_trace_probe", new String[]{"ctx", "arg1", "arg2"});
        RULES.put("art_loadmethod_resolver", new String[]{"handle", "out", "arg2"});
        RULES.put("art_setdebuginfo_hook", new String[]{"handle", "hook"});
        RULES.put("dvm_dexfindclass_probe", new String[]{"handle", "arg1"});
        RULES.put("bytebuffer_wrap", new String[0]);
        RULES.put("base64_table", new String[0]);
    }

    private String[] lookup(String fnName) {
        // exact match first
        for (Map.Entry<String, String[]> e : RULES.entrySet()) {
            if (fnName.equals(e.getKey())) return e.getValue();
        }
        // prefix match
        for (Map.Entry<String, String[]> e : RULES.entrySet()) {
            if (fnName.startsWith(e.getKey())) return e.getValue();
        }
        return null;
    }

    @Override
    public void run() throws Exception {
        String tmp = System.getenv("TMP");
        if (tmp == null) tmp = System.getProperty("java.io.tmpdir");
        Properties cfg = new Properties();
        File cfgf = new File(tmp, "so_name_params.cfg");
        if (cfgf.isFile()) {
            try (InputStream in = new FileInputStream(cfgf)) { cfg.load(in); }
        }
        boolean apply = "1".equals(cfg.getProperty("apply", "0"));

        FunctionManager fm = currentProgram.getFunctionManager();
        int renamed = 0, skipped = 0;
        List<String> detail = new ArrayList<>();

        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.isExternal() || f.isThunk()) continue;
            int n = f.getParameterCount();
            if (n == 0) continue;
            String[] names = lookup(f.getName());
            if (names == null) { skipped++; continue; }

            List<String> plan = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                plan.add(i < names.length ? names[i] : ("arg" + i));
            }
            if (!apply) {
                detail.add(String.format("%-40s -> %s", f.getName(), plan));
                renamed++;
                continue;
            }
            try {
                Parameter[] ps = f.getParameters();
                for (int i = 0; i < ps.length; i++) {
                    String nm = plan.get(i);
                    if (!nm.equals(ps[i].getName())) {
                        ps[i].setName(nm, SourceType.USER_DEFINED);
                    }
                }
                renamed++;
                if (detail.size() < 40) detail.add(f.getName() + " -> " + plan);
            } catch (Exception e) {
                detail.add("FAIL " + f.getName() + ": " + e.getMessage());
            }
        }
        println(String.format("renamed=%d skipped=%d apply=%s", renamed, skipped, apply));
        for (String s : detail) println("  " + s);
    }
}
