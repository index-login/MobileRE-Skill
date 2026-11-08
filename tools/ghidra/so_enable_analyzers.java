// so_enable_analyzers.java -- enable the missing per-function analyzers
//
// Two analyzer options were off, which is why many functions still look wrong:
//   Decompiler Parameter ID            = false  (no ABI params inferred)
//   Stack.Create Param Variables       = false  (stack args not turned into params)
//
// Turning them on does NOT retro-apply; the analyzers must be re-run. This
// script only flips the options so a later targeted run picks them up.
//
// Config: $TMP/so_enable_analyzers.cfg
//   apply=1
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.*;

public class so_enable_analyzers extends GhidraScript {

    @Override
    public void run() throws Exception {
        String tmp = System.getenv("TMP");
        if (tmp == null) tmp = System.getProperty("java.io.tmpdir");
        Properties cfg = new Properties();
        File cfgf = new File(tmp, "so_enable_analyzers.cfg");
        if (cfgf.isFile()) {
            try (InputStream in = new FileInputStream(cfgf)) { cfg.load(in); }
        }
        boolean apply = "1".equals(cfg.getProperty("apply", "0"));

        Options opts = currentProgram.getOptions("Analyzers");
        String[] keys = {
            "Decompiler Parameter ID",
            "Stack.Create Param Variables",
            "Stack.Create Local Variables",
            "Decompiler Parameter ID.Commit Data Types",
            "Call Convention ID",
            "Decompiler Switch Analysis",
        };
        for (String k : keys) {
            boolean cur = opts.getBoolean(k, false);
            println(String.format("  %-50s = %s", k, cur));
            if (apply && !cur) {
                opts.setBoolean(k, true);
                println("    -> enabled");
            }
        }
        if (apply) {
            println("options updated (they take effect on the next analyzer run)");
        } else {
            println("dry run; pass apply=1 to change");
        }
    }
}
