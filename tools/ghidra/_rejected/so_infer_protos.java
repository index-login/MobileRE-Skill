// ===== REJECTED（已否决，仅留档复核）=====
// 否决原因：按 live-in 寄存器推断函数原型会大量错位 —— 这些寄存器是 CFF 状态机
// 在块间传递的上下文，不是函数参数。实测产出大量假参数。
// 结论与替代方案见 references/so-analysis-pipeline.md >「失败方案（不要重走）」。
// so_infer_protos.java -- infer internal function prototypes from call sites
//
// Problem: many internal functions have no parameters and no locals, so the
// decompiler emits `unaff_x19`, `unaff_x24`, `in_stack_00000028` noise.
// Those registers are inherited from the caller (callee-saved regs that the
// function reads before writing).
//
// Strategy:
//   1) For each function, scan its body for reads of x19..x28 that happen
//      BEFORE any write to the same register. Those are "live-in" registers.
//   2) Convert each live-in register into a parameter (typed void* by default).
//   3) Also detect stack reads above the frame (in_stack_*) and extend the
//      prototype with extra parameters.
//
// Config: $TMP/so_infer_protos.cfg
//   apply=1         dry run when 0
//   max_params=8    safety cap
//   only_named=1    only touch functions with a real name (skip FUN_*)
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.*;
import java.util.regex.*;

public class so_infer_protos extends GhidraScript {

    private static final String[] CALLEE_SAVED = {
        "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28"
    };

    @Override
    public void run() throws Exception {
        String tmp = System.getenv("TMP");
        if (tmp == null) tmp = System.getProperty("java.io.tmpdir");
        Properties cfg = new Properties();
        File cfgf = new File(tmp, "so_infer_protos.cfg");
        if (cfgf.isFile()) {
            try (InputStream in = new FileInputStream(cfgf)) { cfg.load(in); }
        }
        boolean apply = "1".equals(cfg.getProperty("apply", "0"));
        int maxParams = Integer.parseInt(cfg.getProperty("max_params", "8"));
        boolean onlyNamed = "1".equals(cfg.getProperty("only_named", "0"));

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing lst = currentProgram.getListing();
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataType voidPtr = new PointerDataType(dtm.getDataType("/void"));

        int scanned = 0, fixed = 0, skipped = 0;
        List<String> detail = new ArrayList<>();

        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.isExternal() || f.isThunk()) continue;
            if (f.getParameterCount() > 0) continue;          // already has params
            String nm = f.getName();
            if (onlyNamed && (nm.startsWith("FUN_") || nm.startsWith("frag_")
                    || nm.startsWith("leaf_") || nm.startsWith("tail_"))) { skipped++; continue; }
            scanned++;

            // scan body: find live-in callee-saved registers
            Set<String> liveIn = new LinkedHashSet<>();
            Set<String> written = new HashSet<>();
            Instruction ins = lst.getInstructionAt(f.getEntryPoint());
            int guard = 0;
            Pattern pRead = Pattern.compile("\\b(x(?:19|2[0-8]))\\b");
            while (ins != null && guard++ < 400 && f.getBody().contains(ins.getAddress())) {
                String s = ins.toString();
                // crude: destination register is the first operand
                int comma = s.indexOf(',');
                String dst = comma > 0 ? s.substring(s.indexOf(' ') + 1, comma).trim() : "";
                Matcher m = pRead.matcher(s);
                while (m.find()) {
                    String r = m.group(1);
                    if (!written.contains(r) && !dst.equals(r) && !dst.equals("w" + r.substring(1))) {
                        liveIn.add(r);
                    }
                }
                if (dst.startsWith("x") || dst.startsWith("w")) {
                    String base = dst.startsWith("w") ? "x" + dst.substring(1) : dst;
                    written.add(base);
                }
                ins = ins.getNext();
            }
            if (liveIn.isEmpty()) { skipped++; continue; }

            if (liveIn.size() > maxParams) {
                detail.add(String.format("%s@%s too many live-in (%d)", nm, f.getEntryPoint(), liveIn.size()));
                continue;
            }

            if (apply) {
                try {
                    List<Parameter> params = new ArrayList<>();
                    int i = 0;
                    for (String r : liveIn) {
                        Register reg = currentProgram.getRegister(r);
                        if (reg == null) continue;
                        params.add(new ParameterImpl("in_" + r, voidPtr, reg, currentProgram));
                        i++;
                    }
                    if (!params.isEmpty()) {
                        f.replaceParameters(params, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                                true, SourceType.USER_DEFINED);
                        fixed++;
                        detail.add(String.format("%s@%s <- %s", nm, f.getEntryPoint(), liveIn));
                    }
                } catch (Exception e) {
                    detail.add("FAIL " + nm + ": " + e.getMessage());
                }
            } else {
                fixed++;
                detail.add(String.format("%s@%s <- %s", nm, f.getEntryPoint(), liveIn));
            }
        }

        println(String.format("scanned=%d fixed=%d skipped=%d apply=%s", scanned, fixed, skipped, apply));
        for (int i = 0; i < Math.min(detail.size(), 60); i++) println("  " + detail.get(i));
    }
}
