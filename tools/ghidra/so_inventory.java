// so_inventory.java -- export a complete per-function ledger for a SO program
//
// Purpose: stop re-analysing the same functions. Emits one TSV row per
// non-external function with every fact a later pass needs (size, arity,
// callers, callees, referenced strings, machine-shape fingerprint).
// The companion analyser is tools/so_ledger.py, which turns the TSV into an
// evidence-tiered work queue and a rename proposal.
//
// Config: $TMP/so_inventory.cfg
//   out=<path>        ledger TSV output (default $TMP/so_inventory.tsv)
//   shapes_out=<path> shape fingerprint TSV (default $TMP/so_shapes.tsv)
//   str_max=300       max bytes of collected string refs per function
//   callee_max=400    max bytes of callee name list per function
//
// Columns (ledger):
//   addr name size insns nparam params ret callers callees
//   nCodeRefs nDataRefs refFromFuncs strings calleeNames
//
// Columns (shapes):
//   addr name size insns shape
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import java.io.*;
import java.security.MessageDigest;
import java.util.*;

public class so_inventory extends GhidraScript {

    private static final Set<String> EXTERNAL_PREFIX = new HashSet<>(Arrays.asList(
            "__", "_Z", "_Unwind", "pthread_", "dl", "sig"));

    private String cfg(String key, String dflt) {
        String tmp = System.getenv("TMP");
        if (tmp == null) tmp = System.getProperty("java.io.tmpdir");
        File f = new File(tmp, "so_inventory.cfg");
        if (!f.isFile()) return dflt;
        Properties p = new Properties();
        try (InputStream in = new FileInputStream(f)) { p.load(in); } catch (Exception e) { return dflt; }
        return p.getProperty(key, dflt);
    }

    /** Normalise an instruction to mnemonic + operand shape (drop immediates and symbols). */
    private String shapeOf(Instruction ins) {
        StringBuilder ops = new StringBuilder();
        for (int op = 0; op < ins.getNumOperands(); op++) {
            String s = ins.getDefaultOperandRepresentation(op);
            if (s == null) continue;
            s = s.replaceAll("0x[0-9a-fA-F]+", "#")
                 .replaceAll("\\b(DAT|LAB|FUN|PTR|UNK)_[0-9a-fA-F]+", "#")
                 .replaceAll("\\b[A-Za-z_]*(Stack|uStack|local|param|in_stack)_[0-9a-fA-Fx]+", "#")
                 .replaceAll("[0-9]+", "#");
            ops.append(s).append(',');
        }
        return ins.getMnemonicString() + " " + ops + ";";
    }

    @Override
    public void run() throws Exception {
        String ledgerPath = cfg("out", new File(System.getProperty("java.io.tmpdir"), "so_inventory.tsv").getPath());
        String shapesPath = cfg("shapes_out", new File(System.getProperty("java.io.tmpdir"), "so_shapes.tsv").getPath());
        int strMax = Integer.parseInt(cfg("str_max", "300"));
        int calleeMax = Integer.parseInt(cfg("callee_max", "400"));

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing lst = currentProgram.getListing();

        PrintWriter lw = new PrintWriter(new OutputStreamWriter(new FileOutputStream(ledgerPath), "UTF-8"));
        PrintWriter sw = new PrintWriter(new OutputStreamWriter(new FileOutputStream(shapesPath), "UTF-8"));
        lw.println("addr\tname\tsize\tinsns\tnparam\tparams\tret\tcallers\tcallees\tnCodeRefs\tnDataRefs\trefFromFuncs\tstrings\tcalleeNames\tparentNs");
        sw.println("addr\tname\tsize\tinsns\tshape");

        int rows = 0;
        for (Function f : fm.getFunctions(true)) {
            if (f.isExternal()) continue;

            // ---- body walk: instruction count + string refs + shape ----
            int insnCount = 0;
            StringBuilder strings = new StringBuilder();
            StringBuilder shape = new StringBuilder();
            Set<String> seenStr = new LinkedHashSet<>();
            Instruction ins = lst.getInstructionAt(f.getEntryPoint());
            while (ins != null && insnCount < 20000 && f.getBody().contains(ins.getAddress())) {
                insnCount++;
                shape.append(shapeOf(ins));
                if (strings.length() < strMax) {
                    for (Reference r : ins.getReferencesFrom()) {
                        Data d = getDataAt(r.getToAddress());
                        if (d != null && d.getValue() instanceof String) {
                            String v = (String) d.getValue();
                            if (v.length() >= 4 && v.length() < 80 && seenStr.add(v)) {
                                strings.append(v.replace('\t', ' ')).append(';');
                            }
                        }
                    }
                }
                ins = ins.getNext();
            }

            // ---- refs TO entry ----
            int nCode = 0, nData = 0;
            Set<String> refOwners = new LinkedHashSet<>();
            for (Reference r : getReferencesTo(f.getEntryPoint())) {
                if (r.getReferenceType().isData()) nData++; else nCode++;
                Function o = fm.getFunctionContaining(r.getFromAddress());
                if (o != null && refOwners.size() < 12) refOwners.add(o.getName());
            }

            // ---- signature ----
            StringBuilder params = new StringBuilder();
            for (Parameter p : f.getParameters()) {
                if (params.length() > 0) params.append('|');
                params.append(p.getName());
            }

            // ---- graph ----
            int nCallers = 0;
            for (Function c : f.getCallingFunctions(monitor)) nCallers++;
            StringBuilder callees = new StringBuilder();
            int nCallees = 0;
            for (Function c : f.getCalledFunctions(monitor)) {
                nCallees++;
                if (callees.length() < calleeMax) {
                    if (callees.length() > 0) callees.append('|');
                    callees.append(c.getName());
                }
            }

            // ---- parent namespace (CFF case blocks live under switchD_*) ----
            String parentNs = "";
            try {
                Namespace ns = f.getParentNamespace();
                if (ns != null && !ns.isGlobal()) parentNs = ns.getName();
            } catch (Throwable t) { }

            lw.println(String.format("%s\t%s\t%d\t%d\t%d\t%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s",
                    f.getEntryPoint(), f.getName(), f.getBody().getNumAddresses(), insnCount,
                    f.getParameterCount(), params, f.getReturnType().getName(), nCallers, nCallees,
                    nCode, nData, String.join("|", refOwners), strings, callees, parentNs));

            String h;
            try {
                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] dg = md.digest(shape.toString().getBytes("UTF-8"));
                StringBuilder hx = new StringBuilder();
                for (int i = 0; i < 8; i++) hx.append(String.format("%02x", dg[i]));
                h = hx.toString();
            } catch (Exception e) { h = "err"; }
            sw.println(f.getEntryPoint() + "\t" + f.getName() + "\t" + f.getBody().getNumAddresses()
                    + "\t" + insnCount + "\t" + h);
            rows++;
        }
        lw.close();
        sw.close();
        println("so_inventory: rows=" + rows);
        println("  ledger=" + ledgerPath);
        println("  shapes=" + shapesPath);
    }
}
