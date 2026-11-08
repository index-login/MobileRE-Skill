// so_vm_split_handlers.java — 把 VM 解释器大函数按 opcode 跳转表拆成独立 handler 函数
//
// 背景：
//   so_boundary_rebuild.java 的碎片合并把 0x1bd8a8..0x1c474f（26KB）整块并成了一个
//   frag_1bd8a8 函数，导致 228 个 handler 共用一份伪代码，无法分析。
//
// 做法：
//   1) 读 opcode 跳转表（256 项 x 8 字节），收集所有落在解释器范围内的 handler 入口
//   2) 从 frag_1bd8a8 里按 handler 入口切分：每个入口建独立函数
//   3) 命名 op_<hex>，并加注释说明它是第几个 opcode 的 handler
//
// 参数（配置文件 $TMP/so_vm_split.cfg）：
//   table_va    跳转表 vaddr（Ghidra 地址空间）
//   table_n     表项数（默认 256）
//   big_func    被过度合并的大函数入口
//   range_lo    解释器范围下界
//   range_hi    解释器范围上界
//@category MobileRE

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import java.io.File;
import java.nio.file.Files;
import java.util.*;

public class so_vm_split_handlers extends GhidraScript {

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
        File cfgf = new File(tmp, "so_vm_split.cfg");
        Properties cfg = new Properties();
        if (cfgf.isFile()) {
            try (java.io.InputStream in = Files.newInputStream(cfgf.toPath())) {
                cfg.load(in);
            }
        }

        long tableVa = cfgLong(cfg, "table_va", 0x1f3af0L);
        int tableN = (int) cfgLong(cfg, "table_n", 256);
        long bigFunc = cfgLong(cfg, "big_func", 0x1bd8a8L);
        long rangeLo = cfgLong(cfg, "range_lo", 0x1bd8a8L);
        long rangeHi = cfgLong(cfg, "range_hi", 0x1c474fL);

        println(String.format("table=%#x n=%d big=%#x range=%#x..%#x",
                tableVa, tableN, bigFunc, rangeLo, rangeHi));

        Memory mem = currentProgram.getMemory();
        FunctionManager fm = currentProgram.getFunctionManager();
        Address bigAddr = toAddr(bigFunc);
        Function big = fm.getFunctionAt(bigAddr);
        if (big == null) {
            println("[!] 大函数不存在: " + bigAddr);
            return;
        }
        println("大函数: " + big.getName() + "  " + big.getBody().getNumAddresses() + " bytes");

        // 1) 收集 handler 入口
        TreeMap<Long, List<Integer>> entries = new TreeMap<>();
        for (int i = 0; i < tableN; i++) {
            long v;
            try {
                v = mem.getLong(toAddr(tableVa + i * 8L));
            } catch (Exception e) {
                continue;
            }
            if (v < rangeLo || v > rangeHi) continue;
            entries.computeIfAbsent(v, k -> new ArrayList<>()).add(i);
        }
        println("表内落在解释器范围的 handler 入口: " + entries.size());

        // 2) 切分：从大函数里删除覆盖区，再按入口逐个建函数
        //    先记录大函数原来的名字与入口，最后重建
        String bigName = big.getName();
        long bigSize = big.getBody().getNumAddresses();

        // 删除大函数（只解除代码归属，不删指令）
        fm.removeFunction(bigAddr);
        println("已移除 " + bigName);

        // 3) 逐个建函数
        int made = 0, failed = 0;
        for (Map.Entry<Long, List<Integer>> e : entries.entrySet()) {
            long va = e.getKey();
            List<Integer> ops = e.getValue();
            Address a = toAddr(va);
            try {
                Function f = fm.getFunctionAt(a);
                if (f == null) {
                    f = createFunction(a, null);
                }
                if (f == null) {
                    failed++;
                    continue;
                }
                // 命名：op_<主opcode>，多 opcode 共用时加别名后缀
                int primary = ops.get(0);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < Math.min(ops.size(), 4); i++) {
                    if (i > 0) sb.append('_');
                    sb.append(String.format("%02x", ops.get(i)));
                }
                String nm = String.format("vm_op_%s", sb);
                try {
                    f.setName(nm, SourceType.USER_DEFINED);
                } catch (Exception ex) {
                    // 重名忽略
                }
                if (ops.size() > 1) {
                    f.setComment(String.format("VM handler for opcodes %s",
                            ops.toString()));
                }
                made++;
            } catch (Exception ex) {
                failed++;
            }
        }

        println(String.format("建成 handler 函数 %d 个，失败 %d", made, failed));

        // 4) 剩余未被 handler 覆盖的区间：重建为一个「解释器骨架」函数
        //    （序言 + 回分派代码）
        try {
            Function sk = createFunction(toAddr(bigFunc), bigName + "_skeleton");
            if (sk != null) {
                println("骨架函数: " + sk.getName());
            }
        } catch (Exception ex) {
            println("骨架函数创建失败: " + ex.getMessage());
        }

        println("函数总数: " + fm.getFunctionCount());
    }
}
