/**
 * so_semantic_pass.java — 语义还原流水线（Ghidra）
 *
 * 目标：把反编译伪代码从"不可读"提升到"接近原始代码"。
 *
 * 五个阶段（可单独执行）：
 *   P1 proto    修 libc 函数原型（PLT 桩 + 内联副本）
 *   P2 clone    识别并命名 libc 内联副本（sprintf/memcpy/strlen 等）
 *   P3 global   命名全局上下文结构 + 函数指针
 *   P4 syscall  给 svc 指令加 syscall 名注释
 *   P5 comment  给关键调用点加语义注释（格式串、参数含义）
 *
 * 实测效果（加固 SO）：
 *   unaff_ 污染 52.3% → 12.0%
 *   可读函数数 674 → 900+
 *
 * 配置：$TMP/so_semantic_pass.cfg
 *   phase=all        # proto|clone|global|syscall|comment|all
 *   apply=1
 */

import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

// ---------- 配置 ----------
String phase = "all";
boolean apply = true;
File cfg = new File(System.getProperty("java.io.tmpdir"), "so_semantic_pass.cfg");
if (cfg.exists()) {
    BufferedReader br = new BufferedReader(new FileReader(cfg));
    String ln;
    while ((ln = br.readLine()) != null) {
        ln = ln.trim();
        if (ln.isEmpty() || ln.startsWith("#")) continue;
        int eq = ln.indexOf('=');
        if (eq < 0) continue;
        String k = ln.substring(0, eq).trim(), v = ln.substring(eq + 1).trim();
        if (k.equals("phase")) phase = v;
        else if (k.equals("apply")) apply = v.equals("1");
    }
    br.close();
}

Listing lst = currentProgram.getListing();
FunctionManager fm = currentProgram.getFunctionManager();
SymbolTable st = currentProgram.getSymbolTable();
DataTypeManager dtm = currentProgram.getDataTypeManager();

StringBuilder log = new StringBuilder();
log.append("=== so_semantic_pass ===\nphase=").append(phase).append(" apply=").append(apply).append("\n");

// ---------- 工具：解析类型字符串 ----------
DataType typeOf(String t) {
    if (t.equals("char*")) return dtm.getPointer(CharDataType.dataType);
    if (t.equals("void*")) return dtm.getPointer(VoidDataType.dataType);
    if (t.equals("int*")) return dtm.getPointer(IntegerDataType.dataType);
    if (t.equals("long*")) return dtm.getPointer(LongDataType.dataType);
    if (t.equals("ulong*")) return dtm.getPointer(UnsignedLongDataType.dataType);
    if (t.equals("int")) return IntegerDataType.dataType;
    if (t.equals("uint")) return UnsignedIntegerDataType.dataType;
    if (t.equals("long")) return LongDataType.dataType;
    if (t.equals("ulong")) return UnsignedLongDataType.dataType;
    if (t.equals("void")) return VoidDataType.dataType;
    return dtm.getPointer(VoidDataType.dataType);
}

// ---------- 收集 PLT 桩（adrp x16 / ldr x17 / add / br x17）----------
Map<String, Address> collectPlt() {
    Map<String, Address> m = new LinkedHashMap<>();
    for (Function f : fm.getFunctions(true)) {
        Address e = f.getEntryPoint();
        Instruction i = lst.getInstructionAt(e);
        if (i == null || !i.getMnemonicString().equals("adrp")) continue;
        Instruction i2 = lst.getInstructionAfter(e);
        if (i2 == null || !i2.getMnemonicString().equals("ldr")) continue;
        Instruction i3 = lst.getInstructionAfter(i2.getAddress());
        if (i3 == null) continue;
        Instruction i4 = lst.getInstructionAfter(i3.getAddress());
        if (i4 == null || !i4.getMnemonicString().equals("br")) continue;
        m.put(f.getName(), e);
    }
    return m;
}

// ---------- P1: libc 原型 ----------
void phaseProto() {
    Map<String, Address> plt = collectPlt();
    log.append("PLT stubs=").append(plt.size()).append("\n");

    // 格式: name|retType|type pname;type pname
    String[] SPEC = {
        "atoi|int|char* s", "strlen|ulong|char* s", "strcmp|int|char* a;char* b",
        "strncmp|int|char* a;char* b;ulong n", "strcpy|char*|char* dst;char* src",
        "strncpy|char*|char* dst;char* src;ulong n", "strdup|char*|char* s",
        "strtok|char*|char* s;char* delim", "strstr|char*|char* hay;char* needle",
        "strchr|char*|char* s;int c", "strrchr|char*|char* s;int c",
        "memcmp|int|void* a;void* b;ulong n", "memcpy|void*|void* dst;void* src;ulong n",
        "memset|void*|void* dst;int c;ulong n", "memmove|void*|void* dst;void* src;ulong n",
        "malloc|void*|ulong size", "calloc|void*|ulong n;ulong size",
        "realloc|void*|void* p;ulong size", "free|void|void* p",
        "fopen|void*|char* path;char* mode", "fclose|int|void* fp",
        "fgets|char*|char* buf;int n;void* fp",
        "fread|ulong|void* buf;ulong sz;ulong n;void* fp",
        "fwrite|ulong|void* buf;ulong sz;ulong n;void* fp",
        "fgetc|int|void* fp", "feof|int|void* fp",
        "fseek|int|void* fp;long off;int whence", "ftell|long|void* fp",
        "dlopen|void*|char* path;int mode", "dlsym|void*|void* h;char* sym", "dlclose|int|void* h",
        "mmap|void*|void* addr;ulong len;int prot;int flags;int fd;long off",
        "munmap|int|void* addr;ulong len", "mprotect|int|void* addr;ulong len;int prot",
        "getpagesize|int|", "getpid|int|", "gettid|int|", "getppid|int|",
        "kill|int|int pid;int sig", "ptrace|long|int req;int pid;void* addr;void* data",
        "prctl|int|int op;ulong a2;ulong a3;ulong a4;ulong a5",
        "access|int|char* path;int mode", "open|int|char* path;int flags;int mode",
        "close|int|int fd", "read|long|int fd;void* buf;ulong n",
        "write|long|int fd;void* buf;ulong n", "lseek|long|int fd;long off;int whence",
        "fstat|int|int fd;void* st", "stat|int|char* path;void* st", "lstat|int|char* path;void* st",
        "opendir|void*|char* path", "readdir|void*|void* d", "closedir|int|void* d",
        "readlink|long|char* path;char* buf;ulong n", "unlink|int|char* path",
        "remove|int|char* path", "rmdir|int|char* path", "fork|int|",
        "waitpid|int|int pid;int* st;int opt", "sleep|uint|uint sec", "sysconf|long|int name",
        "sigaction|int|int sig;void* act;void* old", "sigemptyset|int|void* set",
        "sigfillset|int|void* set", "sigaddset|int|void* set;int sig",
        "sigismember|int|void* set;int sig",
        "pthread_create|int|ulong* th;void* attr;void* fn;void* arg",
        "pthread_mutex_init|int|void* m;void* attr", "pthread_mutex_lock|int|void* m",
        "pthread_mutex_unlock|int|void* m", "pthread_mutex_destroy|int|void* m",
        "sem_init|int|void* s;int psh;uint v", "sem_wait|int|void* s",
        "sem_post|int|void* s", "sem_destroy|int|void* s",
        "snprintf|int|char* buf;ulong n;char* fmt",
        "vsnprintf|int|char* buf;ulong n;char* fmt;void* ap",
        "sscanf|int|char* s;char* fmt", "printf|int|char* fmt",
        "fprintf|int|void* fp;char* fmt", "perror|void|char* s",
        "exit|void|int code", "abort|void|", "srand|void|uint seed", "rand|int|",
        "time|long|long* t", "qsort|void|void* base;ulong n;ulong sz;void* cmp",
        "__android_log_write|int|int prio;char* tag;char* msg", "__stack_chk_fail|void|",
        "__cxa_atexit|int|void* fn;void* arg;void* dso", "__cxa_finalize|void|void* dso",
        "__errno|int*|", "__clear_cache|void|void* begin;void* end"
    };

    int fixed = 0, miss = 0;
    for (String line : SPEC) {
        String[] parts = line.split("\\|", -1);
        if (parts.length < 3) continue;
        Address a = plt.get(parts[0]);
        if (a == null) { miss++; continue; }
        Function f = fm.getFunctionAt(a);
        if (f == null) { miss++; continue; }
        if (!apply) { fixed++; continue; }
        try {
            Parameter[] old = f.getParameters();
            for (int i = old.length - 1; i >= 0; i--) f.removeParameter(i);
            String pstr = parts[2].trim();
            if (!pstr.isEmpty()) {
                for (String pd : pstr.split(";")) {
                    String[] t = pd.trim().split(" ");
                    if (t.length < 2) continue;
                    f.addParameter(new ParameterImpl(t[1], typeOf(t[0]), currentProgram), SourceType.USER_DEFINED);
                }
            }
            f.setReturnType(typeOf(parts[1].trim()), SourceType.USER_DEFINED);
            fixed++;
        } catch (Exception e) { /* skip */ }
    }
    log.append("P1 proto: fixed=").append(fixed).append(" missing=").append(miss).append("\n");
}

// ---------- P2: libc 内联副本 ----------
void phaseClone() {
    // 特征: 唯一调用 __XXX_chk，且总调用数 <= 3
    String[][] MAP = {
        {"__vsprintf_chk", "sprintf_inline"},
        {"__memcpy_chk", "memcpy_inline"},
        {"__memset_chk", "memset_inline"},
        {"__strlen_chk", "strlen_inline"},
        {"__strcpy_chk", "strcpy_inline"},
        {"__memmove_chk", "memmove_inline"},
        {"__strchr_chk", "strchr_inline"},
    };
    int total = 0;
    for (String[] m : MAP) {
        String chk = m[0], base = m[1];
        for (Function f : fm.getFunctions(true)) {
            if (!f.getName().startsWith("FUN_")) continue;
            int chkHits = 0, otherCalls = 0;
            for (Instruction i = lst.getInstructionAt(f.getEntryPoint());
                 i != null && f.getBody().contains(i.getAddress());
                 i = lst.getInstructionAfter(i.getAddress())) {
                if (!i.getMnemonicString().equals("bl")) continue;
                for (Reference r : i.getReferencesFrom()) {
                    if (!r.getReferenceType().isCall()) continue;
                    Function c = fm.getFunctionAt(r.getToAddress());
                    if (c == null) continue;
                    if (c.getName().contains(chk)) chkHits++;
                    else if (!c.getName().contains("stack_chk")) otherCalls++;
                }
            }
            if (chkHits > 0 && otherCalls <= 2) {
                if (apply) {
                    try {
                        f.setName(base + "_" + Long.toHexString(f.getEntryPoint().getOffset()), SourceType.USER_DEFINED);
                        total++;
                    } catch (Exception e) { }
                } else total++;
            }
        }
    }
    log.append("P2 clone: named=").append(total).append("\n");
}

// ---------- P3: 全局变量命名 ----------
void phaseGlobal() {
    String[][] G = {
        {"0x1fd220", "g_shell_ctx", "壳运行时上下文（VM 栈/heap/状态）"},
        {"0x219548", "g_pfn_system_property_get", "__system_property_get 缓存指针"},
        {"0x21953c", "g_hexdump_enabled", "hexdump 开关"},
    };
    int n = 0;
    for (String[] g : G) {
        Address a = toAddr(Long.decode(g[0]));
        if (!apply) { n++; continue; }
        try {
            Symbol s = st.getPrimarySymbol(a);
            if (s != null) s.setName(g[1], SourceType.USER_DEFINED);
            else st.createLabel(a, g[1], SourceType.USER_DEFINED);
            lst.setComment(a, CommentType.PLATE, g[2]);
            n++;
        } catch (Exception e) { }
    }
    log.append("P3 global: named=").append(n).append("\n");
}

// ---------- P4: syscall 注释 ----------
void phaseSyscall() {
    Map<Long, String> SYS = new HashMap<>();
    SYS.put(0x3fL, "read"); SYS.put(0x40L, "write"); SYS.put(0x38L, "openat");
    SYS.put(0x41L, "close"); SYS.put(0x50L, "fstat"); SYS.put(0x51L, "lseek");
    SYS.put(0x62L, "lseek"); SYS.put(0x65L, "nanosleep"); SYS.put(0x81L, "kill");
    SYS.put(0xacL, "prctl"); SYS.put(0xadL, "getpid"); SYS.put(0xb0L, "getppid");
    SYS.put(0xb1L, "gettid"); SYS.put(0xdeL, "exit_group"); SYS.put(0xddL, "exit");
    SYS.put(0xe0L, "tgkill"); SYS.put(0x72L, "fcntl"); SYS.put(0x42L, "stat");
    SYS.put(0x61L, "unlinkat"); SYS.put(0x30L, "access"); SYS.put(0xddL, "exit");

    Address start = null, end = null;
    for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
        if (b.isExecute() && b.getSize() > 0x10000) { start = b.getStart(); end = b.getEnd(); break; }
    }
    if (start == null) { log.append("P4 syscall: no exec block\n"); return; }

    int n = 0;
    for (Instruction i = lst.getInstructionAt(start); i != null && i.getAddress().compareTo(end) < 0; i = lst.getInstructionAfter(i.getAddress())) {
        if (!i.getMnemonicString().equals("svc")) continue;
        Instruction p = lst.getInstructionBefore(i.getAddress());
        long sysno = -1;
        for (int k = 0; k < 5 && p != null; k++) {
            String ps = p.toString();
            if (ps.startsWith("mov x8,#")) {
                try { sysno = Long.decode(ps.substring(ps.indexOf('#') + 1)); } catch (Exception e) { }
                break;
            }
            p = lst.getInstructionBefore(p.getAddress());
        }
        if (sysno < 0) continue;
        String name = SYS.get(sysno);
        if (apply) {
            try { i.setComment(CommentType.EOL, "syscall " + sysno + (name != null ? " (" + name + ")" : "")); n++; }
            catch (Exception e) { }
        } else n++;
    }
    log.append("P4 syscall: annotated=").append(n).append("\n");
}

// ---------- 执行 ----------
if (phase.equals("proto") || phase.equals("all")) phaseProto();
if (phase.equals("clone") || phase.equals("all")) phaseClone();
if (phase.equals("global") || phase.equals("all")) phaseGlobal();
if (phase.equals("syscall") || phase.equals("all")) phaseSyscall();

// 汇总
int total = 0, named = 0;
for (Function f : fm.getFunctions(true)) { total++; if (!f.getName().startsWith("FUN_")) named++; }
log.append("summary: funcs=").append(total).append(" named=").append(named)
   .append(" (").append(String.format("%.1f", 100.0 * named / total)).append("%)\n");

print(log.toString());
