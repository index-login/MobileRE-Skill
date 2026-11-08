/*
 * loader.c - zygote loader（B 方案）
 *
 * 目标：不依赖现成框架 / 管理 App，一次性注入 zygote 后，在每个 fork 出的
 *       App 子进程里按配置 dlopen gadget。
 *
 * 两种构建：
 *   python3 tools/inject/build.py            # 阶段 1：只观察（默认，不替换任何指针）
 *   python3 tools/inject/build.py --hook     # 阶段 2：启用 hook
 *
 * 安全开关：文件 /data/local/tmp/loader.on 不存在时，constructor 直接返回。
 * 阶段 1 输出（logcat -s mrx_loader）：
 *   [i] class=0x... method=0x... jni_slot=NN jni_fn=0x... (in libart)
 *
 * 配置（constructor 里读取并缓存；zygote 在注入期可读，子进程沿用内存副本）：
 *   /data/local/tmp/loader.conf
 *     targets=com.foo,com.bar        # 空=全部
 *     gadget=/data/data/%s/libx.so   # %s 会被替换为目标包名，必须目标进程可读
 *
 * 限制：
 *   - 只适配 Android 10（nativeForkAndSpecialize 13 参签名）；
 *   - gadget 路径必须目标 App 可读（放它自己的私有目录）；
 *   - 阶段 2 未在真机验证，启用前先跑阶段 1 确认 jni_slot 正确。
 */
#include <android/log.h>
#include <dlfcn.h>
#include <jni.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#define TAG "mrx_loader"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)


/* ---- 在内存里解析 libart 的导出符号（绕开 linker namespace） ---- */
static uint32_t gnu_hash(const char *s) {
    uint32_t h = 5381;
    while (*s) h = (h * 33) + (uint8_t)*s++;
    return h;
}

static uintptr_t find_lib_base(const char *name) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (f == NULL) return 0;
    char line[512];
    uintptr_t best = 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strstr(line, name) == NULL) continue;
        uintptr_t a = (uintptr_t)strtoull(line, NULL, 16);
        if (best == 0 || a < best) best = a;
    }
    fclose(f);
    return best;
}

static int elf_lookup(uintptr_t base, const char *name, uintptr_t *out) {
    if (base == 0) return -1;
    const ElfW(Ehdr) *eh = (const ElfW(Ehdr) *)base;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return -1;

    const ElfW(Dyn) *dyn = NULL;
    for (int i = 0; i < eh->e_phnum; i++) {
        const ElfW(Phdr) *ph = (const ElfW(Phdr) *)(base + eh->e_phoff + i * eh->e_phentsize);
        if (ph->p_type == PT_DYNAMIC) { dyn = (const ElfW(Dyn) *)(base + ph->p_vaddr); break; }
    }
    if (dyn == NULL) return -1;

    uintptr_t symtab = 0, strtab = 0, gnu = 0;
    for (const ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
        uintptr_t v = (uintptr_t)d->d_un.d_ptr;
        if (v < base) v += base;
        if (d->d_tag == DT_SYMTAB) symtab = v;
        else if (d->d_tag == DT_STRTAB) strtab = v;
        else if (d->d_tag == DT_GNU_HASH) gnu = v;
    }
    if (symtab == 0 || strtab == 0 || gnu == 0) return -1;

    const uint32_t *gh = (const uint32_t *)gnu;
    uint32_t nbuckets = gh[0], symoffset = gh[1], bloom_size = gh[2], bloom_shift = gh[3];
    const ElfW(Addr) *bloom = (const ElfW(Addr) *)(gh + 4);
    const uint32_t *buckets = (const uint32_t *)(bloom + bloom_size);
    const uint32_t *chain = buckets + nbuckets;

    uint32_t h = gnu_hash(name);
    uint32_t wordbits = 8 * sizeof(ElfW(Addr));
    ElfW(Addr) w = bloom[(h / wordbits) % bloom_size];
    ElfW(Addr) mask = ((ElfW(Addr))1 << (h % wordbits)) | ((ElfW(Addr))1 << ((h >> bloom_shift) % wordbits));
    if ((w & mask) != mask) return -1;

    uint32_t idx = buckets[h % nbuckets];
    if (idx < symoffset) return -1;
    for (;;) {
        uint32_t cv = chain[idx - symoffset];
        const ElfW(Sym) *sym = (const ElfW(Sym) *)(symtab + (uintptr_t)idx * sizeof(ElfW(Sym)));
        const char *sname = (const char *)(strtab + sym->st_name);
        if (((cv | 1) == (h | 1)) && strcmp(sname, name) == 0) {
            *out = base + sym->st_value;
            return 0;
        }
        if (cv & 1) break;
        idx++;
    }
    return -1;
}

/* Android 10：比 11+ 少了 is_top_app / pkg_data_info_list / whitelisted_data_info_list / ZZ */
#define SIG_FORK10 "(II[II[[IILjava/lang/String;Ljava/lang/String;[I[IZLjava/lang/String;Ljava/lang/String;)I"

static char g_targets[512];
static char g_gadget[512];
static int g_enabled = 0;

static void load_conf(void) {
    FILE *f = fopen("/data/local/tmp/loader.conf", "r");
    if (f == NULL) return;
    char line[600];
    while (fgets(line, sizeof(line), f) != NULL) {
        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        if (strncmp(line, "targets=", 8) == 0) snprintf(g_targets, sizeof(g_targets), "%s", line + 8);
        else if (strncmp(line, "gadget=", 7) == 0) snprintf(g_gadget, sizeof(g_gadget), "%s", line + 7);
    }
    fclose(f);
}

static int in_targets(const char *pkg) {
    if (pkg == NULL) return 0;
    if (g_targets[0] == '\0') return 1;
    const char *p = g_targets;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t n = comma ? (size_t)(comma - p) : strlen(p);
        if (n == strlen(pkg) && strncmp(p, pkg, n) == 0) return 1;
        if (!comma) break;
        p = comma + 1;
    }
    return 0;
}

/* 收集所有模块的可执行区间：JNI 函数可能不在 libart（例：Zygote 的方法注册在 libandroid_runtime） */
#define MAX_EXEC_RANGES 96
struct exec_ranges { uintptr_t lo[MAX_EXEC_RANGES], hi[MAX_EXEC_RANGES]; int n; };

static int phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    if (info->dlpi_name == NULL) return 0;
    struct exec_ranges *r = (struct exec_ranges *)data;
    for (int i = 0; i < info->dlpi_phnum && r->n < MAX_EXEC_RANGES; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X)) continue;
        r->lo[r->n] = info->dlpi_addr + ph->p_vaddr;
        r->hi[r->n] = r->lo[r->n] + ph->p_memsz;
        r->n++;
    }
    return 0;
}

static int in_exec_range(const struct exec_ranges *r, uintptr_t v) {
    for (int i = 0; i < r->n; i++) if (v >= r->lo[i] && v < r->hi[i]) return 1;
    return 0;
}

static int find_jni_slot(uintptr_t *art_method, const struct exec_ranges *r, uintptr_t *out_fn) {
    /* native 方法的 JNI 函数指针位于 ArtMethod 的某个字；逐个比较是否落在 libart 代码段 */
    for (int i = 0; i < 40; i++) {
        uintptr_t v = art_method[i];
        if (in_exec_range(r, v)) {
            *out_fn = v;
            return i;
        }
    }
    return -1;
}

#ifdef LOADER_HOOK
typedef jint (*fork_fn)(JNIEnv *, jclass, jint, jint, jintArray, jint, jobjectArray, jint,
                        jstring, jstring, jintArray, jintArray, jboolean, jstring, jstring);
static fork_fn g_orig_fork = NULL;
static uintptr_t *g_art_method = NULL;
static uintptr_t g_orig_slot_val = 0;
static int g_jni_slot = -1;

static void load_gadget(const char *pkg) {
    char path[600];
    if (strstr(g_gadget, "%s") != NULL) snprintf(path, sizeof(path), g_gadget, pkg);
    else snprintf(path, sizeof(path), "%s", g_gadget);
    void *h = dlopen(path, RTLD_NOW);
    if (h == NULL) LOGE("gadget dlopen(%s) failed: %s", path, dlerror());
    else LOGI("gadget loaded %s -> %p (pid=%d)", path, h, getpid());
}

static jint hook_fork(JNIEnv *env, jclass clazz, jint uid, jint gid, jintArray gids, jint runtime_flags,
                      jobjectArray rlimits, jint mount_external, jstring se_info, jstring nice_name,
                      jintArray fds_to_close, jintArray fds_to_ignore, jboolean is_child_zygote,
                      jstring instruction_set, jstring app_data_dir) {
    jint pid = g_orig_fork(env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external,
                           se_info, nice_name, fds_to_close, fds_to_ignore, is_child_zygote,
                           instruction_set, app_data_dir);
    if (pid == 0 && g_enabled) {
        const char *pkg = nice_name ? (*env)->GetStringUTFChars(env, nice_name, NULL) : NULL;
        if (in_targets(pkg)) load_gadget(pkg ? pkg : "");
        if (pkg) (*env)->ReleaseStringUTFChars(env, nice_name, pkg);
        /* 子进程里恢复原 JNI 指针，避免影响本进程后续的 fork 逻辑 */
        if (g_art_method != NULL && g_jni_slot >= 0) g_art_method[g_jni_slot] = g_orig_slot_val;
    }
    return pid;
}
#endif

__attribute__((constructor)) static void loader_init(void) {
    if (access("/data/local/tmp/loader.on", F_OK) != 0) {
        LOGI("disabled (no /data/local/tmp/loader.on)");
        return;
    }
    load_conf();
    g_enabled = 1;

    /* JNI_GetCreatedJavaVMs 由 libart 导出；本库不链接 libart，运行时用 dlsym 取 */
    typedef jint (*get_vms_fn)(JavaVM **, jsize, jsize *);
    uintptr_t fn_addr = 0;
    if (elf_lookup(find_lib_base("libart.so"), "JNI_GetCreatedJavaVMs", &fn_addr) != 0) {
        void *art = dlopen("libart.so", RTLD_NOW);
        if (art != NULL) fn_addr = (uintptr_t)dlsym(art, "JNI_GetCreatedJavaVMs");
    }
    if (fn_addr == 0) { LOGE("JNI_GetCreatedJavaVMs not resolved"); return; }
    get_vms_fn get_vms = (get_vms_fn)fn_addr;
    JavaVM *vm = NULL;
    jsize n = 0;
    if (get_vms(&vm, 1, &n) != JNI_OK || n < 1) {
        LOGE("no JavaVM (pid=%d)", getpid());
        return;
    }
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        if ((*vm)->AttachCurrentThread(vm, &env, NULL) != JNI_OK) {
            LOGE("AttachCurrentThread failed");
            return;
        }
    }
    jclass zc = (*env)->FindClass(env, "com/android/internal/os/Zygote");
    if (zc == NULL) { LOGE("Zygote class not found"); return; }
    jmethodID mid = (*env)->GetStaticMethodID(env, zc, "nativeForkAndSpecialize", SIG_FORK10);
    if (mid == NULL) { LOGE("method not found (signature mismatch?)"); return; }

    struct exec_ranges r;
    memset(&r, 0, sizeof(r));
    dl_iterate_phdr(phdr_cb, &r);
    if (r.n == 0) { LOGE("no exec ranges"); return; }

    uintptr_t *am = (uintptr_t *)mid;
    uintptr_t jni_fn = 0;
    int slot = find_jni_slot(am, &r, &jni_fn);
    LOGI("class=%p method=%p exec_ranges=%d jni_slot=%d jni_fn=%p",
         (void *)zc, (void *)mid, r.n, slot, (void *)jni_fn);
    LOGI("art_words: %p %p %p %p %p %p %p %p", (void *)am[0], (void *)am[1], (void *)am[2], (void *)am[3],
         (void *)am[4], (void *)am[5], (void *)am[6], (void *)am[7]);
    if (slot < 0) { LOGE("jni slot not found (unsupported layout?)"); return; }

#ifdef LOADER_HOOK
    g_jni_slot = slot;
    g_art_method = am;
    g_orig_slot_val = am[slot];
    g_orig_fork = (fork_fn)jni_fn;
    /* ArtMethod 在 boot image（r--）里，写前先把它所在页改成可写（COW） */
    long ps = sysconf(_SC_PAGESIZE);
    uintptr_t page = ((uintptr_t)&am[slot]) & ~((uintptr_t)ps - 1);
    if (mprotect((void *)page, (size_t)ps, PROT_READ | PROT_WRITE) != 0)
        LOGE("mprotect failed: %s", strerror(errno));
    am[slot] = (uintptr_t)hook_fork;
    LOGI("hooked nativeForkAndSpecialize (targets='%s' gadget='%s')", g_targets, g_gadget);
#endif
}
