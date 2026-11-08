/*
 * loader_fork.c - zygote loader（GOT 钩子版）
 *
 * 与内联 hook 的区别：只改 libandroid_runtime.so 的 GOT 槽（8 字节原子写），
 * 不修改任何可执行代码，线程安全问题最小。
 *
 * 流程：
 *   constructor: 读配置 → 找 libandroid_runtime 基址 → GOT 替换 fork / vfork /
 *                selinux_android_setcontext
 *   fork hook:   调原函数；pid==0（子进程）置 g_child=1
 *   setcontext:  在子进程里拿到 uid 与进程名；命中 targets → dlopen(gadget)
 *
 * 构建：
 *   python3 tools/inject/build.py --src tools/inject/loader_fork.c --out loader.so
 *   （--hook 决定是否真的加载 gadget；默认只打印，便于阶段 1 验证）
 *
 * 开关/配置：
 *   /data/local/tmp/loader.on
 *   /data/local/tmp/loader.conf → targets=com.a,com.b  /  gadget=/data/data/%s/libx.so
 */
#include <android/log.h>
#include <errno.h>
#include <dlfcn.h>
#include <android/dlext.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <jni.h>
#include <unistd.h>
#include <pthread.h>

#define TAG "mrx_fork"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static char g_targets[512];
static char g_gadget[512];
static char g_stub[512] = "/data/local/tmp/stub.jar";
static int g_deday = 0;
static int g_child = 0;

static void load_conf(void) {
    FILE *f = fopen("/data/local/tmp/loader.conf", "r");
    if (f == NULL) return;
    char line[600];
    while (fgets(line, sizeof(line), f) != NULL) {
        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        if (strncmp(line, "targets=", 8) == 0) snprintf(g_targets, sizeof(g_targets), "%s", line + 8);
        else if (strncmp(line, "gadget=", 7) == 0) snprintf(g_gadget, sizeof(g_gadget), "%s", line + 7);
        else if (strncmp(line, "deday=", 6) == 0) g_deday = atoi(line + 6);
        else if (strncmp(line, "stub=", 5) == 0) snprintf(g_stub, sizeof(g_stub), "%s", line + 5);
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

/* 在模块的 .rela.plt 里找到指定符号的 GOT 槽，替换为 new_fn，返回原值 */
static uintptr_t patch_got(uintptr_t base, const char *sym, uintptr_t new_fn) {
    if (base == 0) return 0;
    const ElfW(Ehdr) *eh = (const ElfW(Ehdr) *)base;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return 0;

    const ElfW(Dyn) *dyn = NULL;
    for (int i = 0; i < eh->e_phnum; i++) {
        const ElfW(Phdr) *ph = (const ElfW(Phdr) *)(base + eh->e_phoff + i * eh->e_phentsize);
        if (ph->p_type == PT_DYNAMIC) { dyn = (const ElfW(Dyn) *)(base + ph->p_vaddr); break; }
    }
    if (dyn == NULL) return 0;

    uintptr_t symtab = 0, strtab = 0, jmprel = 0;
    size_t pltrelsz = 0;
    long pltrel = 0;
    for (const ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
        uintptr_t v = (uintptr_t)d->d_un.d_ptr;
        if (v < base) v += base;
        switch (d->d_tag) {
            case DT_SYMTAB: symtab = v; break;
            case DT_STRTAB: strtab = v; break;
            case DT_JMPREL: jmprel = v; break;
            case DT_PLTRELSZ: pltrelsz = (size_t)d->d_un.d_val; break;
#ifdef DT_PLTREL
            case DT_PLTREL: pltrel = (long)d->d_un.d_val; break;
#endif
            default: break;
        }
    }
    if (symtab == 0 || strtab == 0 || jmprel == 0 || pltrelsz == 0) return 0;
    if (pltrel != 0 && pltrel != DT_RELA) return 0; /* 只处理 RELA */

    size_t count = pltrelsz / sizeof(ElfW(Rela));
    const ElfW(Rela) *rels = (const ElfW(Rela) *)jmprel;
    for (size_t i = 0; i < count; i++) {
        uint32_t idx = (uint32_t)(rels[i].r_info >> 32);
        const ElfW(Sym) *s = (const ElfW(Sym) *)(symtab + (uintptr_t)idx * sizeof(ElfW(Sym)));
        const char *name = (const char *)(strtab + s->st_name);
        if (strcmp(name, sym) != 0) continue;

        uintptr_t *slot = (uintptr_t *)(base + rels[i].r_offset);
        long ps = sysconf(_SC_PAGESIZE);
        uintptr_t page = ((uintptr_t)slot) & ~((uintptr_t)ps - 1);
        if (mprotect((void *)page, (size_t)ps, PROT_READ | PROT_WRITE) != 0) {
            LOGE("mprotect GOT failed: %s", strerror(errno));
            return 0;
        }
        uintptr_t old = *slot;
        *slot = new_fn;
        LOGI("GOT %s @%p: %p -> %p", sym, (void *)slot, (void *)old, (void *)new_fn);
        return old;
    }
    return 0;
}


/* ---- 在内存里解析 libart 导出符号（拿 JNI_GetCreatedJavaVMs） ---- */
static uint32_t gnu_hash2(const char *s) {
    uint32_t h = 5381;
    while (*s) h = (h * 33) + (uint8_t)*s++;
    return h;
}

static int elf_lookup2(uintptr_t base, const char *name, uintptr_t *out) {
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
    if (!symtab || !strtab || !gnu) return -1;
    const uint32_t *gh = (const uint32_t *)gnu;
    uint32_t nbuckets = gh[0], symoffset = gh[1], bloom_size = gh[2], bloom_shift = gh[3];
    const ElfW(Addr) *bloom = (const ElfW(Addr) *)(gh + 4);
    const uint32_t *buckets = (const uint32_t *)(bloom + bloom_size);
    const uint32_t *chain = buckets + nbuckets;
    uint32_t h = gnu_hash2(name);
    uint32_t wordbits = 8 * sizeof(ElfW(Addr));
    ElfW(Addr) w = bloom[(h / wordbits) % bloom_size];
    ElfW(Addr) mask = ((ElfW(Addr))1 << (h % wordbits)) | ((ElfW(Addr))1 << ((h >> bloom_shift) % wordbits));
    if ((w & mask) != mask) return -1;
    uint32_t idx = buckets[h % nbuckets];
    if (idx < symoffset) return -1;
    for (;;) {
        uint32_t cv = chain[idx - symoffset];
        const ElfW(Sym) *sym = (const ElfW(Sym) *)(symtab + (uintptr_t)idx * sizeof(ElfW(Sym)));
        if (((cv | 1) == (h | 1)) && strcmp((const char *)(strtab + sym->st_name), name) == 0) {
            *out = base + sym->st_value;
            return 0;
        }
        if (cv & 1) break;
        idx++;
    }
    return -1;
}

/* ---- 通过自定义 dex 桩（x.L.load）走 System.load：兼容 targetSdk>=35 ---- */
static char *get_code_cache_dir(JNIEnv *env, jobject ctx) {
    static char buf[512];
    jclass cc = (*env)->FindClass(env, "android/content/Context");
    jmethodID m = (*env)->GetMethodID(env, cc, "getCodeCacheDir", "()Ljava/io/File;");
    jobject f = m ? (*env)->CallObjectMethod(env, ctx, m) : NULL;
    if (f == NULL) { (*env)->ExceptionClear(env); return NULL; }
    jclass fc = (*env)->FindClass(env, "java/io/File");
    jmethodID ap = (*env)->GetMethodID(env, fc, "getAbsolutePath", "()Ljava/lang/String;");
    jstring s = (*env)->CallObjectMethod(env, f, ap);
    if (s == NULL) { (*env)->ExceptionClear(env); return NULL; }
    const char *c = (*env)->GetStringUTFChars(env, s, NULL);
    snprintf(buf, sizeof(buf), "%s", c);
    (*env)->ReleaseStringUTFChars(env, s, c);
    return buf;
}

static int load_via_stub(JNIEnv *env, jobject parent_loader, const char *path, const char *code_cache) {
    jclass dcl = (*env)->FindClass(env, "dalvik/system/DexClassLoader");
    if (dcl == NULL) { (*env)->ExceptionClear(env); LOGE("DexClassLoader class not found"); return -1; }
    jmethodID ctor = (*env)->GetMethodID(env, dcl, "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
    if (ctor == NULL) { (*env)->ExceptionClear(env); LOGE("DexClassLoader ctor not found"); return -1; }
    jstring jdex = (*env)->NewStringUTF(env, g_stub);
    jstring jopt = (*env)->NewStringUTF(env, code_cache);
    jobject dlo = (*env)->NewObject(env, dcl, ctor, jdex, jopt, NULL, parent_loader);
    if (dlo == NULL || (*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env); (*env)->ExceptionClear(env);
        LOGE("DexClassLoader create failed: %s", g_stub); return -1;
    }
    jmethodID lc = (*env)->GetMethodID(env, dcl, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    jstring jname = (*env)->NewStringUTF(env, "x.L");
    jclass cls = (jclass)(*env)->CallObjectMethod(env, dlo, lc, jname);
    if (cls == NULL || (*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env); (*env)->ExceptionClear(env);
        LOGE("loadClass x.L failed"); return -1;
    }
    jmethodID lm = (*env)->GetStaticMethodID(env, cls, "load", "(Ljava/lang/String;)V");
    if (lm == NULL) { (*env)->ExceptionClear(env); LOGE("x.L.load not found"); return -1; }
    jstring jpath = (*env)->NewStringUTF(env, path);
    (*env)->CallStaticVoidMethod(env, cls, lm, jpath);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env); (*env)->ExceptionClear(env);
        LOGE("x.L.load threw"); return -1;
    }
    return 0;
}

/* ---- 用 Java 的 Runtime.load(path, classLoader) 加载 gadget（走 classloader 命名空间） ---- */
static int load_via_java(const char *path) {
    typedef jint (*get_vms_fn)(JavaVM **, jsize, jsize *);
    uintptr_t fn = 0;
    if (elf_lookup2(find_lib_base("libart.so"), "JNI_GetCreatedJavaVMs", &fn) != 0) {
        LOGE("JNI_GetCreatedJavaVMs not resolved");
        return -1;
    }
    JavaVM *vm = NULL;
    jsize n = 0;
    if (((get_vms_fn)fn)(&vm, 1, &n) != JNI_OK || n < 1) { LOGE("no JavaVM"); return -1; }
    JNIEnv *env = NULL;
    int tries = 0;
    while ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        if ((*vm)->AttachCurrentThread(vm, &env, NULL) == JNI_OK) break;
        if (++tries > 100) { LOGE("attach failed after 10s"); return -1; }
        usleep(100 * 1000);
    }
    jclass at = (*env)->FindClass(env, "android/app/ActivityThread");
    if (at == NULL) { LOGE("ActivityThread not found"); return -1; }
    jmethodID cur = (*env)->GetStaticMethodID(env, at, "currentApplication", "()Landroid/app/Application;");
    if (cur == NULL) { LOGE("currentApplication id not found"); return -1; }

    /* 等 App attach：currentApplication 非空才说明 handleBindApplication 已完成 */
    jobject app = NULL;
    int waited = 0;
    while (waited < 200) {
        app = (*env)->CallStaticObjectMethod(env, at, cur);
        if (app != NULL) break;
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        usleep(100 * 1000);
        waited++;
    }
    if (app == NULL) { LOGE("app not attached in 20s"); return -1; }
    LOGI("app attached after %d00ms", waited);
    if (g_deday > 0) {
        LOGI("deday: sleep %ds before load", g_deday);
        sleep(g_deday);
    }

    jclass clw = (*env)->FindClass(env, "android/content/ContextWrapper");
    jmethodID getcl = (*env)->GetMethodID(env, clw, "getClassLoader", "()Ljava/lang/ClassLoader;");
    jobject loader = getcl ? (*env)->CallObjectMethod(env, app, getcl) : NULL;
    if (loader == NULL) { LOGE("classloader null"); return -1; }

    /* 优先走自定义 dex 桩的 System.load（targetSdk>=35 下 Runtime.load(2参) 被禁） */
    char *cache = get_code_cache_dir(env, app);
    if (cache != NULL && load_via_stub(env, loader, path, cache) == 0) {
        LOGI("gadget loaded via stub System.load: %s", path);
        return 0;
    }
    LOGE("stub load failed, try Runtime.load");

    jclass rt = (*env)->FindClass(env, "java/lang/Runtime");
    jmethodID getrt = (*env)->GetStaticMethodID(env, rt, "getRuntime", "()Ljava/lang/Runtime;");
    jobject rtobj = (*env)->CallStaticObjectMethod(env, rt, getrt);
    jmethodID load = (*env)->GetMethodID(env, rt, "load", "(Ljava/lang/String;Ljava/lang/ClassLoader;)V");
    if (load == NULL) { (*env)->ExceptionClear(env); LOGE("Runtime.load(String,ClassLoader) not found"); return -1; }
    jstring jpath = (*env)->NewStringUTF(env, path);
    (*env)->CallVoidMethod(env, rtobj, load, jpath, loader);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionDescribe(env); (*env)->ExceptionClear(env); return -1; }
    return 0;
}

typedef pid_t (*fork_fn)(void);
typedef int (*setcontext_fn)(uid_t uid, int isSystemServer, const char *seinfo, const char *name);

static fork_fn g_orig_fork = NULL;
static fork_fn g_orig_vfork = NULL;
static setcontext_fn g_orig_setctx = NULL;

static pid_t hook_fork(void) {
    pid_t pid = g_orig_fork ? g_orig_fork() : fork();
    if (pid == 0) g_child = 1;
    return pid;
}

static pid_t hook_vfork(void) {
    return hook_fork();
}

#ifdef LOADER_HOOK
static void *delayed_load(void *arg) {
    char path[600];
    char *name = (char *)arg;
    if (strstr(g_gadget, "%s")) snprintf(path, sizeof(path), g_gadget, name);
    else snprintf(path, sizeof(path), "%s", g_gadget);
    if (load_via_java(path) == 0) { LOGI("gadget loaded via Runtime.load: %s (pid=%d)", path, getpid()); free(name); return NULL; }
    LOGE("Runtime.load failed, fallback dlopen");
    /* 应用私有目录只能通过 classloader 命名空间加载 */
    void *h = NULL;
    static void *(*p_dlopen_ext)(const char *, int, const android_dlextinfo *) = NULL;
    static struct android_namespace_t *(*p_get_ns)(const char *) = NULL;
    if (p_dlopen_ext == NULL) {
        void *dl = dlopen("libdl.so", RTLD_NOW);
        if (dl != NULL) {
            p_dlopen_ext = (void *(*)(const char *, int, const android_dlextinfo *))dlsym(dl, "android_dlopen_ext");
            p_get_ns = (struct android_namespace_t *(*)(const char *))dlsym(dl, "android_get_exported_namespace");
        }
    }
    if (p_dlopen_ext != NULL && p_get_ns != NULL) {
        struct android_namespace_t *ns = NULL;
        for (int i = 0; i < 200 && ns == NULL; i++) {
            ns = p_get_ns("classloader-namespace");
            if (ns == NULL) usleep(100 * 1000);
        }
        LOGI("classloader-namespace=%p", (void *)ns);
        if (ns != NULL) {
            if (g_deday > 0) sleep(g_deday);
            android_dlextinfo info;
            memset(&info, 0, sizeof(info));
            info.flags = ANDROID_DLEXT_USE_NAMESPACE;
            info.library_namespace = ns;
            h = p_dlopen_ext(path, RTLD_NOW, &info);
        }
    }
    if (h == NULL) h = dlopen(path, RTLD_NOW);
    if (h == NULL) LOGE("gadget dlopen(%s) failed: %s", path, dlerror());
    else LOGI("gadget loaded %s -> %p (pid=%d)", path, h, getpid());
    free(name);
    return NULL;
}
#endif

static int hook_setcontext(uid_t uid, int isSystemServer, const char *seinfo, const char *name) {
    int r = g_orig_setctx ? g_orig_setctx(uid, isSystemServer, seinfo, name) : 0;
    if (g_child && name != NULL) {
        LOGI("child setcontext uid=%d name=%s", (int)uid, name);
#ifdef LOADER_HOOK
        if (in_targets(name)) {
            pthread_t t;
            char *dup = strdup(name);
            if (pthread_create(&t, NULL, delayed_load, dup) == 0) pthread_detach(t);
            else LOGE("pthread_create failed");
        }
#endif
    }
    return r;
}

__attribute__((constructor)) static void fork_loader_init(void) {
    if (access("/data/local/tmp/loader.on", F_OK) != 0) {
        LOGI("disabled");
        return;
    }
    load_conf();

    uintptr_t base = find_lib_base("libandroid_runtime.so");
    if (base == 0) { LOGE("libandroid_runtime not found"); return; }

    g_orig_fork = (fork_fn)patch_got(base, "fork", (uintptr_t)hook_fork);
    g_orig_vfork = (fork_fn)patch_got(base, "vfork", (uintptr_t)hook_vfork);
    g_orig_setctx = (setcontext_fn)patch_got(base, "selinux_android_setcontext", (uintptr_t)hook_setcontext);

    LOGI("install base=%p fork=%p vfork=%p setcontext=%p", (void *)base,
         (void *)g_orig_fork, (void *)g_orig_vfork, (void *)g_orig_setctx);
}
