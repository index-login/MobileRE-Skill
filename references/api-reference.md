# Frida API 参考手册

> 何时读：用户提到"写自定义 hook/API 用法/Stalker/RegisterNatives/内存搜索"时读取。
> 由 SKILL.md 任务路由表指向，按需读取。日常分析优先使用 `scripts/` 下的模块（见 SKILL.md 模块目录）。

---

## 一、各层核心分析能力

### 1.1 Java / ObjC 层（最上层）

#### Java 层核心 API
```javascript
Java.perform(function () {
    // 类操作
    var Cls = Java.use("com.example.Target");           // 获取类
    Java.enumerateLoadedClasses(onMatch, onComplete);   // 枚举已加载类
    Java.openClassFile("/path/to/classes.dex").load();  // 动态加载 dex

    // 方法 hook - 正确处理重载
    Cls.method.overload("int", "java.lang.String").implementation = function (a, b) { };
    Cls.method.overload().implementation = function () { };

    // 构造器 hook
    Cls.$init.overload("android.content.Context").implementation = function (ctx) { };

    // ClassLoader
    var loader = Cls.class.getClassLoader();
    Java.classFactory.loader = loader; // 切换 classFactory 的 ClassLoader
});
```

#### ObjC 层核心 API
```javascript
// 方法 hook - 注意 -/+ 号方法
var method = ObjC.classes.ClassName["- instanceMethod:"];
Interceptor.attach(method.implementation, {
    onEnter: function (args) {
        // args[0] = self, args[1] = _cmd, args[2+] = 实际参数
        var self = new ObjC.Object(args[0]);
        var arg0 = new ObjC.Object(args[2]);
    }
});

// 枚举堆上实例
ObjC.choose(ObjC.classes.ClassName, {
    onMatch: function (instance) { },
    onComplete: function () { }
});
```

#### 何时向下层转移
- 目标方法在 `.so` 中实现（JNI native 方法）
- 应用使用了大量反射调用，难以静态定位类名
- 目标类动态加载，Hook 时机难以把握
- 检测了 Frida 在 Java 层的存在（如 `Debug.isDebuggerConnected()`）

### 1.2 JNI / Native Bridge 层

**关键点：JNI 函数表劫持是连接 Java 层和 Native 层的通用方案。**

```javascript
// Android: Hook JNI NewStringUTF 获取字符串参数
var art = Process.findModuleByName("libart.so");
if (art) {
    var NewStringUTF = Module.findExportByName("libart.so", "_ZN3art3JNI12NewStringUTFEP7_JNIEnvPKc");
    // 或者通过 JNI 函数表偏移
}

// Android: Hook RegisterNatives 跟踪动态注册
var RegisterNatives = Module.findExportByName("libart.so", "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi");
Interceptor.attach(RegisterNatives, {
    onEnter: function (args) {
        var env = args[0];
        var cls = args[1];
        var methods = args[2];
        var count = args[3].toInt32();
        // 遍历 JNINativeMethod 数组
        for (var i = 0; i < count; i++) {
            var name = methods.add(i * 3 * Process.pointerSize).readPointer().readCString();
            var signature = methods.add(i * 3 * Process.pointerSize + Process.pointerSize).readPointer().readCString();
            var fnPtr = methods.add(i * 3 * Process.pointerSize + Process.pointerSize * 2).readPointer();
            console.log("[RegisterNatives]", name, signature, fnPtr);
        }
    }
});
```

**JNI 函数表结构（Android）：**
JNIEnv 是指向函数指针表的二级指针。常见的 JNI 函数在表中的偏移因 Android 版本不同而不同，但可以在运行时动态解析。

### 1.3 Native 库层（.so / .dylib）

#### 模块与符号操作
```javascript
// 枚举模块
Process.enumerateModules();
var mod = Process.findModuleByName("libfoo.so");      // 按名查找
Module.findBaseAddress("libfoo.so");                    // 仅获取基址
Module.findExportByName("libfoo.so", "function_name");  // 按名导出

// 枚举导出/导入
Module.enumerateExports("libfoo.so");
Module.enumerateImports("libfoo.so");

// 处理无符号/去符号的库
// 1. 扫描已知字节模式
Memory.scan(mod.base, mod.size, "55 48 89 E5", { onMatch: function (address, size) { } });
// 2. 通过交叉引用定位
// 3. 通过 plt/got 表定位
```

#### Interceptor 核心用法
```javascript
// 标准 hook
Interceptor.attach(ptr(0x12345678), {
    onEnter: function (args) {
        console.log("arg0:", args[0], "arg1:", args[1]);
        this.saved = args[0];
    },
    onLeave: function (retval) {
        retval.replace(ptr(0x0));
    }
});

// 函数替换
var original = new NativeFunction(ptr(0x12345678), 'int', ['int', 'int']);
Interceptor.replace(ptr(0x12345678), new NativeCallback(function (a, b) {
    return original(a, b);
}, 'int', ['int', 'int']));

// 快速 detach
var listener = Interceptor.attach(target, callbacks);
listener.detach();
```

#### 处理动态加载的库
```javascript
// 监控 dlopen 以便在目标库加载时立即 hook
var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
Interceptor.attach(android_dlopen_ext, {
    onEnter: function (args) {
        this.path = args[0].readCString();
    },
    onLeave: function (retval) {
        if (this.path && this.path.indexOf("libtarget") !== -1) {
            // 此时目标库已经加载，立即 hook
            var mod = Process.findModuleByName("libtarget.so");
            // ... 执行 hook
        }
    }
});
```

### 1.4 系统库层（libc / libSystem / libart）

**这是 Frida 检测与反检测的核心战场。大多数 Frida 检测都在这一层执行。**

#### 文件操作链
```
高层: fopen() / fgets()
  ↓
中层: open() / openat() / read() / __read_chk()
  ↓
底层: syscall(__NR_openat, ...) / svc #0
```

```javascript
// Hook 文件操作 - 覆盖 open 系列
var funcs = ["open", "openat", "__openat", "fopen", "fopen64"];
funcs.forEach(function (name) {
    var addr = Module.findExportByName("libc.so", name);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                var path = args[0].readCString ? args[0].readCString()
                         : (args[1] ? args[1].readCString() : "");
                if (path && (path.indexOf("frida") !== -1 || path.indexOf("linjector") !== -1)) {
                    console.log("[!] Detection opening:", path);
                    console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\n"));
                }
            }
        });
    }
});
```

#### 线程操作链
```
高层: pthread_create() / java.lang.Thread.start()
  ↓
中层: clone() / __clone()
  ↓
底层: syscall(__NR_clone, ...)
```

Frida 注入后会创建新线程（如 `frida-*-loop`、`gum-js-loop`）。检测手段：
1. Hook `pthread_create` 检查线程名或入口函数
2. 读取 `/proc/self/task/` 枚举线程
3. 调用 `syscall(__NR_gettid)` 配合命名规律检测

#### 内存映射检测（/proc/self/maps）
```
高层: fopen("/proc/self/maps") → fgets()
  ↓
中层: open() → read()
  ↓
底层: sendfile() / syscall(__NR_readlinkat, "/proc/self/map_files/...")
```

#### 端口与通信检测
Frida 默认使用 27042 端口通信。
```javascript
// Hook connect() - 检测 Frida 端口通信尝试
// 同时也要 hook socket() + bind() + listen() 的组合，因为有的检测是主动监听
var connect = Module.findExportByName("libc.so", "connect");
Interceptor.attach(connect, {
    onEnter: function (args) {
        var sockfd = args[0].toInt32();
        var addr = args[1];
        // sa_family (2 bytes) + port (2 bytes, big-endian)
        var family = addr.readU16();
        var port = ((addr.add(2).readU8() << 8) | addr.add(3).readU8());
        if (port === 27042 || port === 27043) {
            // 检测到 Frida 端口通信
        }
    }
});
```

### 1.5 系统调用层（最深）

**当检测绕过 libc 直接调用 `syscall()` 时，你需要 hook `syscall` 函数本身。**

```javascript
// Hook syscall() 函数
var syscall = Module.findExportByName("libc.so", "syscall");
if (syscall) {
    Interceptor.attach(syscall, {
        onEnter: function (args) {
            var nr = args[0].toInt32();
            // ARM64 syscall numbers
            var SYSCALL_NAMES = {
                56: "openat",
                63: "read",
                64: "write",
                220: "clone",
                98: "futex",
                101: "ptrace",
            };
            var name = SYSCALL_NAMES[nr] || ("sys_" + nr);
            console.log("[syscall]", name, "called from:",
                DebugSymbol.fromAddress(this.returnAddress));
        }
    });
}
```

**Android ARM64 syscall 参考（常见检测相关）：**
| Number | 函数 | 检测用途 |
|--------|------|---------|
| 56 | openat | 打开文件检测 Frida 特征 |
| 63 | read | 读取 /proc/self/maps 等 |
| 220 | clone | 创建线程（检测 Frida 线程）|
| 98 | futex | 线程同步（检测 Frida 线程活动）|
| 101 | ptrace | 反调试 |
| 78 | readlinkat | 读取 /proc/self/exe 等链接 |
| 17 | getcwd | 获取当前目录 |
| 135 | sigaction | 注册信号处理器 |
| 291 | statfs | statfs("/proc/self/fd") |
| 61 | write | 输出检测字符串 |

**更底层：SVC 指令 hook（ARM64）**
当检测使用内联汇编 `svc #0` 直接发起系统调用时：
```javascript
// 使用 Stalker 追踪 SVC 指令
// 或基于特征码扫描定位 SVC 指令并 inline hook
// 关注 ARM64 的 SVC #0 (0xD4000001)
```

### 1.6 Frida 自保护（frida-server 特征隐藏）

**Frida 在目标进程中的特征：**
- **线程名**：`frida-*-loop`、`gum-js-loop`、`frida-agent`
- **内存映射**：包含 `frida-agent` 的 so 文件、`linjector` 等
- **端口**：27042（默认控制端口）、27043（默认 CLR 端口）
- **文件描述符**：打开 `/proc/self/fd` 可发现 Frida 创建的 fd
- **环境变量**：`FRIDA_*` 系列
- **D-Bus**：Android 上的 `linjector` D-Bus 服务
- **SELinux 上下文**：`u:r:frida:s0`

---

## 二、Hook 稳定性核心原则

### 2.1 时机问题
```javascript
// 方案 A：早于目标库加载时 hook（推荐用于系统库）
// 无需等待，直接 attach 即可
Interceptor.attach(Module.findExportByName("libc.so", "open"), ...);

// 方案 B：等待目标库加载
// 方案 B1 - hook dlopen
var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
Interceptor.attach(android_dlopen_ext, {
    onLeave: function (retval) {
        if (this.path && this.path.indexOf("libtarget") !== -1) {
            hookTargetLibrary();
        }
    }
});
// 方案 B2 - 使用 timeout 轮询（最后手段）
var timer = setInterval(function () {
    var mod = Process.findModuleByName("libtarget.so");
    if (mod) { clearInterval(timer); hookTargetLibrary(); }
}, 100);
```

### 2.2 错误处理模式
```javascript
function safeHook(moduleName, funcName, callbacks) {
    try {
        var addr = Module.findExportByName(moduleName, funcName);
        if (!addr) { console.log("[-] 未找到:", funcName); return null; }
        return Interceptor.attach(addr, callbacks);
    } catch (e) {
        console.log("[-] Hook 失败:", funcName, e.message);
        return null;
    }
}
```

### 2.3 参数安全性（避免崩溃）
```javascript
onEnter: function (args) {
    // 必须判空再读取字符串
    if (args[0] && !args[0].isNull()) {
        try {
            var str = args[0].readCString();
        } catch (e) { }
    }
    // 使用 MemoryAccessMonitor 检查内存可读性
}
```

### 2.4 线程安全
```javascript
// 不要直接在 Native hook 中大量创建 Java 对象
// 将数据通过 send() 发送到 Python 端，由 Python 端协调
// 或者使用 Java.scheduleOnMainThread()

Interceptor.attach(addr, {
    onEnter: function (args) {
        // Native 线程中
        var data = args[0].readByteArray(256);
        send({ type: "native_data", payload: hexdump(data) });
    }
});
```

---

## 三、Stalker 代码追踪

适用于需要了解完整执行流的场景。

```javascript
Stalker.follow(threadId, {
    transform: function (iterator) {
        var instruction;
        while ((instruction = iterator.next()) !== null) {
            // 在每个指令前插入回调
            iterator.putCallout(function (context) {
                console.log(instruction.address, instruction.mnemonic);
            });
            iterator.keep();
        }
    },
    events: {
        call: true,  // 跟踪 call 指令
        ret: true,   // 跟踪 ret 指令
        exec: false, // 跟踪每条指令（性能开销大）
    }
});
// 取消追踪
Stalker.unfollow(threadId);
// 垃圾回收
Stalker.garbageCollect();
```

**Stalker 典型场景：**
- 定位被混淆的代码块
- 追踪 `svc #0` 指令
- 发现未导出的内部函数
- 追踪间接跳转（如虚函数调用）

---

## 四、内存分析

### 4.1 内存搜索
```javascript
// 同步搜索（可能阻塞，小范围推荐）
var results = Memory.scanSync(base, size, "DE AD BE EF ?? ?? 00");
results.forEach(function (match) {
    console.log("Found at:", match.address);
});

// 异步搜索（大范围推荐）
Memory.scan(base, size, "pattern", {
    onMatch: function (address, size) { },
    onComplete: function () { }
});
```

### 4.2 内存读写
```javascript
// 读取
var val8 = ptr.readU8();
var val32 = ptr.readU32();
var val64 = ptr.readU64();
var ptrVal = ptr.readPointer();
var bytes = ptr.readByteArray(length);
var cStr = ptr.readCString();
var utf16 = ptr.readUtf16String();

// 写入
ptr.writeU8(0xFF);
ptr.writeU32(0xDEADBEEF);
ptr.writeByteArray([0x90, 0x90, 0x90, 0x90]); // NOP patch
```

### 4.3 内存保护修改
```javascript
// 修改内存保护以写入代码段
Memory.protect(address, 4096, 'rwx');
// operations...
Memory.protect(address, 4096, 'r-x'); // 恢复
```

### 4.4 结构体读取
```javascript
// 使用 NativeFunction 定义结构体读取函数
// 或直接按偏移量读取
// 注意：ARM64 和 ARM32 的指针大小不同（8 vs 4）
var ptrSize = Process.pointerSize; // 8 for arm64, 4 for arm32
```

---

## 五、分析实战策略

### 5.1 定位目标函数的方法（优先级从高到低）

1. **导出符号** → `Module.findExportByName()`
2. **已知特征码** → `Memory.scan()` + 特征字节
3. **通过调用者定位** → hook 调用者，从 context/returnAddress 反查
4. **通过字符串引用定位** → 搜索字符串在内存中的位置 → 交叉引用
5. **通过 PLT/GOT 表** → 解析 ELF/Mach-O 结构
6. **通过 JNI RegisterNatives** → 监听动态注册
7. **通过 Stalker 追踪** → 大面积代码追踪 + 特征分析

### 5.2 确认 hook 是否被检测/阻挠的方法

```javascript
// 验证 hook 是否生效
Interceptor.attach(target, {
    onEnter: function (args) {
        this.called = true;
        this.tid = Process.getCurrentThreadId();
    },
    onLeave: function (retval) {
        // 如果 onEnter 都没被调用，说明目标路径被绕过
        // 或者目标函数根本未被调用（检测使用了更底层的函数）
    }
});

// 如果一段时间后 onEnter 从未被触发 → 去 hook 更底层
// 如果 onEnter 被触发了但检测仍然生效 → 需要修改返回值或参数
```

### 5.3 应对代码混淆

```javascript
// 1. 查找控制流平坦化的分发器
// 2. 使用 Stalker 追踪实际执行路径
// 3. 找到关键比较指令并 NOP 或修改跳转条件
// 4. Hook 最终的数据处理函数（加密/解密/网络发送）
//    → 无论中间如何进行代码混淆，数据最终要被处理
```

---

## 七、调试技巧

### 7.1 快速验证 hook 的脚本模板
```javascript
// 最小化验证脚本
(function () {
    function tryHook(module, name) {
        var addr = Module.findExportByName(module, name);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    console.log("[+] " + name + " called, thread:", Process.getCurrentThreadId());
                    console.log("    caller:", DebugSymbol.fromAddress(this.returnAddress));
                }
            });
            return true;
        }
        return false;
    }

    // 验证文件操作层
    ["open", "openat", "__openat", "fopen"].forEach(function (f) {
        tryHook("libc.so", f);
    });

    // 验证 syscall
    tryHook("libc.so", "syscall");
})();
```

### 7.2 确认调用链
```javascript
// 打印完整调用栈
function logBacktrace(ctx) {
    var trace = Thread.backtrace(ctx || this.context, Backtracer.ACCURATE);
    console.log("Call stack:");
    trace.map(DebugSymbol.fromAddress).forEach(function (sym, i) {
        console.log("  " + i + ": " + sym);
    });
}
```