# B 方案：独立 zygote loader

> **使用方式见 `README.md`**；本文只记设计与参数依据。

## 目标

一条命令完成：

```bash
python3 tools/inject/loader.py --pkg com.target --gadget /path/libgadget.so
```

做到：注入 zygote 一次 → 每个目标 App 出生时在子进程里 dlopen gadget → frida 连 `127.0.0.1:<port>`。

## 组成

| 文件 | 作用 |
|---|---|
| `loader.c` | 注入 zygote 的 so：取 JNIEnv → 找 `Zygote.nativeForkAndSpecialize` → 替换 ArtMethod 里的 JNI 指针 → 子进程 dlopen gadget |
| `build.py --src loader.c [--hook]` | 编译（默认只观察；`--hook` 启用替换） |
| `/data/local/tmp/loader.on` | 开关文件，不存在则 loader 直接返回（防改坏 zygote） |
| `/data/local/tmp/loader.conf` | `targets=com.a,com.b` / `gadget=/data/data/%s/libx.so` |

## Android 10 关键事实

- 签名：`(II[II[[IILjava/lang/String;Ljava/lang/String;[I[IZLjava/lang/String;Ljava/lang/String;)I`
  （比 11+ 少 `is_top_app`、`pkg_data_info_list`、`whitelisted_data_info_list`、`ZZ`）
- JNI 函数指针在 ArtMethod 内；Android 10 的 `jmethodID` 就是 `ArtMethod*`
- `libart.so` 导出 `JNI_GetCreatedJavaVMs`，zygote 里可直接取 JNIEnv

## 两种模式

1. **默认（不替换）**：只打印 `jni_slot / jni_fn / art_range`，用于验证定位；
2. **`--hook`**：替换指针；子进程 dlopen gadget 后立即恢复原指针。

验证：logcat `-s mrx_loader`，再启动目标 App，`frida-ps -H 127.0.0.1:<port>`。

## 注入前置

1. SELinux：zygote 读不到 `/data/local/tmp` → 注入期间 `setenforce 0`，注入后恢复；
2. 注入器用 AndKitty `--hide`（不隐藏会让目标 App 反复重启）；
3. `loader.on` 与 `loader.conf` 在注入前放好（constructor 在 zygote 里读取并缓存）。

## 风险

- 写错会拖垮所有 App 启动；开关文件 + 先跑默认模式是必做的保险；
- gadget 路径必须目标 App 可读（放它自己的私有目录，如 `/data/data/<pkg>/libx.so`）；
- 只适配 Android 10；11+ 需换签名与 `GetArtMethod` 方式（R 以后 jmethodID 是索引）。

## 适用环境

```
GOT hook fork + selinux_android_setcontext
  → 子进程起 pthread
  → 轮询 ActivityThread.currentApplication() 等 App attach
  → sleep(deday)
  → DexClassLoader(stub.jar) → x.L.load(path)
  → Handler(mainLooper).post → System.load
  → gadget listen
```

| 项 | 值 |
|---|---|
| `deday` | **12 秒**（目标相关，需按 App 调整） |
| `stub` | `/data/local/tmp/stub.jar`（类 `x.L`，源码 `stub/L.java`） |
| `gadget` | `/data/data/<pkg>/libhan.so` |
| 注入 | `AndKittyInjector --memfd --hide`（临时 permissive） |

设计依据见 `references/android-internals.md`：资源时间轴（§2）、加载语义（§4）、ClassLoader 归属（§6）。

构建与注入：

```bash
python3 tools/inject/build_stub.py          # 生成 stub/stub.jar
python3 tools/inject/build.py --src tools/inject/loader_fork.c --hook
python3 tools/inject/inject.py --pkg <pkg> --gadget /data/data/<pkg>/libhan.so
```
