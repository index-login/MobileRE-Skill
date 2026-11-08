# Android Runtime 头文件（ART / libdexfile）

> **头文件不入库**（纯 AOSP 公开数据）。首次使用先拉取：
>
> ```bash
> python3 tools/fetch_android_headers.py --tag android-10.0.0_r1
> # 走代理加 --proxy http://127.0.0.1:7890
> ```
>
> 拉完落在 `android-headers/<tag>/art/`（目录名把点换成连字符）。
> `art_make_structs.java` 与手册里的偏移引用都依赖这批文件。

> 逆向加固壳时，样本大量 `dlsym` ART 内部符号（`ClassLinker::LoadMethod`、
> `Instrumentation::AddListener`、`NterpGetCodeItem`…）并直接读写 `ArtMethod`
> 字段。**偏移必须来自权威头文件**，靠反汇编猜既慢又容易错。

## 内容

```
android-10-0-0-r1/art/       # 目录名把 tag 里的点换成连字符（见下方说明）
├── art_method.h            34 KB   ArtMethod 布局（最关键）
├── class_linker.h          69 KB   LoadClass / LoadMethod / VerifyClassUsingOatFile
├── instrumentation.h       35 KB   AddListener / ConfigureStubs / EnableDeoptimization
├── thread.h                73 KB   art::Thread
├── runtime.h               39 KB   art::Runtime
├── mirror_object.h         36 KB   mirror::Object 头
├── mirror_class.h          65 KB   mirror::Class
├── dex_dex_file.h          38 KB   art::DexFile
├── dex_dex_file_layout.h    4 KB
├── jni_java_vm_ext.h        9 KB   JavaVMExt
└── jni_jni_env_ext.h        9 KB   JNIEnvExt
```

来源：`https://android.googlesource.com/platform/art/+/refs/tags/android-10.0.0_r1/`

## 为什么选 android-10.0.0_r1

`ArtMethod` 的布局**每个大版本都变**：

| Android | `dex_code_item_offset_` | 说明 |
|---|---|---|
| 5–8 | `+0x08` | 直接读 |
| 9 | `+0x08` | 同上 |
| 10+ | 用 `method_index_`/`hotness_count_`/`imt_index_` 复合计算 | 字段被拆分 |

选哪个 tag 取决于目标设备：`getprop ro.build.version.release` 或 `ro.build.version.sdk`。
本文以 Android 10（API 29）为例。
加固壳里常见**按 SDK 版本分支选择字段**的代码，与头文件的版本差异正好对应。

## ArtMethod 布局（LP64，40 字节）

```c
struct art_ArtMethod {          // offset  field (from art_method.h)
    uint32_t declaring_class_;  // 0x00  GcRoot<mirror::Class>
    uint32_t access_flags_;     // 0x04  std::atomic<uint32_t>
    uint32_t dex_code_item_offset_;  // 0x08
    uint32_t dex_method_index_; // 0x0c
    uint16_t method_index_;     // 0x10
    uint16_t hotness_count_;    // 0x12
    uint16_t imt_index_;        // 0x14
    uint8_t  padding_[2];       // 0x16  align to 8
    void    *data_;             // 0x18  native: JNI fn ptr
    void    *entry_point_from_quick_compiled_code_;  // 0x20  hook target
};
```

## 使用方式

```bash
# 重新抓取（需要代理）
python3 tools/fetch_android_headers.py --tag android-10.0.0_r1 --proxy http://127.0.0.1:7890

# 在 Ghidra 里建结构体
#   Script Manager -> art_make_structs.java
#   或 MCP: run_ghidra_script("art_make_structs.java")
```

建好后，把函数参数标成 `art_ArtMethod *`，反编译里的
`*(int *)(out + 8)` 就会变成 `out->dex_code_item_offset_`。

## 配套 Ghidra 脚本

`tools/ghidra/art_make_structs.java` 建立 7 个结构体：

| 结构体 | 大小 | 来源头文件 |
|---|---|---|
| `art_ArtMethod` | 40 B | art_method.h |
| `art_mirror_Object` | 8 B | mirror_object.h |
| `art_mirror_Class` | 36 B | mirror_class.h |
| `art_DexFile` | 97 B | dex_dex_file.h（DEX header 部分） |
| `art_JavaVMExt` | 28 B | jni_java_vm_ext.h |
| `art_JNIEnvExt` | 24 B | jni_jni_env_ext.h |
| `art_Instrumentation` | 24 B | instrumentation.h |

## 注意

- 这些头文件**只用于取布局**，不参与编译。Ghidra 的 `import_data_types`
  解析不了 C++ 模板（`GcRoot<T>`、`std::atomic<T>`），所以脚本里手工展开成
  等宽的基础类型，并在字段注释里标注原始类型。
- Dalvik（`dvm*`）头文件已从 AOSP 主分支移除，样本里的 `dvm*` 符号是
  通过 `dlsym` 兼容旧设备用的，Android 10 上实际走 ART 路径。

## 动态验证（比静态猜更可靠）

头文件给的是**布局**，但样本可能改字段含义。用 `tools/probe_layout.py`
跑一遍 SO，直接看每个偏移上真实流过的值：

```bash
python3 tools/probe_layout.py <so> --setup <样本 setup.py> \
    --entry JNI_OnLoad --at 0x<global_addr> --size 0x100 --chase 0 --chase-size 0x40
```

实测 `g_shell_ctx`（调用 `JNI_OnLoad` 后）：

| 偏移 | 值 | 分类 |
|---|---|---|
| +0x00 | `0x000fda90` | data_ptr → JNIEnv 函数表 |
| +0x08 | `0x10011688` | heap_ptr |
| +0x28 | `0x0011a0f8` | data_ptr → libdvm.so 句柄 |
| +0x60 | `10038` | small_int |
| +0x0b0 | `29` | small_int → **SDK 29 = Android 10** |
| +0x0e8 | `256` | small_int → opcode 表大小 |
| +0x78 | `0x000433ac` | **code_ptr** |

`chase 0` 追第一字段得到 8 个连续 code_ptr，确认是 `JNINativeInterface`。

**这直接验证了静态分析的结论**：`ctx->[0x28]` 是 libdvm 句柄、`ctx->[0xb0]` 是 SDK 版本。
