# inject/ — zygote 注入加载器

> 机制先读：`references/android-internals.md`（资源时间轴 / 加载语义 / 命名空间）；
> 通道选择与前置条件：`references/anti-detection.md` ›「注入通道选择」。
>
> 仅用于**已获授权的安全测试与学习**。使用者自行承担合规责任。
> 已在 Android 10 / arm64 验证；其它版本需自行适配 GOT 布局与 zygote 签名。

一次注入 zygote，之后每个目标 App 在子进程里 `dlopen` gadget，Frida 可直接连。

## 文件

| 文件 | 作用 |
|---|---|
| `inject.py` | **一条命令入口**：体检 → 写配置 → 注入 zygote → 恢复 SELinux |
| `loader_fork.c` | loader（GOT 钩子版）：hook `fork` / `selinux_android_setcontext`，在子进程 attach 后延迟加载 gadget |
| `loader.c` | 早期 ArtMethod 版 loader（保留参考，未采用：需替换 ArtMethod JNI 指针，风险高于 GOT 写） |
| `stub/L.java` | 加载桩：`Handler(mainLooper).post → System.load`，用于 targetSdk ≥ 35 |
| `build_stub.py` | 编译 `stub/L.java` → `stub/stub.jar` |
| `build.py` | 编译 C 源码 |
| `loader-plan.md` | 设计说明（实现细节以本 README 为准） |

产物 `*.so` / `stub.jar` 不随仓库提交（`.gitignore`）。

## 一次性准备

```bash
# 1) loader（Android 10, arm64）
python3 tools/inject/build.py --src tools/inject/loader_fork.c --hook

# 2) 加载桩（targetSdk >= 35 必需；自动找 android.jar + d8.jar）
python3 tools/inject/build_stub.py
adb push tools/inject/stub/stub.jar /data/local/tmp/stub.jar
adb shell chmod 644 /data/local/tmp/stub.jar
```

gadget 需提前放进目标 App 私有目录（loader 不搬运 payload）：

```
/data/data/<pkg>/libgadget.so
/data/data/<pkg>/libgadget.config.so
```

## 一条命令

```bash
python3 tools/inject/inject.py \
  --pkg <pkg> \
  --gadget /data/data/<pkg>/libgadget.so \
  --deday 12
```

`inject.py` 依次完成：

1. 设备 / root / `CapEff` / zygote64 / `stub.jar` / 注入器 体检；
2. 写 `/data/local/tmp/loader.conf`，创建 `loader.on`；
3. 推 `loader.so`；
4. 临时 `setenforce 0` → `AndKittyInjector --memfd --hide` 注入 zygote64 → 恢复 enforcing；
5. 打印验证命令。

只体检不注入：`--check`。

## 手动步骤（等价）

```bash
# loader.conf（4 行）
targets=<pkg>
gadget=/data/data/%s/libgadget.so
deday=12
stub=/data/local/tmp/stub.jar

# 注入
su -c 'setenforce 0'
su -c '/data/local/tmp/AndKittyInjector --pid <zygote64> --libs /data/local/tmp/loader.so --memfd --hide'
su -c 'setenforce 1'
```

## 配置项

| 键 | 含义 |
|---|---|
| `targets` | 精确进程名，逗号分隔；空 = 所有进程。子进程（`:xxx`）需单独列出 |
| `gadget` | gadget 路径，`%s` 替换为进程名；必须目标 App 可读 |
| `deday` | attach 后延迟加载的秒数（默认 12；按目标启动期调整） |
| `stub` | 加载桩 jar 路径 |

## 加载链

```
GOT hook fork + selinux_android_setcontext（zygote）
  → 子进程 pthread
  → 轮询 ActivityThread.currentApplication() 等 attach
  → sleep(deday)
  → DexClassLoader(stub.jar) → x.L.load(path)
  → Handler(mainLooper).post → System.load
  → gadget listen
```

## 验证

```bash
adb forward tcp:26666 tcp:26666
frida-ps -H 127.0.0.1:26666        # 出现 Gadget
frida -H 127.0.0.1:26666 -n Gadget
```

## 约束

- **仅 Android 10 / arm64**：GOT 布局与 `selinux_android_setcontext` 签名按该版本；32 位目标需另编 32 位 loader 注入 zygote32。
- **zygote hook 只在本次开机有效**；改 `loader.conf` 后必须重启再注入（配置在注入时缓存）。
- **必须 `--hide`**：zygote 映射会被所有子进程继承。
- **注入窗口需 permissive**；注入完成必须恢复 enforcing。
- **`targetSdk ≥ 35` 必须有 stub**：`Runtime.load(String, ClassLoader)` 被平台禁用，只能由 App classloader 下的类执行 `System.load`。
- root 需 `CAP_SYS_PTRACE`（`grep CapEff /proc/self/status` 非 0），否则 `PTRACE_SEIZE` 失败。

## 常见失败与对应层

| 现象 | 所属层 | 处理 |
|---|---|---|
| `PTRACE_SEIZE/ATTACH failed: Operation not permitted` | capability | 检查 `CapEff`；UID 0 不等于有 `CAP_SYS_PTRACE` |
| `library ... not found`（文件存在） | 命名空间 | 加载者不在目标 namespace；改 attach 后加载或显式 namespace |
| `is not accessible for the namespace "(anonymous)"` | 命名空间 | `dlopen` 落到默认 namespace；走 `System.load` / `dlopen_ext` |
| `Runtime#load(String, ClassLoader) is not supported` | targetSdk | 用 stub 的 `System.load` |
| 加载成功后数秒进程退出 | 时机 | 锚点落在启动期；调 `deday` 或改用事件锚点 |
| 目标 App 反复重启 | 映射继承 | 注入加 `--hide` |
| `frida-ps` connection closed | 进程已死 | 看 logcat / tombstone，先判活 |
