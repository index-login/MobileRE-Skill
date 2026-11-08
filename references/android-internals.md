# Android 系统机制（hook 框架 / 系统分析）

> 面向"把代码放进目标进程并让它生效"这一类问题，描述系统本身的结构与语义。

## 0. 三层模型

任何一次"注入并生效"都由三层共同决定，三层各有独立约束：

| 层 | 决定什么 | 变量 |
|---|---|---|
| 载体层 | 代码怎么进入目标进程 | ptrace / 注入框架 / 系统模块 / 目标自身加载 |
| 时机层 | 目标进程处于生命周期哪一段 | fork 后 / specialize 后 / attach 后 / 首帧后 |
| 上下文层 | 在什么环境里执行 | 线程、classloader、linker namespace、SELinux 域 |

三层任一不满足，结果都是"没有生效"或"生效后进程异常"，而表面现象往往相似。分析时先分层定位，再讨论具体 API。

## 1. 进程与生命周期

```
init
 └─ zygote64 / zygote32        预加载 boot classpath、系统资源、常用 so；监听 socket
     └─ fork（每个 App 一个）   COW 继承 zygote 的全部映射
         └─ specialize         设置 uid/gid、SELinux 域、进程名
             └─ ActivityThread.main → attach
                 └─ handleBindApplication → Application.onCreate
                     └─ 首帧
```

- zygote 是全部 App 进程的父进程；zygote 内的映射、已加载 so、全局变量会进入每个子进程。
- **fork 只复制调用线程**：zygote 中已存在的线程（监听、后台线程）不会出现在子进程；在 zygote 里创建的线程无法为 App 服务。
- 进程名在 specialize 阶段确定，早于任何 App 代码执行；多进程 App 的主进程与子进程（`:xxx`）是独立 fork、独立生命周期。
- 系统对 App attach 设有超时；attach 期间主线程承担启动工作。

## 2. 资源时间轴

各阶段"可用的资源"是递增的，能做什么由该阶段已就绪的资源决定：

| 阶段 | JavaVM | JNIEnv | App classloader | 主线程 Looper | classloader-namespace |
|---|:--:|:--:|:--:|:--:|:--:|
| fork 后 | 已创建 | 需 Attach | 无 | 未准备 | 未创建 |
| specialize 后 | 已创建 | 需 Attach | 无 | 未准备 | 未创建 |
| ActivityThread.main 后 | 可用 | 可用 | 无 | 已 prepare | 未创建 |
| handleBindApplication | 可用 | 可用 | 已建立 | 可用 | 创建中/已建 |
| attach 完成 | 可用 | 可用 | 可用 | 可用 | 已建 |

由此得到三条语义：

- 纯 native 操作（读 maps、dlopen 系统库、改 GOT）在任何阶段都可行；
- Java 操作要求 JVM 可挂载，App 类操作要求 classloader 已建立；
- 加载 App 私有目录的 so 要求 classloader-namespace 已存在。

就绪性用**状态量**表达，不用时间表达：

| 状态量 | 含义 |
|---|---|
| `JNI_GetCreatedJavaVMs` 返回 ≥1 | JavaVM 已创建 |
| `AttachCurrentThread` 成功 | 当前线程可调 Java（极早期会失败，需重试） |
| `ActivityThread.currentApplication()` 非 null | App 已 attach、classloader 可用 |
| `android_get_exported_namespace("classloader-namespace")` 非 null | App 命名空间已建立 |
| `Looper.getMainLooper()` 非 null | 可向主线程投递任务 |

## 3. 初始化锚点

初始化时机挂在**事件**上，而不是挂在时长上。可用锚点及其保证：

| 锚点 | 保证 | 取法 |
|---|---|---|
| Application 创建完成 | App classloader 可用，Java 侧可操作 | `ActivityThread.currentApplication()` 非 null |
| `handleBindApplication` 返回 | 进程级初始化完成，未进入业务 | hook 该方法的返回 |
| 首个 Activity `onResume` | UI 栈建立，业务入口已就绪 | Activity 生命周期 hook |
| 首帧提交 | 启动路径走完，启动期逻辑通常已结束 | `Choreographer` 首帧回调 / `ViewTreeObserver` |
| 主线程空闲 | 启动任务队列排空 | `Looper` idle handler |

语义：

- 越早的锚点可用资源越少，但离业务越远；
- 越晚的锚点越接近"目标已稳定运行"，与启动期逻辑的竞态越小；
- 锚点之间是包含关系，选择即是在"尽早介入"与"避开启动期逻辑"之间取位置。

目标存在启动期自检时，锚点取在自检完成之后，并以该事件为起点计算后续动作；时长只能作为锚点缺失时的近似。持续轮询型检测不受锚点影响。

## 4. so 的加载语义

"加载一个 so"有四种语义，行为不同：

| 方式 | 归属命名空间 | JNI_OnLoad | 适用场景 |
|---|---|:--:|---|
| `dlopen(path)` | 调用者当前所在 namespace | 不调用 | 系统库、已在搜索路径内的库 |
| `android_dlopen_ext(path, info.namespace)` | 显式指定的 namespace | 不调用 | 需要跨命名空间加载 App 私有库 |
| `System.load(path)` | caller class 所属 classloader 的 namespace | 调用 | 由 App 类发起，加载 App 私有库 |
| `Runtime.load(path, ClassLoader)` | 指定 classloader 的 namespace | 调用 | 显式指定归属；targetSdk ≥ 35 被平台禁用 |

判据：**加载结果 = f(namespace, caller class)**。文件存在与否只是必要条件。

选择规则：

- 能拿到 App classloader 且 targetSdk < 35 → `Runtime.load(path, loader)`；
- 能拿到 App classloader 但 targetSdk ≥ 35 → 由 App classloader 下的类执行 `System.load`；
- 拿不到 classloader，但能取到 namespace 句柄 → `android_dlopen_ext` + `USE_NAMESPACE`；
- 目标库在系统搜索路径内 → `dlopen` 即可。

## 5. 动态链接器与命名空间

- linker 维护多个 namespace（default、classloader-namespace、vendor、sphal 等），每个有自己的搜索路径与可见性。
- classloader-namespace 与 App 的 nativeLibraryDir 绑定，建立时机在 `handleBindApplication` 期间。
- `android_get_exported_namespace(name)` 取 namespace 句柄；`android_dlopen_ext` 通过 `ANDROID_DLEXT_USE_NAMESPACE` 使用它。
- zip 内路径（`base.apk!/lib/<abi>/x.so`）由 linker 直接支持，不需要先解压。
- memfd 是匿名文件，其 stat/read 受 SELinux 域策略约束。
- 加载顺序：`do_dlopen` → 依赖解析 → `call_constructors`（`DT_INIT` / `.init_array`）→（仅 `System.load`/`Runtime.load` 路径）`JNI_OnLoad`。

## 6. ClassLoader 与加载归属

| 类型 | 来源 | parent |
|---|---|---|
| BootClassLoader | 系统 | — |
| PathClassLoader | App 默认，加载 base.apk 与 split | BootClassLoader |
| DexClassLoader | 指定 dex/jar/apk 路径 | 可指定 |

- 库的归属由 caller class 的 classloader 决定，"由哪个类发起加载"是设计变量。
- `System.load` 用 caller class 的 loader；caller 为 boot 类时进入 boot 命名空间，App 私有目录不可见。
- 在 native 线程调用 `FindClass` 走 boot classloader，App 自定义类不可见；需从已有 jobject 取 classloader。
- `DexClassLoader` 可加载任意可读的 dex，用于把"加载动作"放进指定 classloader 上下文：自建一个只调用 `System.load` 的类，由 native 侧加载并调用，即可在无 Xposed 框架时把库归入 App 命名空间。

## 7. ART 与方法 hook

| 版本 | jmethodID 语义 | native 方法 hook 点 |
|---|---|---|
| Android 10 | 即 `ArtMethod*` | ArtMethod 内的 JNI 函数指针 |
| Android 11+ | 索引，需经映射取 ArtMethod | 结构偏移随版本变化 |

- native 方法：替换 ArtMethod 中的 JNI 指针即可改变实现。
- Java 方法：没有 JNI 指针，需改解释器/编译入口（`entry_point_from_*`），与 native 方法属两套机制。
- `JNI_OnLoad` 仅在 `System.load`/`Runtime.load` 路径被运行时调用，`dlopen` 不会触发。

## 8. SELinux 与 capability

两个正交的权限维度，任一不满足都会被拒：

| 维度 | 载体 | 表现 |
|---|---|---|
| capability | 进程 | UID 0 但无 `CAP_SYS_PTRACE` → ptrace 被拒 |
| SELinux | 进程域 × 目标标签 | `untrusted_app` 读特定标签被拒 |

- 文件有标签，进程有域，访问由策略矩阵决定；App 私有目录标签为 `app_data_file` 且带 MLS categories，写入需保持标签与 categories 一致。
- `/data/local/tmp` 标签为 `shell_data_file`，不同域对它的权限不同。
- `setenforce 0` 是全局开关，作用于整个系统，不是单进程。
- 跨域写文件、ptrace、加载非常规路径的 so，都同时受这两个维度约束。

## 9. 包管理与路径

- 安装路径 `/data/app/<pkg>-<后缀>/base.apk`，后缀在重装/升级后改变。
- `ApplicationInfo` 提供 `sourceDir`、`splitSourceDirs`、`nativeLibraryDir`、`dataDir`；后两者是加载与写文件的正确来源。
- `extractNativeLibs=false` 时 native 库直接从 APK 内映射。
- `targetSdkVersion` 决定多项平台行为（hidden API 策略、加载 API 限制、后台限制）。

## 10. Binder 与跨进程数据

- 系统服务通过 `ServiceManager` 获取；App 间通过 `ContentProvider` 暴露数据。
- 跨进程访问：`getContentProviderExternal(authority, userId, token)` → `IContentProvider.call(callingPkg, authority, method, arg, extras)`。
- Provider 需 exported，调用方身份由系统校验。
- Binder 回调运行在线程池中的 Binder 线程，不是主线程。

## 11. 进程内可观测状态

| 位置 | 内容 |
|---|---|
| `/proc/self/maps` | 已加载 so 路径、匿名与 memfd 映射 |
| `/proc/self/task/*/comm` | 线程名 |
| `/proc/self/fd` | 打开的 socket/文件 |
| `/proc/net/tcp` | 监听端口 |
| 进程内存 | 加载器与框架的特征字符串 |
| `TracerPid` | 是否被 ptrace |

映射具有继承性：zygote 中的映射存在于所有子进程中。可观测面的选择因此要区分"进程内可见"与"仅目标可见"。

## 12. hook 框架的分层设计

由前述机制直接导出的框架结构：

| 层 | 职责 | 机制依据 |
|---|---|---|
| 注入层 | 决定代码进入哪些进程 | zygote 注入影响全部子进程；单进程注入只影响目标；系统模块在 specialize 阶段介入 |
| 时机层 | 决定在生命周期哪一段执行 | 资源时间轴：Java/classloader/namespace 按阶段就绪；锚点见 §3 |
| 上下文层 | 决定加载归属与执行线程 | 加载归属由 classloader/namespace 决定；等待与调度放后台线程，避免阻塞启动路径 |
| 生命周期层 | 隐藏、开关、卸载、版本适配 | 映射继承与可观测面；ArtMethod 布局随版本变化 |

设计顺序（从目标特征反推）：

1. 目标 ABI 与进程结构（是否多进程、需覆盖哪些进程名）；
2. 是否需要 Java 层能力（决定时机下限是 attach 之后）；
3. 目标的 targetSdk（决定可用的加载 API）；
4. 待加载 so 的位置（决定走 classloader 还是显式 namespace）；
5. 目标启动期有哪些自检（决定初始化锚点）；
6. 载体所需的 capability 与 SELinux 域（决定注入方式与环境准备）。