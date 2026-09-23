# 行为分析（Behavior Analysis）

> 何时读：用户提到"看网络请求/抓包/还原协议/行为摸底/全程监控/污点追踪/内存扫描/Intent/Serializable"时读取。
> 由 SKILL.md 任务路由表指向，按需读取。相关模块在 `scripts/monitors/`。

---

## 一、行为摸底

```
Step 1: 全量监控
  模块: utils + file_monitor + network_monitor + thread_monitor
  ├── [file_monitor 看到 .dat/.json/.xml] → 追加 crypto_monitor
  ├── [network_monitor 看到陌生 IP 或大量 DNS] → 追加 dl_monitor + crypto_monitor
  ├── [thread_monitor 看到周期性 pthread_create] → 追加 syscall_tracer
  └── [所有模块无输出] → 追加 syscall_tracer(traceAll:true)
```

## 二、网络协议分析

```
Step 1: network_monitor
  模块: utils + network_monitor
  ├── [明文 HTTP/JSON/Protobuf] → 结束
  └── [密文/TCP 字节流] →
       ├── 标准 TLS (端口 443) → SSL Pinning 绕过（见 crypto-hook.md）
       ├── 自定义加密 TCP → 先分析加密层（crypto-hook.md）
       └── 多通道（WebSocket/Binder/Unix Socket）→ proc_monitor + syscall_tracer
```

## 三、跨组件污点追踪（Source → Flow → Sink）

```
攻击链模型：
  Source（不可信数据入口）→ Flow（跨组件传递）→ Sink（危险操作）

Step 1: intent_tracker — 追踪数据在组件间流动
  模块: utils + intent_tracker
  │
  ├── [有输出] → 看到完整的组件跳转链 + Intent extras 内容
  │   ├── 结合 file_monitor 看是否对应文件操作
  │   ├── 结合 network_monitor 看是否对应网络请求
  │   └── 三链路对齐 → 确认完整攻击链 (source→flow→sink)
  │
  └── [无输出] → 组件通信不走标准 Intent API
       ├── 可能是 Binder 直接调用 → 下钻到 syscall_tracer
       └── 可能是 Unix Socket → proc_monitor

Step 2: 组合攻击链验证
  模块: utils + intent_tracker + file_monitor + network_monitor
  操作: 触发 deeplink / 发送 Intent → 观察三模块日志：
  │
  ├── intent_tracker: ExportedActivity → InternalActivity (extras:{url: "evil.com"})
  ├── file_monitor:   InternalActivity.openat /data/data/.../secret.db
  └── network_monitor: InternalActivity.connect evil.com:443
  │
  └── 三条日志时间戳对齐 → 攻击链确认
```

---

## 四、模块间交叉分析

单模块日志提供**纵向**信号（某种行为是否发生），多模块日志交叉分析提供**横向**关联（行为之间的因果关系）。以下模式帮助判断路由：

### 4.1 配置文件解密识别

```
信号组合: file_monitor 看到 read /data/.../config.dat
         + crypto_monitor 随后出现 AES/ECB/PKCS5Padding 解密
时间窗口: file_monitor 时间戳 < crypto_monitor 时间戳 < 1ms
结论:     config.dat 是加密配置文件，算法为 AES/ECB
操作:     用 crypto_monitor 输出的密钥和 IV 离线解密 config.dat
```

### 4.2 Native 层网络初始化识别

```
信号组合: dl_monitor 看到加载 libnetwork.so
         + network_monitor 随后出现 connect(... 443)
时间窗口: dl_monitor < network_monitor < 500ms
结论:     libnetwork.so 负责网络初始化，可能在 .init_array 中执行
操作:     对该 so 追加 init_hook — 配置 onModuleInit:libnetwork.so
```

### 4.3 检测 so 定位（反检测协同）

```
信号组合: so_loader_tracer 看到加载 libDetect.so
         + exit_blocker 随后立即 BLOCKED exit_group
时间窗口: so_loader_tracer < exit_blocker < 10ms
结论:     libDetect.so 的 init_array 触发了退出（典型反 Frida 检测）
操作:     → 加载 anti-detection.md Phase 2-6
```

### 4.4 加密函数 native 层定位

```
信号组合: network_monitor 看到 sendto(... 密文 payload, length=256)
         + syscall_tracer 看到 write(fd, len=256) 在同一线程、同一时间戳
时间窗口: |network_monitor 时间戳 - syscall_tracer 时间戳| < 2ms
结论:     write() 的调用者就是加密/发送函数
操作:     在 write() hook 中执行 Thread.backtrace() → 第2-3帧即加密函数地址
         → Process.findModuleByAddress 解析为 libxxx.so+0xoffset
```

### 4.5 关联模式速查

| 信号组合 | 结论 | 时间窗口 |
|---------|------|---------|
| file_monitor `read /data/.../config.dat` → crypto_monitor `AES/ECB` | 加密配置文件 | <1ms |
| dl_monitor `libnetwork.so` → network_monitor `connect(...443)` | native 网络初始化 | <500ms |
| so_loader_tracer `libDetect.so` → exit_blocker `BLOCKED exit_group` | 反 Frida 检测 | <10ms |
| network_monitor `sendto(密文,256)` + syscall_tracer `write(fd,256)` 同线程同时 | 加密/发送函数 | <2ms |
| intent_tracker `ExportedActivity → WebViewActivity` + file_monitor `openat .../secret.db` | 跨组件攻击链 | <500ms |
| intent_tracker extras 含 `Serializable` + file_monitor 读到私有文件 | 反序列化攻击链 | intent_tracker 先于 file_monitor |

### 4.6 反向推断：用缺失信号做排除

```
场景: 你 hook javax.crypto.Cipher 但无输出
交叉验证: 同时加载 file_monitor
  → file_monitor 有输出 → utils.js 正常、Frida 正常、进程正常 — 问题锁定在 Java hook 层
  → file_monitor 也无输出 → 可能：
      - app 在 Frida attach 前就退出了 → 检查 exit_blocker
      - 目标进程不是 JVM 进程 → 检查 Java.available
      - Frida 没有正确注入 → 检查 frida-ps -U 确认进程可见
```

---

## 五、设备交互（`tools/device_ui.py`）

常用动作：`text`（空格自动转 `%s`；`--replace` 先清空）、`clear`、`tap --text/--id`、`wait-for`、`launch`、`shot`、`logs`、`stayon`/`wake`。

**元素树异常时退化为坐标操作**：个别场景 `tools/device_ui.py elements` 只 dump 到系统 App（App 已在前台、`dumpsys window` 焦点正常），`tap --text/--id` 全部 "no element matched"。兜底：`adb shell input tap X Y` + `adb shell input text ...`，坐标从一次成功截图量取（先 `shot` 再量）。

---

## 常用组合

| 分析目标 | 模块组合 |
|---------|---------|
| 行为摸底 | `utils + file_monitor + network_monitor + thread_monitor` |
| 字节级协议 | `utils + network_monitor(showPayload:true)` |
| 子进程监控 | `utils + proc_monitor` |
| 跨组件污点追踪 | `utils + intent_tracker` |
| 完整攻击链 | `utils + intent_tracker + file_monitor + network_monitor` |
| 全量覆盖 | `utils + file + thread + network + syscall + dl + proc + crypto`（日志量大） |