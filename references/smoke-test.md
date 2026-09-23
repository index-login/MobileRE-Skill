# 冒烟自检（可选，验证整套链路）

回归清单：验证 Frida 注入 / ELF 侦察 / 离线复算链路可用。样本为 OWASP MASTG UnCrackable（开源练习 App），本地目录 `owasp.mstg.uncrackable2/`（L2）、`owasp.mstg.uncrackable3/`（L3），含 `base.apk` / `libfoo.so` 与历史脚本、截图。

## L2（基线，`Level_02`）

- `scripts/checklist/fridainject.js` 弹窗出现
- `tools/elfinfo.py` 导出地址与运行时基址相加精确对上
- `libc!strncmp` + 调用者过滤 + 23 位输入拿到 secret（`Thanks for all the fish`）

## L3（逻辑混淆回归，`Level_03`）

- `init` 启动时被调用两次（memcpy 24B 到全局 + counter++，counter 1→2）；`bar` 要求 counter==2、输入 24 字节，`expected[i] = initArr[i] XOR gen(LCG 展开)[i]` → secret `making owasp great again`
- 已知坑 1：`waitForModule` 竞态（改用 dlopen 同步 hook）
- 已知坑 2：函数中部 inline hook 会崩——机制已定位（2026-09-23）：hook `bar` 内 `0x3434` → `stack corruption detected (-fstack-protector)` → SIGABRT（tombstone `bar+252` = `__stack_chk_fail` 调用点），**只 hook 函数入口**（`bar` 入口 + gen 生成器 `0x10e0` 入口/onLeave）全程稳定
- 已知坑 3（2026-09-23）：`bar`/`init` 的 Java 参数是 **`byte[]`（不是 String）**。按 jstring 读会得到假值（`getStringLength` 返回假 12 / 读到窗口切片），且会把启动期 `init` 调用写成 SIGSEGV（tombstone pc 落在注入 agent `memfd:xjd-cache`，易误判为反调试）。正确读法：JNIEnv vtable 偏移 `0x558=GetArrayLength`、`0x5c0=GetByteArrayElements`（取自本 so 自身反汇编）
- Frida 端进程名是 App label（`Uncrackable Level 3`），`-n <包名>` 报 ProcessNotFoundError，attach 用 PID
- UI 驱动：`input text` 异步——先 `elements` 确认字段内容再点 VERIFY；输入框未聚焦时 `--replace` 的 DEL 无效
- 安全脚本与完整复现：`owasp.mstg.uncrackable3/hook_l3_dump.js`、`owasp.mstg.uncrackable3/REPORT.md`

## 离线复算（无需设备）

```bash
python3 tools/emu_run.py owasp.mstg.uncrackable2/libfoo.so --sym Java_sg_vantagepoint_uncrackable2_CodeCheck_bar --jni --poke 0x1300c:1=1 --args "env,0,'Thanks for all the fish'"
```

→ `x0=0x1`（错误串得 `x0=0x0`）
