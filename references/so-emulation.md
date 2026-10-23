# 单函数离线仿真（SO Emulation）

> 何时读：`so-emulate` 卡片走不通时；需要模拟 JNI/syscall/TLS、写 Harness、或判断"该 hook 还是该仿真"。

## 1. 定位：仿真是下钻手段，不是首选

| 情况 | 选择 |
|---|---|
| App 能跑，只看一次真实调用 | **真机 hook**（`native_hooker`，见 [native-analysis.md ›「三、SO 动态分析」](native-analysis.md)） |
| 要试上万个输入 / 需要穷举 | 仿真（`emu_run`） |
| 反调试挂不上 / 不想在设备留痕 | 仿真 |
| 依赖大量真实上下文（网络、文件、TEE） | 真机 hook；仿真只能近似，结论要标置信度 |

## 2. 快速路径

```bash
python3 tools/emu_run.py <so> --sym <export> --args "0,0" --timeout 5
python3 tools/emu_run.py <so> --sym Java_pkg_Cls_m --jni --args "env,0" --trace-stubs
```

常用参数：`--off`（按地址）、`--raw`（vaddr==offset 时强制 raw 映射）、`--trace`、`--timeout`、`--imp`、`--stub name=val`、`--log-jni`、`--dump-jni-out`、`--setup hooks.py`。
完整参数与观测层（`--watch-*` / `--scan`）见 [native-analysis.md ›「3.6 复杂函数离线仿真（emu_run 广度 + setup 助手）」](native-analysis.md)。

## 3. 环境模拟

libc（`malloc`/`memcpy`/`printf`）、C++ runtime（`operator new`）、`pthread_*`/`dlopen` 这类常规符号 `emu_run` 已内置桩，不用手写。需要自己处理的只有三类：

**JNI**：UC 内存里建假 `JNIEnv` 表，表项 8 字节、按 `jni.h` 声明顺序，每槽写 RET 桩，再钩桩地址。
槽位从反汇编反推：`ldr x8, [x8, #1408]` → 1408 / 8 = 176 = `NewByteArray`。
实测需要：23 `DeleteLocalRef`、172 `NewObjectArray`、174 `SetObjectArrayElement`、176 `NewByteArray`、179 `NewIntArray`、184 `GetByteArrayElements`、208 `SetByteArrayRegion`、211 `SetIntArrayRegion`。

**syscall**：`UC_HOOK_INTR` 里按 X8 的 syscall 号分发（ARM64）。

**TLS**：`mrs xN, TPIDR_EL0` 读 canary/errno → 映射一页并设 `UC_ARM64_REG_TPIDR_EL0`，canary 前后读到同一地址即通过（`Harness.setup_tls()` 已封装）。

**钩子写法**：`UC_HOOK_CODE` 命中导入地址 → Python 模拟 → `PC = LR` 跳过原函数。

## 4. Harness kit（`tools/uniharness.py`）

```python
from uniharness import Harness, asm, JNI_SLOTS

h = Harness(trace=False)
h.map_raw("lib.so", 0, 0x10000)       # vaddr==file offset；否则 h.map_elf("lib.so")
h.setup_stack()
h.setup_tls()                          # TPIDR_EL0 + canary at TLS+40
env = h.jni_env(slots={JNI_SLOTS["NewByteArray"]: cb})
r = h.call(0x196C, args=[env, 0])      # r.x0, r.insns
```

Helpers：`map` / `map_raw` / `map_elf` / `alloc` / `setup_stack` / `setup_tls` / `stub`（可传 `asm()` 的 `code=`）/ `hook` / `jni_env` / `call` / `run` / `fault`。自检：`python3 uniharness.py`。

**独立 Harness 的坑（实测）**：`h.map_elf` 只做映射，**不装导入桩**；直接 `h.call` 打到未重定位的 GOT 会 `pc=0`。正确顺序：

```python
import emu_run
h.map_elf(so); h.setup_stack(); h.setup_tls()
stubs = emu_run.make_libc_stubs(h, extra=[])
emu_run.apply_relocations(h, so, stubs)
emu_run.run_init(h, so)
```

## 5. 写好 hooks.py（与 `tools/emu_setup.py` 协作）

hooks.py 只需一个入口，拿到 Harness 全权：

```python
import emu_setup as E

def setup(h):
    s = E.std_string(h, b"aGVoZWhl")
    print(E.call_sret(h, 0x22168, [s]))       # b'...'，sret(x8) 返回 std::string
    E.install_stub(h, 0x4F6A8, my_memmove)    # 覆盖默认 _ret0 桩
```

- **执行时机**：`map → stack/TLS → 导入桩+重定位 → JNIEnv → --poke → setup(h) → DT_INIT → syscall 层 → 调用`。setup 里能读到 `--poke` 写的内存，但 DT_INIT 之后全局还可能被覆盖。
- **是 exec 不是 import**：hooks.py 在独立命名空间执行（`__name__ = "__emu_setup__"`），`if __name__ == "__main__"` 不生效；内部 `import emu_run` 会重新执行模块，别依赖其模块级全局（字节数组长度表因此挂在 Harness 上）。

| helper | 返回 / 作用 |
|---|---|
| `std_string(h, data, addr=None)` | 造 libc++ `std::string`（≤22 短串 / 长串自动），返对象地址 |
| `read_std_string(h, obj)` | 解回 bytes |
| `std_vector(h, data)` / `read_std_vector(h, obj)` | `vector<char>` 造 / 读 |
| `call_sret(h, fn, args, ret="string")` | 按 x8 sret 调用；`ret` 取 `string` / `vector` / `raw` |
| `install_stub(h, got, impl)` | GOT 槽装干净桩后挂 impl，避开 `apply_relocations` 已挂的 `_ret0` |
| `patch_data_import(h, got, data_addr)` | 数据导入槽指向现成数据 |
| `ctype_table(h)` | 258 字节 ctype 表（alnum 位），返地址 |
| `cstr(h, s)` / `argv_stack(h, argv)` | C 字符串 / 栈上 argv 数组 |

libc++ 布局：短串 `[0]=size<<1`、data 从 `[1]`；长串 `[0]=(cap<<1)|1`、`[8]=size`、`[16]=ptr`；vector `[0]=begin,[8]=end,[16]=cap`。

## 6. 卡壳树

| 症状 | 处理 |
|---|---|
| 一上来就取指/数据错 | 先 `so.py info` 看 `raw=YES/NO`：`vaddr==offset` 才能 `map_raw`，否则 `map_elf` 或 `--raw` 反向使用 |
| 独立 Harness 直接 `pc=0` | 没装重定位/导入桩：按 §4 的顺序调 `make_libc_stubs` / `apply_relocations` / `run_init` |
| 相邻导入的钩子串台 | `hook_add` 的 `end` 是**闭区间**：4 字节桩写 `end = addr + 3`，多写一字节就跑到隔壁调用点 |
| TLS 访问崩 / `__stack_chk_fail` | `setup_tls()`；确认 prologue/epilogue 读到同一 canary |
| 死循环无返回 | 代码钩子里加执行计数，超阈值停；或 `--timeout` |
| JNI 调用返回 NULL 后崩 | `--jni` + `--trace-stubs` 看命中哪个槽；按槽补回调返回有效对象 |
| C++ 对象入参错位 | `--setup` + `emu_setup.std_string/std_vector`；sret 用 `--ret-str` / `call_sret` |
| `[!] unstubbed: name` | 该导入没桩：`--imp name` 或 `--stub name=val` |
| 结果不可信（依赖真实上下文） | 降级为真机 hook，仿真结论标置信度 |

## 7. 实例（`libtztCalcKit.so`）

```bash
python3 tools/emu_run.py libtztCalcKit.so --sym tztZFGetRefValue --args "0,0" --timeout 5
# x0=0x0  insns=4

python3 tools/emu_run.py libtztCalcKit.so --sym tztZZKlineReleaseMemory --args "0"
# x0=0x0  insns=10

python3 tools/emu_run.py libtztCalcKit.so --sym Java_com_tztZZKlineCalc_getKLineTechObjData \
  --jni --args "env,0" --trace-stubs
# [stub] GetIntArrayElements(...) -> 0x0
# [stub] GetObjectClass(...) -> 0x0
# x0=0x0  insns=80
```
