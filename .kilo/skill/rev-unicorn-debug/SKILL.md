---
name: rev-unicorn-debug
description: Debug and emulate specific code fragments or functions using the Unicorn engine. Activate when the user wants to emulate a function with Unicorn, trace binary execution without running the full program, decrypt or decode data by emulating the algorithm, or bypass environment dependencies (JNI, syscalls, libc) during emulation.
---

# rev-unicorn-debug - Unicorn Emulation Debugger

Debug and emulate specific code fragments or functions using the Unicorn engine. Analyze context dependencies (JNI, syscalls, library functions) and simulate them through hook mechanisms to complete the user's debugging goal.

> Source: P4nda0s/reverse-skills (MIT).

## Prerequisites

```bash
pip install unicorn
```

Unicorn is the CPU emulation engine (Python binding, Windows wheel available — no JDK or Android toolchain needed). It emulates instructions only: loading the .so, resolving relocations, and simulating libc/JNI/syscalls are done by the Python harness you write (see below).

## Harness kit (tools/uniharness.py)

Import it instead of rewriting boilerplate:

```python
from uniharness import Harness, asm, JNI_SLOTS

h = Harness(trace=False)                    # trace=True prints every instruction
h.map_raw("lib.so", 0, 0x10000)             # vaddr==file offset; else h.map_elf("lib.so")
h.setup_stack()
h.setup_tls()                               # TPIDR_EL0 + canary at TLS+40

env = h.jni_env(slots={JNI_SLOTS["NewByteArray"]: cb})   # fake JNIEnv: stub + hook per slot
r = h.call(0x196C, args=[env, 0])           # run until ret; r.x0, r.insns
```

Helpers: `map` / `map_raw` / `map_elf` / `alloc` / `setup_stack` / `setup_tls` / `stub` (accepts `code=` from `asm()`) / `hook` / `jni_env` / `call` / `run` / `fault`. Self-test: `python3 uniharness.py`.

Recon before writing a harness (raw-map check / deps / exports / relocs): `tools/so.py info`.
Dependencies: see repo root `requirements.txt` (unicorn, capstone, keystone-engine, pyelftools).

## CLI runner (tools/emu_run.py)

One-shot emulation without writing a harness:

```bash
python3 tools/emu_run.py libfoo.so --sym Java_pkg_Cls_method --jni --args "env,0,'text'" --poke 0x1300c:1=1 --read 0x1000:32
```

Options: `--off 0x..` (address instead of symbol), `--imp` (extra import stubs), `--trace`, `--timeout`, `--raw`, `--setup hooks.py` (full `Harness` access), `--stub name=val` (override an import stub's return, e.g. `getpid=1234`), `--log-jni` (log every JNI call: `[jni] name(args) -> ret`, string/array args decoded), `--dump-jni-out FILE` (append NewStringUTF / SetByteArrayRegion payloads), `--trace-stubs` (log every stub hit: `[stub] name(args) -> ret`; both logs aggregate beyond `--watch-max`).

Observability layer (white-box / VM / algorithm work): `--watch-code PC --watch-regs x0,x1 --watch-buf "x19+0x61f0:16"`, `--watch-read/--watch-write lo-hi` (auto-aggregated beyond `--watch-max`), `--scan hex[,hex] [--scan-at PC]`. Pair with `tools/trace_recon.py` (event log -> buffer state sequence) and `tools/cipher_lab.py` (layer/table/schedule adjudication).

---

## Core Principles

1. **Load file raw first** — do NOT parse ELF/PE/Mach-O headers. Read the file as raw bytes and map directly into Unicorn memory. We only need to emulate specific functions, not the entire binary. If raw loading fails (code references segments at specific addresses), then parse minimally — only map the segments needed.
2. **Identify context dependencies** — analyze the target code for external calls (JNI, syscalls, libc, imports) and hook them to provide simulated responses.
3. **Use callbacks extensively** — leverage Unicorn's hook system for debugging, tracing, error recovery, and environment simulation.
4. **Iterative fix** — when emulation crashes, use the callback info to diagnose and fix (map missing memory, hook unhandled calls, fix register state).
5. **Minimal trace output** — prefer block-level tracing over instruction-level. Only enable instruction trace on small targeted ranges. Use counters and summaries instead of per-step logging.

---

## Environment Simulation Strategy

Before emulating, read the target function and identify what it calls. Hook external dependencies by address and simulate in Python:

| Category | Examples | Simulation Strategy |
|----------|----------|-------------------|
| libc | `malloc`, `free`, `memcpy`, `strlen`, `printf` | Hook address, implement logic in Python (bump allocator for malloc) |
| JNI | `GetStringUTFChars`, `FindClass`, `GetMethodID` | Build fake JNIEnv function table in UC memory, write RET stubs at each entry, hook stub addresses |
| Syscalls | `read`, `write`, `mmap`, `ioctl` | Hook `UC_HOOK_INTR`, dispatch by syscall number |
| C++ runtime | `operator new`, `__cxa_throw` | Hook and simulate |
| Library calls | `pthread_mutex_lock`, `dlopen` | Hook and return success/stub |
| TLS | `mrs xN, TPIDR_EL0` (stack canary, errno) | Map a page and set `UC_ARM64_REG_TPIDR_EL0` to its base; canary checks pass as long as prologue/epilogue reads hit the same bytes |

**JNIEnv slot math:** table entries are 8 bytes each, in `jni.h` declaration order — e.g. slot 176 = `NewByteArray`, 184 = `GetByteArrayElements`, 208 = `SetByteArrayRegion`. Derive the slot from the disassembly (`ldr x8, [x8, #1408]` → 1408 / 8 = 176).

**Hook pattern:** Register a `UC_HOOK_CODE` callback. When PC hits a known import address, execute the Python simulation, then set PC = LR to skip the original function.

---

## Callback Types to Use

| Callback | Purpose |
|----------|---------|
| `UC_HOOK_CODE` | Intercept import calls by address; instruction-level trace (use sparingly, narrow range only) |
| `UC_HOOK_BLOCK` | Block-level trace (preferred over instruction trace) |
| `UC_HOOK_MEM_UNMAPPED` | Auto-map missing pages to recover from unmapped access errors |
| `UC_HOOK_MEM_READ \| UC_HOOK_MEM_WRITE` | Trace memory access on targeted data ranges only |
| `UC_HOOK_INTR` | Intercept SVC/INT for syscall simulation |

**Range gotcha:** `hook_add`'s `end` is **inclusive**. For a 4-byte stub use `end = addr + size - 1`; with adjacent stubs an off-by-one makes neighbouring callbacks fire into each other (they see the other call site's registers).

---

## Iterative Debugging Workflow

When emulation fails, follow this loop:

1. **Run** — start emulation, let it crash
2. **Read callback output** — which address faulted? What type (read/write/fetch)?
3. **Diagnose**:
   - Unmapped memory fetch → missing code page, map it
   - Unmapped memory read/write → missing data section or uninitialized pointer, map or hook
   - Hitting an import stub → identify the function, add a simulation hook
   - TLS access fault (`mrs xN, TPIDR_EL0` followed by a load from an offset) or `__stack_chk_fail` reached → map a TLS page and set `UC_ARM64_REG_TPIDR_EL0` (see Environment Simulation)
   - Infinite loop → add a code hook with execution counter, stop after threshold
4. **Fix** — add the hook / map the memory / adjust registers
5. **Re-run** — repeat until the target function completes

---

## Architecture Quick Reference

| Arch | Uc Const | Mode | SP | LR | Args | Return | Syscall |
|------|----------|------|----|----|------|--------|---------|
| ARM64 | `UC_ARCH_ARM64` | `UC_MODE_LITTLE_ENDIAN` | SP | X30 | X0-X7 | X0 | X8 + SVC #0 |
| ARM32 | `UC_ARCH_ARM` | `UC_MODE_THUMB` / `UC_MODE_ARM` | SP | LR | R0-R3 | R0 | R7 + SVC #0 |
| x86-64 | `UC_ARCH_X86` | `UC_MODE_64` | RSP | (stack) | RDI,RSI,RDX,RCX,R8,R9 | RAX | RAX + syscall |
| x86-32 | `UC_ARCH_X86` | `UC_MODE_32` | ESP | (stack) | (stack) | EAX | EAX + int 0x80 |
| MIPS32 | `UC_ARCH_MIPS` | `UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN` | $sp | $ra | $a0-$a3 | $v0 | $v0 + syscall |
