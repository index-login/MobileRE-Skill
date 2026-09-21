---
name: rev-symbol
description: Restore function symbols by analyzing code patterns, strings, constants, and cross-references
---

# rev-symbol - Symbol Recovery

Analyze function code characteristics to recover/identify function symbols and names.

> Adapted from P4nda0s/reverse-skills (MIT) for the Ghidra MCP toolchain (upstream targets IDA; the analysis methodology is unchanged).

## Data Sources

The upstream skill reads an IDA-NO-MCP export directory (`decompile/*.c` with `callers:` / `callees:` headers, `strings.txt`, `imports.txt`, `exports.txt`). The equivalent sources here — repo scripts live under `frida-mobile-security/scripts/utils/`:

| Data | Offline (no Ghidra instance) | Ghidra MCP |
|------|------------------------------|------------|
| Imports / exports / deps / relocs / segments / vaddr↔offset | `elfinfo.py <so> --json` | `ghidra_list_imports`, `ghidra_list_exports`, `ghidra_list_external_locations` |
| Strings | `strings -a -t x <so>` | `ghidra_list_strings`, `ghidra_search_strings` |
| String → code xrefs | `find_strref.py <so> <str_vaddr>` | `ghidra_get_xrefs_to` |
| Callers of a function | `find_branch_callers.py <so> <func_vaddr>` | `ghidra_get_function_callers` |
| Callees of a function | read from the pseudocode | `ghidra_get_function_callees` |
| Function pseudocode | — | `ghidra_decompile_function` |
| Whole-.so export (upstream layout) | — | `ghidra_batch_decompile` + `ghidra_get_bulk_xrefs`, or a custom dump via `ghidra_run_ghidra_script` |

The offline tools need no Ghidra instance and are deterministic — use them for the static tables; use Ghidra MCP for pseudocode, xrefs and renaming. Single-function recovery should query on demand; build a full export only when the whole .so is in scope.

## Pre-check

Ghidra MCP (`ghidra_*` tools):

1. Target .so not yet imported → `adb pull` it from the device, then `ghidra_import_file` (ELF auto-detects the language; explicit IDs: ARM64 `AARCH64:LE:64:v8A`, ARM32 `ARM:LE:32:v7`).
2. Query the loaded instance: decompile by address/name, get callers/callees, list strings/imports/exports, rename functions, apply comments.
3. Exact tool names depend on the loaded tool groups — list or search them with `ghidra_list_tool_groups` / `ghidra_search_tools` when unsure.

If no Ghidra instance is connected, check `ghidra_list_instances` and connect with `ghidra_connect_instance`, or ask the user to start one.

## Symbol Recovery Steps

### Step 1: Analyze Internal Characteristics

Carefully examine the target function for:

- **String constants**: Strings used in the function may reveal its purpose
- **Numeric constants / Magic Numbers**:
  - MD5: `0x67452301`, `0xEFCDAB89`, `0x98BADCFE`, `0x10325476`
  - CRC32: `0xEDB88320`
  - Base64 charset: `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`
  - AES S-Box: `0x63, 0x7C, 0x77, 0x7B...`
  - Zlib: `0x78`, `0x9C` (compression header)
  - other constants/magic numbers...
- **Code structure**: Loop patterns, bitwise operations, specific algorithm flows

If you can identify a known algorithm through constants/structure, tell the user directly.

### Step 2: Analyze Cross-References

**Analyze Callees (called functions):**

- Get the callee list with `ghidra_get_function_callees`, or read the calls from the pseudocode (`ghidra_decompile_function`).
- Classify each callee against the import table — `ghidra_list_imports` / `ghidra_list_external_locations`, or `elfinfo.py` offline. A callee that resolves to an import (external location, `thunk_*`, undefined in .dynsym) is a library call; name it from the import symbol.
- Recognize call patterns even when symbols are missing:

**Paired function patterns (identify by matching call pairs):**

```c
// malloc/free, new/delete, alloc/dealloc
xx = sub_A(0x100);        // alloc: takes size, returns pointer
...
sub_B(xx);                // free: takes the same pointer

// mutex_lock/mutex_unlock, pthread_mutex_lock/unlock
sub_A(lock_ptr);          // lock
...                       // critical section
sub_B(lock_ptr);          // unlock (same lock object)

// open/close, fopen/fclose, CreateFile/CloseHandle
fd = sub_A("/path", 0);   // open: path + flags, returns handle
...
sub_B(fd);                // close: takes the handle

// pthread_create/pthread_join
sub_A(&tid, 0, func, arg); // create: out param, attr, func, arg
...
sub_B(tid, &ret);          // join: tid, out param
```

**Argument pattern recognition:**

```c
// socket(AF_INET, SOCK_STREAM, 0) - fixed constants
sub_XXX(2, 1, 0);         // socket: domain=2, type=1, protocol=0

// connect/bind(sockfd, addr, addrlen)
sub_XXX(fd, &var, 16);   // addr struct, len=16 for IPv4

// memcpy/memmove(dst, src, size)
sub_XXX(dst, src, n);     // 3 params: dst, src, count

// memset(ptr, value, size)
sub_XXX(ptr, 0, 0x100);   // 3 params: ptr, byte value, count

// read/write(fd, buf, count)
ret = sub_XXX(fd, buf, n); // returns bytes read/written

// strcmp/strncmp(s1, s2) or (s1, s2, n)
if (sub_XXX(s1, s2) == 0)  // returns 0 on equal
```

**Return value patterns:**

```c
// file/socket operations: -1 on error
if ((fd = sub_XXX(...)) == -1) goto error;

// allocation: NULL on failure
if (!(ptr = sub_XXX(size))) goto error;

// success/error: 0 = success
if (sub_XXX(...) != 0) goto error;

// strlen: returns size_t
len = sub_XXX(str);
sub_YYY(dst, src, len);   // len used in memcpy
```

**Analyze Callers (calling functions):**

- Get the caller list with `ghidra_get_function_callers`, or `find_branch_callers.py` offline.
- A caller counts as *named* only when its symbol is not auto-generated (`FUN_` / `sub_` / `thunk_` / `LAB_` / `j_` prefix) — i.e. it comes from the export table or has already been renamed.
- Bounded recursion: if the direct caller is unnamed, walk up its callers; stop at the first named caller or at depth 3. If nothing is named, fall back to internal characteristics (Step 1) and web search (Step 3).
- Analyze how the return value is used by callers.

### Step 3: Information Gathering and Search

Collect the following information:

- Strings referenced by the function (`ghidra_get_xrefs_to` on the string address, or `find_strref.py` offline)
- Magic Numbers / constants
- Known imports in the call chain (`ghidra_list_imports`, or `elfinfo.py` offline)
- Caller/callee symbol names (`ghidra_list_exports`, `elfinfo.py` exports, already-renamed functions)
- Paired function patterns identified

Based on collected information:

1. First attempt local reasoning based on:
   - Function signature (number and types of parameters)
   - Paired call patterns (alloc/free, lock/unlock)
   - Known imports in the call chain
   - Code structure similarity to known algorithms

2. If uncertain, use **Web Search** to search:
   - Search Magic Numbers: `0x67452301 0xEFCDAB89 algorithm`
   - Search code patterns: `rotate left xor constant algorithm`
   - Search unique strings found in the function
   - Search parameter patterns: `function(int, int, 0) socket`

---

## Output Format

```
## Symbol Recovery Analysis: <function_address>

### Function Characteristics
- Strings: <list discovered strings>
- Constants: <list key constants>
- Called imports: <list>

### Cross-Reference Analysis
- Callers: <callers and their symbols>
- Callees: <callees and their symbols>

### Inference Result
- **Suggested symbol name**: <suggested_name>
- **Confidence**: High / Medium / Low
- **Reasoning**: <explain why this name is suggested>

### Similar Open Source Implementation
- <if similar open source code is found, provide link>
```
