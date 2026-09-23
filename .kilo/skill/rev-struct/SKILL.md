---
name: rev-struct
description: Reconstruct data structures by analyzing memory access patterns across functions
---

# rev-struct - Structure Recovery

Recover data structure definitions by analyzing memory access patterns in functions and their call chains.

> Adapted from P4nda0s/reverse-skills (MIT) for the Ghidra MCP toolchain (upstream targets IDA; the analysis methodology is unchanged).

## Pre-check

This skill operates on decompiled native code. In this agent the toolchain is **Ghidra MCP** (`ghidra_*` tools):

1. Target .so not yet imported → `adb pull` it from the device, then `ghidra_import_file` (ELF auto-detects; explicit IDs: ARM64 `AARCH64:LE:64:v8A`, ARM32 `ARM:LE:32:v7`).
2. Query the loaded instance through Ghidra MCP: decompile functions by address/name, get callers/callees, inspect data types.
3. Exact tool names depend on the loaded tool groups — list or search them with `ghidra_list_tool_groups` / `ghidra_search_tools` when unsure.

If no Ghidra instance is connected, check `ghidra_list_instances` and connect with `ghidra_connect_instance`, or ask the user to start one.

## Structure Recovery Steps

### Step 1: Read Target Function

1. Decompile the function at the user-provided address/name via Ghidra MCP
2. Note its callers and callees (cross-references)
3. Identify pointer parameters in the function (potential structure pointers)

### Step 2: Collect Memory Access Patterns

Search for the following patterns in the target function:

**Direct offset access:**
```c
*(a1 + 0x10)           // offset 0x10
*(_DWORD *)(a1 + 8)    // offset 0x8, DWORD type
*(_QWORD *)(a1 + 0x20) // offset 0x20, QWORD type
*(_BYTE *)(a1 + 4)     // offset 0x4, BYTE type
```

**Array access:**
```c
*(a1 + 8 * i)          // array, element size 8 bytes
a1[i]                  // array access
```

**Nested structures:**
```c
*(*a1 + 0x10)          // first field of struct pointed by a1 is a pointer
```

**Record format:**
```
offset=0x00, size=8, access=read/write, type=QWORD
offset=0x08, size=4, access=read, type=DWORD
...
```

### Step 3: Traverse Callers for Analysis

Decompile each caller (start from direct callers; expand one hop at a time and stop once the offset pattern stops changing) and analyze:

1. **Parameter passing**: What is passed when calling?
   ```c
   sub_401000(v1);        // v1 might be a struct pointer
   sub_401000(&v2);       // v2 is a struct
   sub_401000(malloc(64)); // struct size is ~64 bytes
   ```

2. **Operations before/after the call**:
   ```c
   v1 = malloc(0x40);     // allocate 0x40 bytes
   *v1 = 0;               // offset 0x00 initialization
   *(v1 + 8) = callback;  // offset 0x08 is a function pointer
   sub_401000(v1);
   ```

3. **Collect more offset accesses**

### Step 4: Traverse Callees for Analysis

Decompile each callee (direct callees first, same one-hop-at-a-time rule) and analyze:

1. **How parameters are used**:
   ```c
   // In callee
   int callee(void *a1) {
       return *(a1 + 0x18);  // accesses offset 0x18
   }
   ```

2. **Passed to other functions**:
   ```c
   another_func(a1 + 0x20);  // offset 0x20 might be a nested struct
   ```

### Step 5: Aggregate and Infer

1. **Merge all offset information**, sort by offset
2. **Calculate struct size**: max(offset) + last_field_size
3. **Infer field types**:
   - Called as function pointer → function pointer
   - Passed to `strlen`/`printf` → string pointer
   - Compared with constants → enum/flags
   - Increment/decrement operations → counter/index
4. **Identify common patterns**:
   - Offset 0 is a function pointer table → vtable (C++ object)
   - next/prev pointers → linked list node
   - refcount field → reference counted object

### Step 6: Apply the Struct in Ghidra

Define the recovered struct through Ghidra MCP datatype tools (create struct + fields at the recovered offsets), then re-decompile the functions — the decompiler now renders field names instead of raw offsets, and inconsistent accesses expose wrong guesses. Iterate until the view is consistent.

---

## Output Format

```c
/*
 * Structure Recovery Analysis
 * Source function: <func_address>
 * Analysis scope: <number of callers/callees analyzed>
 *
 * Functions using this struct:
 *   - 0x401000 (initialization)
 *   - 0x401100 (field access)
 *   - 0x401200 (destruction)
 */

// Estimated size: 0x48 bytes
// Confidence: High / Medium / Low

struct suggested_name {
    /* 0x00 */ void *vtable;           // vtable pointer, called: (*(*this))()
    /* 0x08 */ int refcount;           // reference count, has ++/-- operations
    /* 0x0C */ int flags;              // flags, AND with 0x1, 0x2
    /* 0x10 */ char *name;             // string, passed to strlen/printf
    /* 0x18 */ void *data;             // data pointer
    /* 0x20 */ size_t size;            // size field
    /* 0x28 */ struct node *next;      // linked list next pointer
    /* 0x30 */ struct node *prev;      // linked list prev pointer
    /* 0x38 */ callback_fn handler;    // callback function
    /* 0x40 */ void *user_data;        // user data
};

// Field access examples:
// 0x401000: *(this + 0x08) += 1;     // refcount++
// 0x401100: printf("%s", *(this + 0x10));  // print name
```
