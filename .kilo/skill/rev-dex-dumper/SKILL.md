---
name: rev-dex-dumper
description: Root memory dump of DEX from a running Android app: no injection, no ptrace (survives ptrace-blocking anti-debug; invisible to Frida checks), twin tools cross-check each other. Activate to unpack an APK, extract decrypted DEX, or defeat class-loading packing; for extraction shells or Frida-based dumping see frida-mobile-security.
---

# rev-dex-dumper - Android DEX Dumper

Dump DEX files from a running Android application's memory via ADB. Two bundled tools (arm64):

| Tool | Access path | Freezes target | Role |
|------|-------------|----------------|------|
| `panda-dex-dumper` | `/proc/<pid>/mem` | SIGSTOP / SIGCONT | primary |
| `mem-dex-dumper` | `/proc/<pid>/mem` or `process_vm_readv(2)` | none | alternative / cross-check |

**Neither tool uses `ptrace`.** They read process memory directly (`/proc/<pid>/mem`; `mem-dex-dumper` can also use `process_vm_readv(2)`) and still work against a process that has claimed the ptrace slot via `PTRACE_TRACEME` (TracerPid != 0): anti-debug that polices `TracerPid` or blocks `PTRACE_ATTACH` does not stop them, while a genuinely ptrace-based dumper would be blocked.

---

## Tool Location

The binaries are bundled in this skill's directory. Resolve absolute paths relative to this SKILL.md file:

```
skills/rev-dex-dumper/panda-dex-dumper
skills/rev-dex-dumper/mem-dex-dumper
skills/rev-dex-dumper/mem-dex-dumper.c    (source)
```

---

## Workflow

### 1. Push the tool to device

```bash
adb push <path-to>/panda-dex-dumper /data/local/tmp/
adb shell chmod +x /data/local/tmp/panda-dex-dumper
```

### 2. Determine target package name

If the user provides a package name, use it directly. Otherwise, get the foreground app:

```bash
adb shell dumpsys activity top | grep 'ACTIVITY' | tail -1 | awk '{print $2}' | cut -d/ -f1
```

### 3. Run the dumper

```bash
adb shell "cd /data/local/tmp && ./panda-dex-dumper -p $(adb shell pidof <package_name>)"
```

The dumped DEX files are saved to `/data/local/tmp/panda/` on the device.

### 4. Pull DEX files to host

```bash
adb pull /data/local/tmp/panda/ ./
```

Pull to the user's current working directory.

### 5. Clean up device cache

```bash
adb shell rm -rf /data/local/tmp/panda/
adb shell rm /data/local/tmp/panda-dex-dumper
```

---

## mem-dex-dumper (alternative / cross-check)

```bash
adb push <path-to>/mem-dex-dumper /data/local/tmp/
adb shell chmod +x /data/local/tmp/mem-dex-dumper
adb shell "su -c 'cd /data/local/tmp && ./mem-dex-dumper -p <pid> -o /data/local/tmp/memdump'"
adb pull /data/local/tmp/memdump/ ./
adb shell "su -c 'rm -rf /data/local/tmp/memdump/ /data/local/tmp/mem-dex-dumper'"
```

Options: `-p <pid>` (required), `-o <outdir>` (default `/data/local/tmp/memdump`), `-b mem|vmreadv` (default `mem` = `/proc/<pid>/mem`; `vmreadv` = `process_vm_readv(2)`). Use it to cross-check a panda dump, for extra coverage, or when the target must not be frozen.

Source: `mem-dex-dumper.c` in this directory. Rebuild with the NDK (r21+):

```bash
aarch64-linux-android29-clang -O2 -static -o mem-dex-dumper mem-dex-dumper.c
llvm-strip mem-dex-dumper
```

### Background

- `mem-dex-dumper` is a tool we developed in-house — source (`mem-dex-dumper.c`) and rebuild steps ship with the skill. When it misbehaves, fix the source and rebuild (see Debugging / fixing below).
- `panda-dex-dumper` is a third-party binary without source, so it can only be worked around, not fixed.
- The two tools cross-check each other: for the same address, output is byte-identical whenever both choose the same size.

### How it works

1. Parse `/proc/<pid>/maps`; iterate readable regions ≥ 0x70 bytes.
2. Read in 1 MiB chunks with a 7-byte overlap, so a `dex\n` magic straddling a chunk boundary is still seen.
3. Scan for `dex\n` + 3 digits + NUL (any DEX version).
4. `try_dump()` validates the header before dumping: `header_size == 0x70`, `endian_tag` ∈ {0x12345678, 0x78563412}, `0x70 ≤ file_size ≤ 1 GiB`, `string_ids`/`class_defs` tables inside `file_size`.
5. Dedupe: hits inside an already-dumped range are skipped (also suppresses re-hits from chunk overlap).
6. Dump `file_size` bytes in 1 MiB chunks; on a failed read keep the partial data (`dumped < file_size` in the log).

Per-hit log: `find dex off: 0x<addr>  file_size: 0x<n>  dumped: 0x<n>`; final line `scanned <N> bytes, done.` — the primary diagnostic surface.

### Known issues

| Symptom | Cause | Action |
|---------|-------|--------|
| `open /proc/<pid>/mem: Permission denied` | not root / SELinux / kernel restriction | run via `su -c`; if still denied, try `-b vmreadv` |
| `-b vmreadv` fails (EPERM/EINVAL) | kernel/SELinux blocks `process_vm_readv` for the target | use the default backend; syscall presence: `grep process_vm_readv /proc/kallsyms` |
| No hits although the app is packed | payload not decrypted yet, or header intentionally scrambled | keep the app foregrounded past splash; cross-check with panda |
| Fewer files than panda | (a) strict validation rejects corrupted headers that panda dumps as `guess_size` fragments; (b) range-dedupe swallows a DEX nested inside a bigger claimed range | compare logs; for (b) bypass `in_dumped()` temporarily, or extract the inner address manually (`dd` from `/proc/<pid>/mem`) |
| Very large file (tens of MB) | `.vdex`-embedded header with inflated `file_size` | noise — the payload lives in anon heap (`[anon:libc_malloc]`); verify structure first |
| Some classes fail to parse | torn live read (packer wrote memory while scanning) | re-run; if reproducible, prefer panda (SIGSTOP gives a frozen snapshot) |
| Won't exec on another device | arm64-only, static, API 29 | rebuild for the target ABI (above) |

Not bugs: extra/missing hits vs panda in mapped system-jar territory (`/system/framework/*.jar`, `/apex/*/javalib/*.jar`, `*.vdex`) — different scan heuristics, treat as noise. `pidof` returning several PIDs: dump each process separately, the payload may live in any of them.

### Debugging / fixing

1. Read stdout first: per-hit lines + `scanned N bytes`. Name each hit's mapping with `grep <addr-prefix> /proc/<pid>/maps` (file-backed = usually system noise; anon heap = payload).
2. Validate a suspicious dump structurally (header fields + class descriptors) before blaming the tool.
3. Missing hits → loosen `try_dump()` checks (start with `header_size`), or confirm the region is readable (`dd` from `/proc/<pid>/mem`).
4. Compare with panda on shared addresses — md5-equal means both extracted the same bytes.
5. Sandbox: a tiny process that loads a known DEX into heap and sleeps (run via `su`) is a good repro target — dump it with both backends, compare md5 with the source file.
6. After any change: rebuild + strip (above), re-run the sandbox test, keep the log format stable.

---

## Guidelines

1. **Always verify ADB connection first** — run `adb devices` and confirm a device is listed before proceeding.
2. **Root is required** — both tools read another UID's process memory. On production builds `adb root` fails; run via `su -c`.
3. **Wait for app to fully load** — if the user is dumping a packed app, the real DEX is only available after the packer's class loader has decrypted it. Advise the user to navigate past the splash screen before dumping.
4. **Handle pidof failure** — if `pidof` returns empty, the app may not be running. Launch it first with `adb shell monkey -p <package_name> -c android.intent.category.LAUNCHER 1`.
5. **Multiple DEX files are normal** — packed apps often produce several DEX files. All files in `/data/local/tmp/panda/` should be pulled.
6. **Always clean up** — remove both the dumped DEX files and the tool binary from the device after pulling results to avoid leaving artifacts.
