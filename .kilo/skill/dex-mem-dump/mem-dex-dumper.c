/* mem-dex-dumper: dump DEX files from a live Android process without ptrace.
 *
 * Access path: /proc/<pid>/mem (default) or process_vm_readv(2) (-b vmreadv).
 * Scans readable mappings from /proc/<pid>/maps for DEX magic, validates the
 * header (magic/version/header_size/endian/ids bounds), then writes each hit
 * to <outdir>/dex_0x<addr>.dex.
 *
 * Build (NDK r21+, arm64):
 *   aarch64-linux-android29-clang -O2 -static -o mem-dex-dumper mem-dex-dumper.c
 *   llvm-strip mem-dex-dumper
 *
 * Verified equivalent to panda-dex-dumper output (byte-identical for all
 * shared addresses) on Android 10 / cn.boccfc.loan.finance, 2026-09.
 * See SKILL.md. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/types.h>

#define CHUNK       (1u << 20)
#define OVERLAP     7
#define MAX_DEX     (1u << 30)

static int g_pid = -1;
static int g_memfd = -1;
static int g_backend = 0; /* 0=/proc/pid/mem, 1=process_vm_readv */
static const char *g_outdir = "/data/local/tmp/memdump";

struct range { uint64_t start, end; };
static struct range g_ranges[8192];
static int g_nranges = 0;

static ssize_t rd(uint64_t addr, void *buf, size_t len) {
  if (g_backend == 0)
    return pread(g_memfd, buf, len, (off_t)addr);
  struct iovec local = { buf, len };
  struct iovec remote = { (void *)(uintptr_t)addr, len };
  return process_vm_readv(g_pid, &local, 1, &remote, 1, 0);
}

static int is_dex_magic(const unsigned char *m) {
  if (memcmp(m, "dex\n", 4) != 0) return 0;
  if (m[7] != 0) return 0;
  for (int i = 4; i < 7; i++)
    if (m[i] < '0' || m[i] > '9') return 0;
  return 1;
}

static uint32_t le32(const unsigned char *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int in_dumped(uint64_t addr) {
  for (int i = 0; i < g_nranges; i++)
    if (addr >= g_ranges[i].start && addr < g_ranges[i].end) return 1;
  return 0;
}

static void try_dump(uint64_t addr) {
  unsigned char hdr[112];
  if (rd(addr, hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) return;
  if (!is_dex_magic(hdr)) return;
  uint32_t file_size   = le32(hdr + 0x20);
  uint32_t header_size = (uint32_t)hdr[0x24] | ((uint32_t)hdr[0x25] << 8);
  uint32_t endian      = le32(hdr + 0x28);
  if (header_size != 0x70) return;
  if (endian != 0x12345678 && endian != 0x78563412) return;
  if (file_size < 0x70 || file_size > MAX_DEX) return;
  uint32_t sid_size = le32(hdr + 0x38), sid_off = le32(hdr + 0x3c);
  uint32_t cdd_size = le32(hdr + 0x60), cdd_off = le32(hdr + 0x64);
  if (sid_size && (uint64_t)sid_off + (uint64_t)sid_size * 4 > file_size) return;
  if (cdd_size && (uint64_t)cdd_off + (uint64_t)cdd_size * 32 > file_size) return;
  if (in_dumped(addr)) return;

  char path[512];
  snprintf(path, sizeof(path), "%s/dex_0x%llx.dex", g_outdir, (unsigned long long)addr);
  int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (fd < 0) { fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return; }

  unsigned char *buf = malloc(CHUNK);
  uint64_t remain = file_size, cur = addr;
  while (remain) {
    size_t want = remain > CHUNK ? CHUNK : (size_t)remain;
    ssize_t n = rd(cur, buf, want);
    if (n <= 0) break;
    if (write(fd, buf, n) != n) break;
    cur += n; remain -= n;
    if ((size_t)n < want) break;
  }
  close(fd);
  free(buf);

  uint64_t dumped = file_size - remain;
  if (g_nranges < 8192) {
    g_ranges[g_nranges].start = addr;
    g_ranges[g_nranges].end = addr + (dumped ? dumped : 1);
    g_nranges++;
  }
  printf("find dex off: 0x%llx  file_size: 0x%x  dumped: 0x%llx\n",
         (unsigned long long)addr, file_size, (unsigned long long)dumped);
  fflush(stdout);
}

int main(int argc, char **argv) {
  int opt;
  while ((opt = getopt(argc, argv, "p:o:b:")) != -1) {
    switch (opt) {
      case 'p': g_pid = atoi(optarg); break;
      case 'o': g_outdir = optarg; break;
      case 'b': g_backend = strcmp(optarg, "vmreadv") == 0 ? 1 : 0; break;
      default:
        fprintf(stderr, "usage: %s -p <pid> [-o outdir] [-b mem|vmreadv]\n", argv[0]);
        return 1;
    }
  }
  if (g_pid <= 0) { fprintf(stderr, "need -p <pid>\n"); return 1; }

  char mpath[64];
  snprintf(mpath, sizeof(mpath), "/proc/%d/mem", g_pid);
  if (g_backend == 0) {
    g_memfd = open(mpath, O_RDONLY);
    if (g_memfd < 0) { fprintf(stderr, "open %s: %s\n", mpath, strerror(errno)); return 1; }
  }

  mkdir(g_outdir, 0755);
  printf("pid %d backend=%s output=%s\n", g_pid,
         g_backend ? "process_vm_readv" : "/proc/pid/mem", g_outdir);

  char lpath[64];
  snprintf(lpath, sizeof(lpath), "/proc/%d/maps", g_pid);
  FILE *fp = fopen(lpath, "r");
  if (!fp) { perror("maps"); return 1; }

  unsigned char *buf = malloc(CHUNK);
  char line[512];
  unsigned long long total = 0;
  while (fgets(line, sizeof(line), fp)) {
    unsigned long long start, end;
    char perms[8];
    if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3) continue;
    if (perms[0] != 'r') continue;
    uint64_t size = end - start;
    if (size < 0x70) continue;
    total += size;
    for (uint64_t off = 0; off < size; ) {
      size_t want = (size - off) > CHUNK ? CHUNK : (size_t)(size - off);
      ssize_t n = rd(start + off, buf, want);
      if (n <= 0) { off += want; continue; }
      for (ssize_t i = 0; i + 8 <= n; i++) {
        if (buf[i] == 'd' && buf[i+1] == 'e' && buf[i+2] == 'x' && buf[i+3] == '\n')
          try_dump(start + off + i);
      }
      off += (n > OVERLAP) ? (uint64_t)(n - OVERLAP) : (uint64_t)n;
    }
  }
  fclose(fp);
  printf("scanned %llu bytes, done.\n", total);
  return 0;
}
