/**
 * native_memguard.js - Native 内存错误守卫（无源码、无需 debuggable）
 *
 * 用途：在 user build + 非 debuggable 应用上替代 malloc debug（该路径要求
 *       linker 读属性或应用 debuggable，很多设备用不了）。
 *       本模块用 Frida 在 libc 层自建"分配表 + 拷贝边界检查"。
 *
 * 原理：
 *   1) hook malloc/calloc/realloc/free，维护 指针 → 大小 的表（有上限，LRU 淘汰）
 *   2) hook memcpy/memmove/memset/strcpy/strncpy/strcat，检查目标区间是否越界
 *   3) 越界/非法释放 → 打印调用栈（含 so+offset），便于回 Ghidra 定位
 *
 * 覆盖与局限：
 *   - 只覆盖堆分配（栈/全局越界抓不到，那需要 ASan/MTE）
 *   - strcpy 系列按实际字符串长度算，读取越界源可能崩（可用 checkStrcpy 关闭）
 *   - 有性能开销，定向测试时开，跑完即退
 *
 * 加载：
 *   frida -H 127.0.0.1:27042 -n Gadget -l scripts/core/utils.js -l scripts/monitors/native_memguard.js -q -t 120
 *
 * 配置：
 *   var CONFIG_OVERRIDE = {
 *     native_memguard: {
 *       trackAlloc: true,      // 维护分配表（越界检测依赖它）
 *       checkCopies: true,     // 检查 memcpy/memmove/memset
 *       checkStrcpy: false,    // 检查 strcpy/strncpy/strcat（读取源串，风险略高）
 *       maxEntries: 50000,     // 分配表上限
 *       minCopySize: 8,        // 小于该长度的拷贝不检查（降噪）
 *       logBigCopy: 4096,      // 超过该长度的拷贝即使不越界也打印
 *       backtrace: true
 *     }
 *   };
 *
 * REPL：MemGuard.stats()
 */
(function (global) {
  'use strict';

  var U = global.Utils;
  if (!U) { console.log("[-] native_memguard requires utils.js (load it first)"); return; }

  var CONFIG = U.mergeConfig('native_memguard', {
    trackAlloc: true,
    checkCopies: true,
    checkStrcpy: false,
    maxEntries: 50000,
    minCopySize: 8,
    logBigCopy: 4096,
    backtrace: true
  });

  var SIZES = new Map();       // NativePointer(string) -> size
  var ORDER = [];              // 简易 FIFO，用于淘汰
  var STATS = { alloc: 0, free: 0, realloc: 0, checked: 0, overflow: 0, badfree: 0, bigcopy: 0 };

  function key(p) { return p.toString(); }

  function remember(p, size) {
    var k = key(p);
    if (!SIZES.has(k)) ORDER.push(k);
    SIZES.set(k, size);
    while (ORDER.length > CONFIG.maxEntries) {
      var old = ORDER.shift();
      SIZES.delete(old);
    }
  }

  function forget(p) {
    var k = key(p);
    var size = SIZES.get(k);
    SIZES.delete(k);
    return size;
  }

  function frames(context) {
    if (!CONFIG.backtrace) return "";
    try {
      return Thread.backtrace(context, Backtracer.ACCURATE).slice(0, 6).map(function (f) {
        var m = Process.findModuleByAddress(f);
        return m ? (m.name + "+0x" + f.sub(m.base).toString(16)) : String(f);
      }).join(" <- ");
    } catch (e) { return ""; }
  }

  function exp(name) {
    return Module.findExportByName("libc.so", name) || Module.findExportByName(null, name);
  }

  function hookAlloc() {
    var p = exp("malloc");
    if (p) Interceptor.attach(p, {
      onEnter: function (args) { this.size = args[0].toInt32(); },
      onLeave: function (ret) {
        STATS.alloc++;
        if (!ret.isNull()) remember(ret, this.size);
      }
    });

    var c = exp("calloc");
    if (c) Interceptor.attach(c, {
      onEnter: function (args) { this.n = args[0].toInt32(); this.sz = args[1].toInt32(); },
      onLeave: function (ret) {
        STATS.alloc++;
        if (!ret.isNull()) remember(ret, this.n * this.sz);
      }
    });

    var r = exp("realloc");
    if (r) Interceptor.attach(r, {
      onEnter: function (args) { this.ptr = args[0]; this.size = args[1].toInt32(); },
      onLeave: function (ret) {
        STATS.realloc++;
        if (!this.ptr.isNull()) forget(this.ptr);
        if (!ret.isNull()) remember(ret, this.size);
      }
    });

    var f = exp("free");
    if (f) Interceptor.attach(f, {
      onEnter: function (args) {
        STATS.free++;
        var p2 = args[0];
        if (p2.isNull()) return;
        var size = forget(p2);
        if (size === undefined) {
          STATS.badfree++;
          U.fail("[MEMGUARD] free 未登记指针 " + p2 + "（double free / 非堆指针？）");
          U.fail("          bt: " + frames(this.context));
        }
      }
    });

    U.ok("alloc hooks: malloc/calloc/realloc/free");
  }

  function checkRange(dst, len, name, context) {
    STATS.checked++;
    if (len < CONFIG.minCopySize) return;

    var size = SIZES.get(key(dst));
    if (size !== undefined && len > size) {
      STATS.overflow++;
      U.fail("[MEMGUARD] " + name + " 越界: dst=" + dst + " 分配=" + size + " 写入=" + len);
      U.fail("          bt: " + frames(context));
      return;
    }
    if (len >= CONFIG.logBigCopy) {
      STATS.bigcopy++;
      U.ok("[MEMGUARD] " + name + " 大拷贝 dst=" + dst + " len=" + len +
           (size !== undefined ? " (分配=" + size + ")" : " (非本表分配)"));
    }
  }

  function hookCopies() {
    // 长度参数位置：memcpy/memmove/memset 都是第 3 个参数
    [["memcpy", 2], ["memmove", 2], ["memset", 2]].forEach(function (item) {
      var p = exp(item[0]);
      if (!p) return;
      Interceptor.attach(p, {
        onEnter: function (args) {
          checkRange(args[0], args[item[1]].toInt32(), item[0], this.context);
        }
      });
    });
    U.ok("copy hooks: memcpy/memmove/memset");

    if (CONFIG.checkStrcpy) {
      [["strcpy", 1], ["strcat", 1]].forEach(function (item) {
        var p = exp(item[0]);
        if (!p) return;
        Interceptor.attach(p, {
          onEnter: function (args) {
            try {
              var src = args[1].readCString();
              checkRange(args[0], (src ? src.length : 0) + 1, item[0], this.context);
            } catch (e) {}
          }
        });
      });
      var sc = exp("strncpy");
      if (sc) Interceptor.attach(sc, {
        onEnter: function (args) {
          checkRange(args[0], args[2].toInt32(), "strncpy", this.context);
        }
      });
      U.ok("str hooks: strcpy/strcat/strncpy");
    }
  }

  Java.perform(function () {
    U.ok("=== native_memguard ===");
    if (CONFIG.trackAlloc) hookAlloc();
    if (CONFIG.checkCopies) hookCopies();
    U.ok("config: maxEntries=" + CONFIG.maxEntries + " minCopySize=" + CONFIG.minCopySize +
         " logBigCopy=" + CONFIG.logBigCopy + " checkStrcpy=" + CONFIG.checkStrcpy);
    global.MemGuard = {
      stats: function () { return STATS; },
      tableSize: function () { return SIZES.size; }
    };
  });
})(this);
