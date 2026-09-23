'use strict';

// mem_trace.js — 设备侧内存访问追踪（MemoryAccessMonitor：只动页保护，不改代码段）
// 输出与 tools/trace_recon.py 兼容的日志行：
//   [wr] 0xADDR size=N val=0xV pc=0xPC
//   [rd] 0xADDR size=1 pc=0xPC   （读事件 size 为近似值，仅用于定位）
// 与仿真路径等价：仿真 = emu_run --watch-write → 本模块 = 真机版
//
// 配置（CONFIG_OVERRIDE.mem_trace）:
//   ranges: [{module:"libfoo.so", off:0x15038, size:24, mode:"w"|"rw"} | {base:0x..., size:24}]
//   pollMs: 50   未加载模块的轮询间隔
// 用法（frida_run 示例）:
//   python3 tools/frida_run.py -H 127.0.0.1:8888 -f com.app \
//     -l scripts/core/utils.js -l scripts/monitors/mem_trace.js \
//     -e 'var CONFIG_OVERRIDE={mem_trace:{ranges:[{module:"libfoo.so",off:0x15038,size:24,mode:"w"}]}};' -t 20
//
// 说明:
// - MemoryAccessMonitor 为"一次性"：某页触发后自动解除，本模块在异步里 diff 内存并重臂，
//   两次重臂间隙的写入仍会被 diff 捕获（读取当前内容与影子对比），但高频跨页访问会变慢
// - 建议监视范围小而精（对齐目标缓冲），避免整页热点被反复触发

var CFG = { ranges: [], pollMs: 50, rearm: false };
if (typeof CONFIG_OVERRIDE !== 'undefined' && CONFIG_OVERRIDE.mem_trace) {
  Object.assign(CFG, CONFIG_OVERRIDE.mem_trace);
}

var armed = {};
var busy = {};

function keyOf(r) {
  return (r.module || "abs") + ":" + (r.off !== undefined ? r.off : r.base);
}

function readBytes(base, size) {
  try { return new Uint8Array(Memory.readByteArray(base, size)); } catch (e) { return null; }
}

function leHex(bytes) {
  var v = BigInt(0);
  for (var i = bytes.length - 1; i >= 0; i--) { v = (v << BigInt(8)) | BigInt(bytes[i]); }
  return "0x" + v.toString(16);
}

function diffRuns(a, b) {
  var runs = [];
  var i = 0;
  var n = Math.min(a.length, b.length);
  while (i < n) {
    if (a[i] !== b[i]) {
      var j = i;
      while (j < n && a[j] !== b[j]) j++;
      runs.push([i, j - i]);
      i = j;
    } else {
      i++;
    }
  }
  return runs;
}

function arm(w) {
  MemoryAccessMonitor.enable({ base: w.base, size: w.size }, {
    onAccess: function (d) {
      // details 只在回调期内有效：同步取出字段，异步做 diff（字段名按 frida 版本兼容）
      var op = d.operation;
      var from = (d.pc !== undefined) ? d.pc : ((d.from !== undefined) ? d.from : null);
      var addr = d.address;
      if (busy[w.key]) return;
      busy[w.key] = true;
      setTimeout(function () { settle(w, op, from, addr); }, 0);
    }
  });
}

function settle(w, op, from, addr) {
  var step = "start";
  try {
    step = "op";
    if (op === 'write') {
      step = "read";
      var cur = readBytes(w.base, w.size);
      if (cur && w.shadow) {
        step = "diff";
        var runs = diffRuns(w.shadow, cur);
        for (var i = 0; i < runs.length; i++) {
          var off = runs[i][0];
          var len = runs[i][1];
          step = "emit";
          console.log("[wr] " + w.base.add(off) + " size=" + len +
            " val=" + leHex(cur.subarray(off, off + len)) + " pc=" + from);
        }
        w.shadow = cur;
      }
    } else if (op === 'read') {
      step = "emit-rd";
      console.log("[rd] " + addr + " size=1 pc=" + from);
    }
    if (CFG.rearm) {
      step = "rearm";
      w.shadow = readBytes(w.base, w.size);
      arm(w);
    } else {
      step = "done-oneshot";
      console.log("[mem_trace] " + w.key + " one-shot consumed (rearm=false)");
    }
  } catch (e) {
    console.log("[mem_trace] settle error at " + step + ": " + e);
  } finally {
    busy[w.key] = false;
  }
}

function tryArm(r) {
  var k = keyOf(r);
  if (armed[k]) return;
  var base = null;
  if (r.module) {
    var m = Process.findModuleByName(r.module);
    if (!m) return;
    base = m.base.add(r.off || 0);
  } else if (r.base !== undefined) {
    base = ptr(r.base);
  }
  if (!base) return;
  armed[k] = {
    key: k, base: base, size: r.size,
    mode: r.mode || "w", shadow: readBytes(base, r.size)
  };
  console.log("[mem_trace] armed " + base + " size=" + r.size + " mode=" + (r.mode || "w") +
    (r.module ? " (" + r.module + "+0x" + (r.off || 0).toString(16) + ")" : ""));
  arm(armed[k]);
}

(function () {
  var dl = Module.findExportByName(null, "android_dlopen_ext");
  if (dl) {
    Interceptor.attach(dl, {
      onLeave: function () { CFG.ranges.forEach(tryArm); }
    });
  }
  setInterval(function () { CFG.ranges.forEach(tryArm); }, CFG.pollMs);
})();
