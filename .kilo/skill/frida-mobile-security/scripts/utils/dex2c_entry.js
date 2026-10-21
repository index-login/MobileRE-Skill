/**
 * dex2c_entry.js - 按 ArtMethod 定位 native / DEX2C 方法的真实入口
 *
 * 与 utils/scan_register_natives.js 互补：
 *   - scan_register_natives 依赖"注册时在场"（spawn），attach 场景拿不到历史注册；
 *   - 本模块任意时刻读取 ArtMethod，attach 可用，并能解析匿名跳板。
 *
 * 加载：
 *   frida -H 127.0.0.1:27042 -n Gadget \
 *     -l scripts/core/utils.js -l <cfg.js> -l scripts/utils/dex2c_entry.js -q -t 15
 *
 * 用法（cfg.js）：
 *   var CONFIG_OVERRIDE = {
 *     dex2c_entry: {
 *       classes: ["com.example.Foo"],
 *       methods: ["onCreate", "onResume"],
 *       hook: false
 *     }
 *   };
 *
 * 输出示例：
 *   [+] Foo.onResume() : void[0] native
 *       data  = 0x7c7e5915f8 -> libexecmain.so+0x4a5f8
 *       quick = 0x7c8e56f2c0 -> libart.so+0x13f2c0
 *       jump  = libexecmain.so+0x4a5f8 (depth=1)
 *
 * 判定规则：
 *   native=true  → data_ 指向真实 JNI 函数
 *   native=false → data_=0，说明运行时已被壳替换/回填，需从内存 dex 取代码
 */
(function (global) {
  'use strict';

  var U = global.Utils;
  if (!U) { console.log("[-] dex2c_entry requires utils.js (load it first)"); return; }

  var CONFIG = U.mergeConfig('dex2c_entry', {
    // 目标类，如 ["com.newtzt.activity.tztZZThirdLaunchActivity"]
    classes: [],
    // 方法名过滤，空 = 全部
    methods: [],
    // 对匿名可执行跳板做反汇编跟随（b / ldr+br / adrp+add+br）
    resolveTrampoline: true,
    // 跳板最大跟随层数
    maxDepth: 4,
    // 打印入口前 N 字节，0 = 不打印
    showBytes: 16,
    // 解析成功后是否直接 Interceptor.attach
    hook: false,
    // 只输出 ACC_NATIVE 方法；false 时可看到被回填成 Java 的方法（data_=0）
    onlyNative: true
  });

  // ArtMethod 布局（Android 64 位，API 26+）
  //   0  declaring_class_ (4) | 4  access_flags_ (4)
  //   8  dex_code_item_offset_ (4) | 12 dex_method_index_ (4)
  //   16 method_index_ (2) | 18 hotness_count_ (2)
  //   24 ptr_sized_fields_.data_                          <- native 的 JNI 入口
  //   32 ptr_sized_fields_.entry_point_from_quick_compiled_code_
  var OFF_DATA = 24;
  var OFF_QUICK = 32;
  var ACC_NATIVE = 0x0100;

  function where(addr) {
    var m = Process.findModuleByAddress(addr);
    if (m) return m.name + "+0x" + addr.sub(m.base).toString(16);
    var r = Process.findRangeByAddress(addr);
    if (r) return "anon " + r.base + "-" + r.base.add(r.size) + " " + r.protection;
    return "unmapped";
  }

  function isExec(addr) {
    var r = Process.findRangeByAddress(addr);
    return !!(r && r.protection.indexOf("x") >= 0);
  }

  // 解析 ARM64 跳板。壳常用三种：
  //   b imm                 直接跳
  //   ldr xN,[pc,#d]; br xN 读字面量
  //   adrp+add+br xN        页基址 + 偏移
  function resolveArm64Jump(start) {
    var p = start;
    var regs = {};
    for (var i = 0; i < 4; i++) {
      var ins;
      try { ins = Instruction.parse(p); } catch (e) { return null; }
      var ops = ins.operands;

      if (ins.mnemonic === "br" && ops.length) return regs[ops[0].value] || null;

      if (ins.mnemonic === "adrp" && ops.length >= 2) {
        var page = ins.address.and(ptr("0xfffffffffffff000"));
        regs[ops[0].value] = page.add(ops[1].value);
      } else if (ins.mnemonic === "add" && ops.length >= 3 && regs[ops[0].value] !== undefined) {
        regs[ops[0].value] = regs[ops[0].value].add(ops[2].value);
      } else if (ins.mnemonic === "ldr" && ops.length >= 2 &&
                 ops[1].type === "mem" && ops[1].mem.base === "pc") {
        var lit = ins.address.add(ops[1].mem.disp);
        try { regs[ops[0].value] = lit.readPointer(); } catch (e) { return null; }
      }
      p = p.add(4);
    }
    return null;
  }

  function follow(addr) {
    var cur = addr;
    for (var d = 0; d < CONFIG.maxDepth; d++) {
      if (Process.findModuleByAddress(cur)) {
        return { addr: cur, where: where(cur), depth: d, ok: true };
      }
      if (!isExec(cur)) return { addr: cur, where: where(cur), depth: d, ok: false };

      var target = null;
      try {
        var ins = Instruction.parse(cur);
        if (ins.mnemonic === "b" && ins.operands.length && ins.operands[0].type === "imm") {
          target = ptr(ins.operands[0].value);
        } else {
          target = resolveArm64Jump(cur);
        }
      } catch (e) {
        return { addr: cur, where: where(cur), depth: d, ok: false, err: String(e) };
      }
      if (target === null || target.equals(cur)) {
        return { addr: cur, where: where(cur), depth: d, ok: false };
      }
      cur = target;
    }
    return { addr: cur, where: where(cur), depth: CONFIG.maxDepth, ok: false };
  }

  function disasm(addr, n) {
    var out = [];
    var p = addr;
    for (var i = 0; i < n; i++) {
      try {
        var ins = Instruction.parse(p);
        out.push(ins.mnemonic + " " + ins.opStr);
        p = p.add(ins.size);
      } catch (e) { break; }
    }
    return out.join(" ; ");
  }

  function scanMethod(className, mname, ov, idx) {
    var h;
    try { h = ov.handle; } catch (e) { return; }
    if (!h || h.isNull()) return;

    var flags = 0;
    try { flags = h.add(4).readU32(); } catch (e) { return; }
    var isNative = (flags & ACC_NATIVE) !== 0;
    if (CONFIG.onlyNative && !isNative) return;

    var args = [];
    try { ov.argumentTypes.forEach(function (t) { args.push(t.className); }); } catch (e) {}
    var ret = "";
    try { ret = ov.returnType.className; } catch (e) {}
    var sig = mname + "(" + args.join(", ") + ")" + (ret ? " : " + ret : "");

    var data = ptr("0");
    var quick = ptr("0");
    try { data = h.add(OFF_DATA).readPointer(); } catch (e) {}
    try { quick = h.add(OFF_QUICK).readPointer(); } catch (e) {}

    var line = className.split(".").pop() + "." + sig + "[" + idx + "]" +
      (isNative ? " native" : "") +
      "\n    data  = " + data + " -> " + where(data) +
      "\n    quick = " + quick + " -> " + where(quick);

    if (CONFIG.showBytes > 0 && !data.isNull() && isExec(data)) {
      try {
        line += "\n    bytes = " + U.hexdumpSafe(data, CONFIG.showBytes).replace(/\n/g, "\n            ");
      } catch (e) {}
    }

    var target = data;
    if (CONFIG.resolveTrampoline && !data.isNull() &&
        !Process.findModuleByAddress(data) && isExec(data)) {
      var f = follow(data);
      line += "\n    jump  = " + f.where + " (depth=" + f.depth + (f.ok ? "" : ", unresolved") + ")";
      if (!f.ok) line += "\n    code  = " + disasm(data, 4);
      target = f.addr;
    }

    U.ok(line);
    hookTarget(className, mname, target);
  }

  function hookTarget(className, mname, target) {
    if (!CONFIG.hook || target.isNull() || !isExec(target)) return;
    try {
      Interceptor.attach(target, {
        onEnter: function (a) {
          var s = [];
          for (var i = 0; i < 4; i++) {
            try { s.push(String(a[i])); } catch (e) { break; }
          }
          U.ok("[HOOK] " + className.split(".").pop() + "." + mname + " args=" + s.join(", "));
        }
      });
      U.ok("[+] attached " + where(target));
    } catch (e) {
      U.fail("attach fail " + where(target) + " : " + e);
    }
  }

  function scanClass(name) {
    var C;
    try {
      C = Java.use(name);
    } catch (e) {
      U.fail("class not found: " + name + " (" + e + ")");
      return;
    }
    U.ok("[*] " + name);

    var names = {};
    try {
      C.class.getDeclaredMethods().forEach(function (m) {
        var n = String(m.getName());
        if (CONFIG.methods.length && CONFIG.methods.indexOf(n) < 0) return;
        names[n] = true;
      });
    } catch (e) {
      U.fail("getDeclaredMethods fail: " + e);
      return;
    }

    Object.keys(names).forEach(function (n) {
      var fn;
      try { fn = C[n]; } catch (e) { return; }
      if (!fn || !fn.overloads) return;
      fn.overloads.forEach(function (ov, i) { scanMethod(name, n, ov, i); });
    });
  }

  Java.perform(function () {
    if (!CONFIG.classes.length) {
      U.ok("[i] 用法：CONFIG_OVERRIDE = { dex2c_entry: { classes: [\"com.a.B\"], methods: [\"onCreate\"], hook: false } }");
      U.ok("[i] 不需要在 native 注册时在场，attach 场景可用");
      return;
    }
    CONFIG.classes.forEach(scanClass);
    U.ok("[done]");
  });
})(this);
