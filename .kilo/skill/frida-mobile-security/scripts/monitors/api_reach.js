/**
 * api_reach.js — API 调用面 / 可达性统计（纯观测，不改行为）
 *
 * 定位：给"先定可达面，再深审可达面"提供执行工具。按**类**枚举并 hook 其全部方法，
 *       只统计调用次数与是否命中，**不读取业务语义、不修改返回值**。
 *       与专用模块协作而非替代：专用模块（crypto_monitor / native_hooker / dl_monitor …）
 *       给"是什么"，本模块给"有没有被调到"。专用模块先加载，本模块后加载即可并存。
 *
 * 覆盖：任意 Java 类的声明方法（含 private / static / native 声明）
 *       —— 典型用法是配合 .so 审计：hook `PdfiumCore` 的 `native*`，得到"哪些 JNI 真被调到"。
 *
 * 加载（交互式）：
 *   frida -H 127.0.0.1:27042 -n Gadget \
 *     -l scripts/core/utils.js -l scripts/monitors/api_reach.js \
 *     -e 'var CONFIG_OVERRIDE={api_reach:{targets:["com.shockwave.pdfium.PdfiumCore"],methodPrefix:"native"}}'
 *
 * 配置：
 *   var CONFIG_OVERRIDE = { api_reach: {
 *     targets: [],              // 必填：类名数组
 *     methodPrefix: "",         // 只 hook 该前缀的方法（如 "native"）
 *     include: [],              // 正则数组：只保留匹配的方法名（可选）
 *     exclude: [],              // 正则数组：排除匹配的方法名
 *     includeSynthetic: false,  // 是否包含 $ / access$ 合成方法
 *     logArgs: false,           // 命中时打印入参（前 maxArgs 个）
 *     maxArgs: 4,
 *     verbose: true,
 *     reportOnExit: true        // 脚本 detach 前打印一次汇总（frida_run 定时退出时有用）
 *   }};
 *
 * REPL：
 *   ApiReach.status()   // 配置 + 已 hook 方法数 + 命中/未命中数
 *   ApiReach.report()   // 打印「可达」「未命中」两张表（按方法名排序）
 *   ApiReach.hits()     // { "cls.method(sig)": count }
 *   ApiReach.missed()   // 已 hook 但 0 次调用的方法名数组
 *   ApiReach.reset()
 *
 * 用法要点：
 *   1. 一次只指定**一个入口组件**触发，记录该输入的命中集合；
 *   2. 换**多形态输入**（页数 / 书签 / 链接 / 加密 / 字体 / 表单 …）各跑一遍；
 *   3. 取并集 = 真实可达面。0 次调用的方法分两类处理：
 *      - 类里有调用方 → 只是"输入未覆盖"，必须补输入再测；
 *      - 类里没有调用方 → 才是"代码级不可达"，可判定不审。
 */
(function (global) {
  'use strict';

  var U = global.Utils;
  if (!U) { console.log("[-] api_reach requires utils.js (load it first)"); return; }

  var MODULE = "api_reach";
  var VERSION = "1.0.0";

  var CONFIG = U.mergeConfig(MODULE, {
    targets: [],
    methodPrefix: "",
    include: [],
    exclude: [],
    includeSynthetic: false,
    logArgs: false,
    maxArgs: 4,
    verbose: true,
    reportOnExit: true
  });

  var STATE = {
    hits: {},        // key -> count
    hooked: {},      // key -> true
    classes: {},     // className -> { methods: N, overloads: N, error: string|null }
    order: []        // 首次命中顺序
  };

  function L(s) { if (CONFIG.verbose) U.ok(s); }

  function fmtArg(v, i) {
    if (i >= CONFIG.maxArgs) return '…';
    try {
      if (v === null) return 'null';
      var s = String(v);
      return s.length > 60 ? s.substring(0, 60) + '…' : s;
    } catch (e) { return '?'; }
  }

  function installClass(clsName) {
    var C;
    try { C = Java.use(clsName); } catch (e) {
      STATE.classes[clsName] = { methods: 0, overloads: 0, error: String(e) };
      U.fail("[miss-class] " + clsName + " :: " + e);
      return;
    }

    var ms;
    try { ms = C.class.getDeclaredMethods(); } catch (e) {
      STATE.classes[clsName] = { methods: 0, overloads: 0, error: String(e) };
      U.fail("[miss-methods] " + clsName + " :: " + e);
      return;
    }

    var inc = U.compilePatterns(CONFIG.include);
    var exc = U.compilePatterns(CONFIG.exclude);
    var seen = {};
    var nMethods = 0, nOverloads = 0;

    for (var i = 0; i < ms.length; i++) {
      var mn;
      try { mn = String(ms[i].getName()); } catch (e) { continue; }
      if (seen[mn]) continue;
      seen[mn] = true;

      if (CONFIG.methodPrefix && mn.indexOf(CONFIG.methodPrefix) !== 0) continue;
      if (!CONFIG.includeSynthetic && (mn.indexOf('$') >= 0 || mn.indexOf('access$') === 0)) continue;
      if (inc.length && !U.matchesAnyPattern(mn, inc)) continue;
      if (exc.length && U.matchesAnyPattern(mn, exc)) continue;
      if (!C[mn] || !C[mn].overloads) continue;

      var hookedThis = false;
      C[mn].overloads.forEach(function (ov) {
        var sig;
        try {
          sig = ov.argumentTypes.map(function (t) { return t.className; }).join(',');
        } catch (e) { return; }
        var key = clsName + '.' + mn + '(' + sig + ')';
        if (STATE.hooked[key]) return;

        try {
          ov.implementation = function () {
            var a = [].slice.call(arguments);
            if (STATE.hits[key] === undefined) {
              STATE.hits[key] = 0;
              STATE.order.push(key);
              L("[hit] " + key + (CONFIG.logArgs ? "  [" + a.map(fmtArg).join(', ') + "]" : ''));
              try { U.sendJson(MODULE, { ev: 'first-hit', key: key }); } catch (e) { }
            }
            STATE.hits[key]++;
            return ov.apply(this, a);
          };
          STATE.hooked[key] = true;
          nOverloads++;
          hookedThis = true;
        } catch (e) {
          U.fail("[hook-fail] " + key + " :: " + e);
        }
      });
      if (hookedThis) nMethods++;
    }

    STATE.classes[clsName] = { methods: nMethods, overloads: nOverloads, error: null };
    U.ok("[+] " + clsName + " -> " + nMethods + " methods / " + nOverloads + " overloads hooked");
  }

  function report() {
    var hits = Object.keys(STATE.hits).sort();
    var missed = Object.keys(STATE.hooked).filter(function (k) { return STATE.hits[k] === undefined; }).sort();

    U.ok("=== 可达（" + hits.length + "）===");
    hits.forEach(function (k) { U.ok("  " + k + "  x" + STATE.hits[k]); });
    if (hits.length === 0) U.ok("  (none)");

    U.ok("=== 未命中（" + missed.length + "）===");
    missed.forEach(function (k) { U.ok("  " + k); });
    if (missed.length === 0) U.ok("  (none)");

    try {
      U.sendJson(MODULE, { ev: 'report', hits: STATE.hits, missed: missed });
    } catch (e) { }
  }

  Java.perform(function () {
    U.ok("=== " + MODULE + " v" + VERSION + " ===");
    var targets = CONFIG.targets || [];
    if (targets.length === 0) {
      U.fail("未配置 targets。示例: -e 'var CONFIG_OVERRIDE={api_reach:{targets:[\"com.foo.Bar\"],methodPrefix:\"native\"}}'");
    }
    U.ok("config: targets=[" + targets.join(", ") + "] prefix='" + CONFIG.methodPrefix +
      "' include=" + CONFIG.include.length + " exclude=" + CONFIG.exclude.length + " logArgs=" + CONFIG.logArgs);

    targets.forEach(installClass);

    global.ApiReach = {
      status: function () {
        return {
          version: VERSION,
          config: {
            targets: targets, methodPrefix: CONFIG.methodPrefix,
            logArgs: CONFIG.logArgs
          },
          classes: STATE.classes,
          hooked: Object.keys(STATE.hooked).length,
          hit: Object.keys(STATE.hits).length,
          missed: Object.keys(STATE.hooked).length - Object.keys(STATE.hits).length
        };
      },
      report: report,
      hits: function () { return STATE.hits; },
      missed: function () {
        return Object.keys(STATE.hooked).filter(function (k) { return STATE.hits[k] === undefined; }).sort();
      },
      order: function () { return STATE.order; },
      reset: function () {
        STATE.hits = {}; STATE.order = [];
        return "reset (hooks 保留，计数清零)";
      }
    };

    if (CONFIG.reportOnExit) {
      // frida CLI 退出/detach 前打印一次（best-effort）
      try {
        Script.bindWeak(global, function () { try { report(); } catch (e) { } });
      } catch (e) { }
    }
  });
})(this);
