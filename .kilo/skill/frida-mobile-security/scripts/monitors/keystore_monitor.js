/**
 * keystore_monitor.js - Android Keystore 观测（纯事实，不做判定）
 *
 * 定位：通用观测原语。采集 Android Keystore 的**全部可获得事实**（密钥清单 / 创建策略 /
 *       密钥操作），不按场景裁剪、不做安全性判定 —— 用途与解释由使用者决定。
 * origin: ReversecLabs/android-keystore-audit (BSD-3-Clause, F-Secure)，按本仓库规范重写。
 *
 * 覆盖：
 *   - java.security.KeyStore：getInstance / getKey / getEntry / setEntry / setKeyEntry /
 *     getCertificate[Chain] / load / store
 *   - javax.crypto.KeyGenerator：getInstance / init / generateKey
 *   - android.security.keystore.KeyGenParameterSpec$Builder：构造 + 全部 set*（原样记录）
 *   - android.security.keystore.KeyInfo：全部 getter（API 版本差异自动跳过）
 *   - javax.crypto.SecretKeyFactory.getKeySpec（读已存在 / 导入密钥属性的唯一途径）
 *   - javax.crypto.Cipher.init / java.security.Signature.initSign|initVerify（key alias ↔ 操作）
 *
 * 加载（交互式）：
 *   frida -H 127.0.0.1:27042 -n Gadget \
 *     -l scripts/core/utils.js -l scripts/monitors/keystore_monitor.js
 *
 * 配置：
 *   var CONFIG_OVERRIDE = {
 *     keystore_monitor: {
 *       verbose: true,
 *       apis: ["keystore", "keygen", "keyinfo", "cipher"],
 *       filterAlias: [],        // 正则数组；非空时只记录匹配的 alias
 *       dumpEncoded: false,     // true = 额外 dump 可导出密钥的编码（含密钥材料，谨慎）
 *       maxEvents: 2000,        // 事件环形缓冲上限
 *       logBacktrace: false
 *     }
 *   };
 *
 * REPL：
 *   KeystoreMonitor.status()   // 配置 + 命中统计 + 已 hook 点
 *   KeystoreMonitor.keys()     // 密钥清单：alias -> 全量事实
 *   KeystoreMonitor.events()   // 原始事件流
 *   KeystoreMonitor.reset()    // 清空 keys/events/计数
 */
(function (global) {
  'use strict';

  var U = global.Utils;
  if (!U) { console.log("[-] keystore_monitor requires utils.js (load it first)"); return; }

  var MODULE = "keystore_monitor";
  var VERSION = "1.0.0";
  var ANDROID_KEYSTORE = "AndroidKeyStore";

  var CONFIG = U.mergeConfig(MODULE, {
    verbose: true,
    apis: ["keystore", "keygen", "keyinfo", "cipher"],
    filterAlias: [],
    dumpEncoded: false,
    maxEvents: 2000,
    logBacktrace: false
  });

  var STATE = {
    keys: {},          // alias -> facts
    events: [],
    hooked: {},
    stats: { spec: 0, keyinfo: 0, op: 0 },
    lastBuilderAlias: null,
    spec: {}           // alias -> { alias, purposes, setters: { name: rawValue } }
  };

  var PURPOSE_NAMES = [
    [1, "ENCRYPT"], [2, "DECRYPT"], [4, "SIGN"], [8, "VERIFY"],
    [16, "WRAP_KEY"], [32, "UNWRAP_KEY"], [64, "DERIVE_KEY"], [128, "AGREE_KEY"]
  ];
  var ORIGIN_NAMES = { 0: "GENERATED", 1: "IMPORTED", 2: "UNKNOWN" };

  // ---------------- 基础工具 ----------------

  function enabled(api) { return CONFIG.apis.indexOf(api) >= 0; }

  function decodePurposes(p) {
    try {
      var out = [];
      for (var i = 0; i < PURPOSE_NAMES.length; i++) {
        if (p & PURPOSE_NAMES[i][0]) out.push(PURPOSE_NAMES[i][1]);
      }
      return "0x" + (p >>> 0).toString(16) + (out.length ? " (" + out.join("|") + ")" : "");
    } catch (e) { return String(p); }
  }

  function stringify(v) {
    if (v === null || v === undefined) return "null";
    try {
      if (typeof v !== "string" && typeof v.length === "number") {
        var out = [];
        for (var i = 0; i < v.length && i < 64; i++) {
          out.push(typeof v[i] === "number" ? ("0x" + (v[i] & 0xff).toString(16)) : String(v[i]));
        }
        return "[" + out.join(", ") + "]" + (v.length > 64 ? "(" + v.length + ")" : "");
      }
    } catch (e) { }
    return String(v);
  }

  function dateStr(d) {
    try { return d === null ? "null" : d.toString(); } catch (e) { return "?"; }
  }

  function aliasAllowed(alias) {
    if (!CONFIG.filterAlias || CONFIG.filterAlias.length === 0) return true;
    var pats = U.compilePatterns(CONFIG.filterAlias);
    return U.matchesAnyPattern(String(alias), pats);
  }

  function emit(ev, data) {
    var rec = { ev: ev, ts: U.timestamp() };
    for (var k in data) { if (data.hasOwnProperty(k)) rec[k] = data[k]; }
    STATE.events.push(rec);
    if (STATE.events.length > CONFIG.maxEvents) STATE.events.shift();
    try { U.sendJson(MODULE, rec); } catch (e) { }
    return rec;
  }

  function fact(alias, patch) {
    if (!alias) return null;
    var a = String(alias);
    if (!STATE.keys[a]) STATE.keys[a] = { alias: a, sources: [] };
    var rec = STATE.keys[a];
    for (var k in patch) { if (patch.hasOwnProperty(k)) rec[k] = patch[k]; }
    if (patch && patch.source && rec.sources.indexOf(patch.source) < 0) rec.sources.push(patch.source);
    return rec;
  }

  // ---------------- 密钥属性读取 ----------------

  function isAndroidKeyStoreKey(key) {
    try {
      if (key === null) return false;
      var cn = key.$className || "";
      if (cn.indexOf("AndroidKeyStore") >= 0) return true;
      return key.getFormat() === null;   // AndroidKeyStore 密钥不可编码
    } catch (e) { return false; }
  }

  // KeyStore.getEntry 返回 Entry（PrivateKeyEntry/SecretKeyEntry），取出内层 Key
  function extractKey(obj) {
    if (obj === null) return null;
    try { if (obj.getSecretKey) { var sk = obj.getSecretKey(); if (sk !== null) return sk; } } catch (e) { }
    try { if (obj.getPrivateKey) { var pk = obj.getPrivateKey(); if (pk !== null) return pk; } } catch (e) { }
    return obj;
  }

  var KEYINFO_GETTERS = [
    ["algorithm", "getKeyAlgorithm"],
    ["keySize", "getKeySize"],
    ["origin", "getOrigin"],
    ["insideSecureHardware", "isInsideSecureHardware"],
    ["userAuthRequired", "isUserAuthenticationRequired"],
    ["userAuthValidityDurationSeconds", "getUserAuthenticationValidityDurationSeconds"],
    ["userAuthEnforcedBySecureHardware", "isUserAuthenticationRequirementEnforcedBySecureHardware"],
    ["invalidatedByBiometricEnrollment", "isInvalidatedByBiometricEnrollment"],
    ["trustedUserPresenceRequired", "isTrustedUserPresenceRequired"],
    ["userAuthValidWhileOnBody", "isUserAuthenticationValidWhileOnBody"],
    ["blockMode", "getBlockMode"],
    ["digest", "getDigest"],
    ["encryptionPaddings", "getEncryptionPaddings"],
    ["signaturePaddings", "getSignaturePaddings"],
    ["keyValidityStart", "getKeyValidityStart"],
    ["keyValidityForConsumptionEnd", "getKeyValidityForConsumptionEnd"],
    ["keyValidityForOriginationEnd", "getKeyValidityForOriginationEnd"]
  ];

  function dumpKeyInfo(ki) {
    var out = {};
    for (var i = 0; i < KEYINFO_GETTERS.length; i++) {
      var name = KEYINFO_GETTERS[i][0], fn = KEYINFO_GETTERS[i][1];
      try {
        var v = ki[fn]();
        if (name === "origin") out[name] = ORIGIN_NAMES[v] !== undefined ? (ORIGIN_NAMES[v] + "(" + v + ")") : v;
        else if (name.indexOf("keyValidity") === 0) out[name] = dateStr(v);
        else out[name] = (v === null ? null : (typeof v === "object" && typeof v.length === "number" ? stringify(v) : v));
      } catch (e) { /* 该 API level 不存在，跳过 */ }
    }
    return out;
  }

  function readKeyInfo(key) {
    var algo = null;
    try { algo = key.getAlgorithm(); } catch (e) { return null; }

    try {
      var SKF = Java.use("javax.crypto.SecretKeyFactory");
      var skf = SKF.getInstance(algo, ANDROID_KEYSTORE);
      var KI = Java.use("android.security.keystore.KeyInfo");
      return dumpKeyInfo(Java.cast(skf.getKeySpec(key, KI.class), KI));
    } catch (e) { }

    try {
      var KF = Java.use("java.security.KeyFactory");
      var kf = KF.getInstance(algo, ANDROID_KEYSTORE);
      var KI2 = Java.use("android.security.keystore.KeyInfo");
      return dumpKeyInfo(Java.cast(kf.getKeySpec(key, KI2.class), KI2));
    } catch (e) { }

    return null;
  }

  function describeKey(key, alias) {
    var facts = {
      source: "keyinfo",
      alias: alias === null || alias === undefined ? null : String(alias),
      keyClass: null, algorithm: null, format: null,
      encodedLength: null, encoded: null
    };
    try { facts.keyClass = key.$className; } catch (e) { }
    try { facts.algorithm = key.getAlgorithm(); } catch (e) { }
    try { facts.format = key.getFormat(); } catch (e) { }
    try {
      var enc = key.getEncoded();
      if (enc !== null) {
        facts.encodedLength = enc.length;
        if (CONFIG.dumpEncoded) facts.encoded = U.bytesToHex(enc);
      }
    } catch (e) { }

    var ki = readKeyInfo(key);
    if (ki) {
      for (var k in ki) { if (ki.hasOwnProperty(k)) facts[k] = ki[k]; }
      STATE.stats.keyinfo++;
    }
    return facts;
  }

  // ---------------- KeyGenParameterSpec$Builder ----------------

  var BUILDER_SETTERS = [
    "setUserAuthenticationRequired", "setUserAuthenticationValidityDurationSeconds",
    "setInvalidatedByBiometricEnrollment", "setUnlockedDeviceRequired", "setIsStrongBoxBacked",
    "setRandomizedEncryptionRequired", "setUserConfirmationRequired", "setUserPresenceRequired",
    "setKeySize", "setDigests", "setBlockModes", "setEncryptionPaddings", "setSignaturePaddings",
    "setAlgorithmParameterSpec", "setKeyValidityStart", "setKeyValidityEnd",
    "setKeyValidityForConsumptionEnd", "setKeyValidityForOriginationEnd", "setAttestationChallenge"
  ];

  function hookBuilder() {
    var B;
    try { B = Java.use("android.security.keystore.KeyGenParameterSpec$Builder"); } catch (e) {
      U.fail("[keygen] KeyGenParameterSpec$Builder 不可用: " + e); return;
    }

    B.$init.overloads.forEach(function (ov) {
      ov.implementation = function () {
        var args = [].slice.call(arguments);
        // Builder(String keystoreAlias, int purposes[, AlgorithmParameterSpec])
        var alias = args.length >= 1 ? String(args[0]) : null;
        var purposes = args.length >= 2 ? args[1] : null;
        STATE.lastBuilderAlias = alias;
        if (alias && aliasAllowed(alias)) {
          STATE.spec[alias] = { alias: alias, purposes: purposes, purposesDecoded: decodePurposes(purposes), setters: {} };
          STATE.stats.spec++;
          emit("spec-new", { alias: alias, purposes: purposes, purposesDecoded: decodePurposes(purposes) });
          if (CONFIG.verbose) U.ok("[keygen] Builder alias=" + alias + " purposes=" + decodePurposes(purposes));
        }
        return ov.apply(this, args);
      };
    });
    STATE.hooked["KeyGenParameterSpec$Builder"] = B.$init.overloads.length;

    BUILDER_SETTERS.forEach(function (m) {
      if (!B[m]) return;
      B[m].overloads.forEach(function (ov) {
        ov.implementation = function () {
          var args = [].slice.call(arguments);
          var raw = args.length === 1 ? stringify(args[0]) : stringify(args);
          var alias = STATE.lastBuilderAlias;
          var rec = alias && STATE.spec[alias];
          if (rec) {
            rec.setters[m] = args.length === 1 ? raw : stringify(args);
            rec.setters[m + "_raw"] = args.length === 1 ? args[0] : undefined;
          }
          emit("spec-set", { alias: alias, method: m, value: raw });
          if (CONFIG.verbose) U.ok("[keygen] " + alias + "." + m + "(" + raw + ")");
          return ov.apply(this, args);
        };
      });
    });
  }

  // ---------------- KeyStore / KeyGenerator / 操作 ----------------

  function hookKeyStore() {
    var KS;
    try { KS = Java.use("java.security.KeyStore"); } catch (e) { U.fail("[keystore] 不可用: " + e); return; }

    function hookGet(method, aliasArgIdx) {
      if (!KS[method]) return;
      KS[method].overloads.forEach(function (ov) {
        ov.implementation = function () {
          var args = [].slice.call(arguments);
          var alias = args.length > aliasArgIdx ? args[aliasArgIdx] : null;
          var r = ov.apply(this, args);
          if (r !== null && aliasAllowed(alias)) {
            var facts = describeKey(extractKey(r), alias);
            var rec = fact(alias, facts);
            emit("keystore-get", { method: method, alias: String(alias), facts: facts });
            if (CONFIG.verbose) U.ok("[keystore] " + method + "(" + alias + ") -> " + facts.algorithm +
              " class=" + facts.keyClass + " enc=" + facts.encodedLength);
          }
          return r;
        };
      });
    }

    hookGet("getKey", 0);
    hookGet("getEntry", 0);

    ["getInstance"].forEach(function (m) {
      if (!KS[m]) return;
      KS[m].overloads.forEach(function (ov) {
        ov.implementation = function () {
          var args = [].slice.call(arguments);
          emit("keystore-instance", { type: String(args[0]), provider: args.length > 1 ? String(args[1]) : null });
          if (CONFIG.verbose) U.ok("[keystore] getInstance(" + args.map(String).join(", ") + ")");
          return ov.apply(this, args);
        };
      });
    });

    [["setEntry", 0], ["setKeyEntry", 0], ["getCertificate", 0], ["getCertificateChain", 0]].forEach(function (p) {
      var m = p[0];
      if (!KS[m]) return;
      KS[m].overloads.forEach(function (ov) {
        ov.implementation = function () {
          var args = [].slice.call(arguments);
          emit("keystore-call", { method: m, alias: args.length ? String(args[0]) : null });
          if (CONFIG.verbose) U.ok("[keystore] " + m + "(" + String(args[0]) + ")");
          return ov.apply(this, args);
        };
      });
    });

    ["getKey", "getEntry", "getInstance", "setEntry", "setKeyEntry", "getCertificate", "getCertificateChain"].forEach(function (m) {
      if (KS[m]) STATE.hooked["KeyStore." + m] = KS[m].overloads.length;
    });
  }

  function hookKeyGenerator() {
    var KG;
    try { KG = Java.use("javax.crypto.KeyGenerator"); } catch (e) { return; }

    if (KG.generateKey) {
      KG.generateKey.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var r = ov.apply(this, arguments);
          var alias = STATE.lastBuilderAlias;
          if (r !== null) {
            var facts = describeKey(r, alias);
            if (alias && STATE.spec[alias]) {
              facts.setters = STATE.spec[alias].setters;
              facts.purposesDecoded = STATE.spec[alias].purposesDecoded;
              facts.source = "spec+keyinfo";
            }
            if (alias) fact(alias, facts);
            emit("generateKey", { alias: alias, facts: facts });
            if (CONFIG.verbose) U.ok("[keygen] generateKey -> " + facts.algorithm + " alias=" + alias +
              " insideSecureHW=" + facts.insideSecureHardware);
          }
          return r;
        };
      });
    }

    if (KG.init) {
      KG.init.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var args = [].slice.call(arguments);
          try {
            if (args[0] && String(args[0].$className).indexOf("KeyGenParameterSpec") >= 0) {
              var spec = Java.cast(args[0], Java.use("android.security.keystore.KeyGenParameterSpec"));
              var alias = null;
              try { alias = spec.getKeystoreAlias(); } catch (e) { }
              if (alias) STATE.lastBuilderAlias = String(alias);
              emit("keygen-init", { alias: alias === null ? null : String(alias) });
            }
          } catch (e) { }
          return ov.apply(this, args);
        };
      });
    }

    if (KG.generateKey) STATE.hooked["KeyGenerator.generateKey"] = KG.generateKey.overloads.length;
    if (KG.init) STATE.hooked["KeyGenerator.init"] = KG.init.overloads.length;
    if (KG.getInstance) STATE.hooked["KeyGenerator.getInstance"] = KG.getInstance.overloads.length;
  }

  function hookOps() {
    try {
      var Cipher = Java.use("javax.crypto.Cipher");
      Cipher.init.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var args = [].slice.call(arguments);
          var key = null;
          for (var i = 0; i < args.length; i++) {
            try { if (args[i] && args[i].getAlgorithm && args[i].$className) { key = args[i]; break; } } catch (e) { }
          }
          var keyAlgo = null, keyClass = null, aks = false;
          try { if (key) { keyAlgo = key.getAlgorithm(); keyClass = key.$className; aks = isAndroidKeyStoreKey(key); } } catch (e) { }
          STATE.stats.op++;
          emit("cipher-init", { opmode: args[0], keyAlgorithm: keyAlgo, keyClass: keyClass, androidKeyStore: aks });
          if (CONFIG.verbose) U.ok("[cipher] init opmode=" + args[0] + " key=" + keyAlgo +
            (aks ? " (AndroidKeyStore)" : "") + " class=" + keyClass);
          return ov.apply(this, args);
        };
      });
      STATE.hooked["Cipher.init"] = Cipher.init.overloads.length;
    } catch (e) { U.fail("[cipher] Cipher.init 不可用: " + e); }

    try {
      var Sig = Java.use("java.security.Signature");
      ["initSign", "initVerify"].forEach(function (m) {
        if (!Sig[m]) return;
        Sig[m].overloads.forEach(function (ov) {
          ov.implementation = function () {
            var args = [].slice.call(arguments);
            var keyAlgo = null, aks = false;
            try { keyAlgo = args[0].getAlgorithm(); aks = isAndroidKeyStoreKey(args[0]); } catch (e) { }
            STATE.stats.op++;
            emit("signature-init", { method: m, keyAlgorithm: keyAlgo, androidKeyStore: aks });
            if (CONFIG.verbose) U.ok("[signature] " + m + " key=" + keyAlgo + (aks ? " (AndroidKeyStore)" : ""));
            return ov.apply(this, args);
          };
        });
      });
      STATE.hooked["Signature.initSign/initVerify"] = 2;
    } catch (e) { }
  }

  // ---------------- 安装 ----------------

  Java.perform(function () {
    U.ok("=== " + MODULE + " v" + VERSION + " ===");
    U.ok("config: apis=[" + CONFIG.apis.join(",") + "] verbose=" + CONFIG.verbose +
      " filterAlias=[" + CONFIG.filterAlias.join(",") + "] dumpEncoded=" + CONFIG.dumpEncoded);

    if (enabled("keystore")) hookKeyStore();
    if (enabled("keygen")) { hookBuilder(); hookKeyGenerator(); }
    if (enabled("keyinfo")) { /* readKeyInfo 由 keygen/keystore 路径按需调用 */ }
    if (enabled("cipher")) hookOps();

    U.ok("[done] hooked: " + JSON.stringify(STATE.hooked));
    U.ok("提示：本模块只采集事实，不做判定；安全性判定用 checklist/keystore_audit.js");

    global.KeystoreMonitor = {
      status: function () {
        return {
          version: VERSION,
          config: { apis: CONFIG.apis, filterAlias: CONFIG.filterAlias, dumpEncoded: CONFIG.dumpEncoded },
          hooked: STATE.hooked,
          stats: STATE.stats,
          keyCount: Object.keys(STATE.keys).length,
          eventCount: STATE.events.length
        };
      },
      keys: function () { return STATE.keys; },
      events: function () { return STATE.events; },
      reset: function () {
        STATE.keys = {}; STATE.events = []; STATE.spec = {};
        STATE.stats = { spec: 0, keyinfo: 0, op: 0 };
        return "reset";
      }
    };
  });
})(this);
