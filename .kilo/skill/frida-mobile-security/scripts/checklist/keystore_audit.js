/**
 * keystore_audit.js - Android Keystore 密钥策略判定（检测清单）
 *
 * 定位：把"哪些 Keystore 配置是弱的"这一领域知识固化成可执行规则，避免每次重新推理。
 *       输出 = 事实（observed）+ 判定（rule/severity/evidence），**不绑场景**、不含
 *       MASVS/取证/合规等语义字段 —— 场景解释（标准对照、能否解数据）见
 *       references/crypto-hook.md 第六节。
 * origin: ReversecLabs/android-keystore-audit (BSD-3-Clause, F-Secure)，按本仓库规范重写。
 *
 * 规则（详见 references/crypto-hook.md 第六节）：
 *   K1  userAuthRequired=true 且 validityDuration>0            → WEAK  时间窗内可复用密钥
 *   K2  userAuthRequired=false                                 → INFO  密钥不受认证保护
 *   K3  userAuthRequired=true 且 invalidatedByBiometric=false  → WEAK  新增生物特征后旧密钥仍有效
 *   K4  userAuthRequired=true 且 unlockedDeviceRequired≠true   → INFO  锁屏态可用
 *   K5  insideSecureHardware=false                             → INFO  密钥不在安全硬件
 *   K6  origin=IMPORTED                                        → INFO  密钥由外部导入
 *   K7  AndroidKeyStore 密钥却可 getEncoded()                  → HIGH  密钥材料可导出到应用内存
 *   K8  randomizedEncryptionRequired=false                     → WEAK  调用方可控 IV
 *   K9  ECB / AES<128 / NoPadding / DIGEST_NONE                → WEAK|INFO 弱算法配置
 *
 * 加载（交互式）：
 *   frida -H 127.0.0.1:27042 -n Gadget \
 *     -l scripts/core/utils.js -l scripts/checklist/keystore_audit.js
 *
 * 配置：
 *   var CONFIG_OVERRIDE = {
 *     keystore_audit: {
 *       severityFloor: "INFO",   // "HIGH" | "WEAK" | "INFO"
 *       emitJson: true,
 *       verbose: true
 *     }
 *   };
 *
 * REPL：
 *   KeystoreAudit.findings()        // 结构化发现（数组）
 *   KeystoreAudit.summary()         // 按 severity 计数 + 按 rule 计数
 *   KeystoreAudit.selftest()        // 规则自测（17 夹具，离线可跑，不需目标 App）
 *   KeystoreAudit.evaluate(view)    // 喂单个 view，返回命中规则
 *   KeystoreAudit.reset()
 */
(function (global) {
  'use strict';

  var U = global.Utils;
  if (!U) { console.log("[-] keystore_audit requires utils.js (load it first)"); return; }

  var MODULE = "keystore_audit";
  var VERSION = "1.0.0";
  var ANDROID_KEYSTORE = "AndroidKeyStore";
  var SEV_RANK = { HIGH: 3, WEAK: 2, INFO: 1 };

  var CONFIG = U.mergeConfig(MODULE, {
    severityFloor: "INFO",
    emitJson: true,
    verbose: true
  });

  var STATE = {
    views: {},        // alias -> normalized view
    findings: [],     // 去重后的发现
    seen: {},         // rule|alias|evidence -> true
    stats: { evaluated: 0, hits: 0 },
    lastBuilderAlias: null
  };

  var PURPOSE_NAMES = [
    [1, "ENCRYPT"], [2, "DECRYPT"], [4, "SIGN"], [8, "VERIFY"],
    [16, "WRAP_KEY"], [32, "UNWRAP_KEY"], [64, "DERIVE_KEY"], [128, "AGREE_KEY"]
  ];

  function decodePurposes(p) {
    var out = [];
    try {
      for (var i = 0; i < PURPOSE_NAMES.length; i++) {
        if (p & PURPOSE_NAMES[i][0]) out.push(PURPOSE_NAMES[i][1]);
      }
    } catch (e) { }
    return out;
  }

  // ---------------- 取值解析（setter 原始串 -> 规范值） ----------------

  function parseBool(raw) {
    if (raw === true || raw === false) return raw;
    if (raw === "true") return true;
    if (raw === "false") return false;
    return null;
  }

  function parseInt10(raw) {
    if (typeof raw === "number") return raw;
    var n = parseInt(String(raw), 10);
    return isNaN(n) ? null : n;
  }

  function parseArr(raw) {
    if (raw === null || raw === undefined) return null;
    var s = String(raw);
    if (s.charAt(0) === "[" && s.charAt(s.length - 1) === "]") {
      var inner = s.substring(1, s.length - 1).trim();
      if (inner === "") return [];
      return inner.split(",").map(function (x) { return x.trim(); });
    }
    return [s];
  }

  function stringify(v) {
    if (v === null || v === undefined) return "null";
    try {
      if (typeof v !== "string" && typeof v.length === "number") {
        var out = [];
        for (var i = 0; i < v.length && i < 64; i++) {
          out.push(typeof v[i] === "number" ? ("0x" + (v[i] & 0xff).toString(16)) : String(v[i]));
        }
        return "[" + out.join(", ") + "]";
      }
    } catch (e) { }
    return String(v);
  }

  // ---------------- 规则（纯函数，可单元自测） ----------------

  function f(rule, severity, view, observed, evidence) {
    return {
      rule: rule,
      severity: severity,
      alias: view.alias === undefined ? null : view.alias,
      observed: observed,
      evidence: evidence
    };
  }

  function runRules(view) {
    var out = [];
    var v = view || {};
    var arr = function (x) { return Array.isArray(x) ? x : []; };
    var has = function (list, s) { return list.indexOf(s) >= 0; };
    var enc = arr(v.encryptionPaddings);
    var purposes = arr(v.purposes);

    // K1 时间窗复用
    if (v.userAuthRequired === true && typeof v.validityDurationSeconds === "number" && v.validityDurationSeconds > 0) {
      out.push(f("K1", "WEAK", v,
        { userAuthRequired: true, validityDurationSeconds: v.validityDurationSeconds },
        "setUserAuthenticationValidityDurationSeconds/getUserAuthenticationValidityDurationSeconds == " + v.validityDurationSeconds));
    }
    // K2 无认证要求
    if (v.userAuthRequired === false) {
      out.push(f("K2", "INFO", v,
        { userAuthRequired: false },
        "isUserAuthenticationRequired()/setUserAuthenticationRequired == false"));
    }
    // K3 新增生物特征不失效
    if (v.userAuthRequired === true && v.invalidatedByBiometricEnrollment === false) {
      out.push(f("K3", "WEAK", v,
        { userAuthRequired: true, invalidatedByBiometricEnrollment: false },
        "setInvalidatedByBiometricEnrollment/isInvalidatedByBiometricEnrollment == false"));
    }
    // K4 锁屏态可用
    if (v.userAuthRequired === true && v.unlockedDeviceRequired !== true) {
      out.push(f("K4", "INFO", v,
        { userAuthRequired: true, unlockedDeviceRequired: v.unlockedDeviceRequired === undefined ? null : v.unlockedDeviceRequired },
        "setUnlockedDeviceRequired 未置 true"));
    }
    // K5 非安全硬件
    if (v.insideSecureHardware === false) {
      out.push(f("K5", "INFO", v, { insideSecureHardware: false }, "isInsideSecureHardware() == false"));
    }
    // K6 导入密钥
    if (typeof v.origin === "string" && v.origin.indexOf("IMPORTED") === 0) {
      out.push(f("K6", "INFO", v, { origin: v.origin }, "KeyInfo.getOrigin() == IMPORTED"));
    }
    // K7 可导出（AndroidKeyStore 密钥却拿得到编码）
    if (v.fromAndroidKeyStore === true && typeof v.encodedLength === "number") {
      out.push(f("K7", "HIGH", v,
        { keyClass: v.keyClass, encodedLength: v.encodedLength },
        "AndroidKeyStore 密钥 getEncoded() != null（长度 " + v.encodedLength + "）"));
    }
    // K8 非随机 IV
    if (v.randomizedEncryptionRequired === false) {
      out.push(f("K8", "WEAK", v, { randomizedEncryptionRequired: false },
        "setRandomizedEncryptionRequired == false"));
    }
    // K9 弱算法配置
    if (v.blockMode === "ECB") {
      out.push(f("K9", "WEAK", v, { blockMode: "ECB" }, "blockMode == ECB"));
    }
    if (v.algorithm === "AES" && typeof v.keySize === "number" && v.keySize < 128) {
      out.push(f("K9", "WEAK", v, { algorithm: "AES", keySize: v.keySize }, "AES keySize == " + v.keySize + " (<128)"));
    }
    if (has(enc, "NoPadding") && (has(purposes, "ENCRYPT") || has(purposes, "DECRYPT"))) {
      out.push(f("K9", "WEAK", v, { encryptionPaddings: enc }, "加密填充 == NoPadding"));
    }
    if (v.digest === "NONE" && (has(purposes, "SIGN") || has(purposes, "VERIFY"))) {
      out.push(f("K9", "INFO", v, { digest: "NONE" }, "签名/验签 digest == NONE"));
    }

    return out;
  }

  // 规则自测夹具：want=必须命中，not=必须不命中（K4 与 K1/K3 同时命中属设计预期）
  var SELFTEST_CASES = [
    { n: "K1", v: { alias: "t", userAuthRequired: true, validityDurationSeconds: 30 }, want: ["K1"], not: [] },
    { n: "K1-neg", v: { alias: "t", userAuthRequired: true, validityDurationSeconds: -1 }, want: [], not: ["K1", "K2", "K3"] },
    { n: "K2", v: { alias: "t", userAuthRequired: false }, want: ["K2"], not: ["K1", "K3", "K4"] },
    { n: "K3", v: { alias: "t", userAuthRequired: true, invalidatedByBiometricEnrollment: false }, want: ["K3"], not: [] },
    { n: "K4", v: { alias: "t", userAuthRequired: true }, want: ["K4"], not: [] },
    { n: "K4-neg", v: { alias: "t", userAuthRequired: true, unlockedDeviceRequired: true }, want: [], not: ["K4"] },
    { n: "K5", v: { alias: "t", insideSecureHardware: false }, want: ["K5"], not: [] },
    { n: "K6", v: { alias: "t", origin: "IMPORTED(1)" }, want: ["K6"], not: [] },
    { n: "K7", v: { alias: "t", fromAndroidKeyStore: true, encodedLength: 32 }, want: ["K7"], not: [] },
    { n: "K7-neg", v: { alias: "t", fromAndroidKeyStore: false, encodedLength: 32 }, want: [], not: ["K7"] },
    { n: "K8", v: { alias: "t", randomizedEncryptionRequired: false }, want: ["K8"], not: [] },
    { n: "K9-ecb", v: { alias: "t", blockMode: "ECB" }, want: ["K9"], not: [] },
    { n: "K9-aes<128", v: { alias: "t", algorithm: "AES", keySize: 64 }, want: ["K9"], not: [] },
    { n: "K9-nopad", v: { alias: "t", encryptionPaddings: ["NoPadding"], purposes: ["ENCRYPT"] }, want: ["K9"], not: [] },
    { n: "K9-digestnone", v: { alias: "t", digest: "NONE", purposes: ["SIGN"] }, want: ["K9"], not: [] },
    { n: "K9-neg", v: { alias: "t", encryptionPaddings: ["NoPadding"], purposes: ["SIGN"] }, want: [], not: ["K9"] },
    {
      n: "strong", want: [], not: ["K1", "K2", "K3", "K4", "K5", "K6", "K7", "K8", "K9"],
      v: {
        alias: "t", userAuthRequired: true, validityDurationSeconds: -1,
        invalidatedByBiometricEnrollment: true, unlockedDeviceRequired: true,
        insideSecureHardware: true, origin: "GENERATED(0)", blockMode: "CBC",
        algorithm: "AES", keySize: 256, encryptionPaddings: ["PKCS7Padding"],
        randomizedEncryptionRequired: true, digest: "SHA-256", purposes: ["ENCRYPT"]
      }
    }
  ];

  function selftest() {
    var pass = 0, fails = [];
    for (var i = 0; i < SELFTEST_CASES.length; i++) {
      var c = SELFTEST_CASES[i];
      var got = runRules(c.v).map(function (x) { return x.rule; });
      var ok = c.want.every(function (r) { return got.indexOf(r) >= 0; }) &&
               c.not.every(function (r) { return got.indexOf(r) < 0; });
      if (ok) pass++; else fails.push(c.n + " got=[" + got.join(",") + "]");
    }
    var res = { pass: pass, fail: fails.length, total: SELFTEST_CASES.length, fails: fails };
    if (fails.length === 0) U.ok("[selftest] " + pass + "/" + SELFTEST_CASES.length + " PASS");
    else U.fail("[selftest] " + JSON.stringify(res));
    return res;
  }

  // ---------------- 视图归并 ----------------

  function ensureView(alias) {
    var a = String(alias);
    if (!STATE.views[a]) {
      STATE.views[a] = { alias: a, purposes: [], purposesDecoded: null };
    }
    return STATE.views[a];
  }

  function ingestSpecSetter(alias, method, raw) {
    var v = ensureView(alias);
    switch (method) {
      case "setUserAuthenticationRequired": v.userAuthRequired = parseBool(raw); break;
      case "setUserAuthenticationValidityDurationSeconds": v.validityDurationSeconds = parseInt10(raw); break;
      case "setInvalidatedByBiometricEnrollment": v.invalidatedByBiometricEnrollment = parseBool(raw); break;
      case "setUnlockedDeviceRequired": v.unlockedDeviceRequired = parseBool(raw); break;
      case "setIsStrongBoxBacked": v.strongBoxBacked = parseBool(raw); break;
      case "setRandomizedEncryptionRequired": v.randomizedEncryptionRequired = parseBool(raw); break;
      case "setKeySize": v.keySize = parseInt10(raw); break;
      case "setBlockModes": v.blockMode = parseArr(raw)[0]; break;
      case "setDigests": v.digest = parseArr(raw)[0]; break;
      case "setEncryptionPaddings": v.encryptionPaddings = parseArr(raw); break;
      case "setSignaturePaddings": v.signaturePaddings = parseArr(raw); break;
      default: break;
    }
    return v;
  }

  function ingestKeyInfo(alias, facts) {
    var v = ensureView(alias);
    if (typeof facts.algorithm === "string") v.algorithm = facts.algorithm;
    if (typeof facts.keySize === "number") v.keySize = facts.keySize;
    if (typeof facts.userAuthRequired === "boolean") v.userAuthRequired = facts.userAuthRequired;
    if (typeof facts.userAuthValidityDurationSeconds === "number") v.validityDurationSeconds = facts.userAuthValidityDurationSeconds;
    if (typeof facts.invalidatedByBiometricEnrollment === "boolean") v.invalidatedByBiometricEnrollment = facts.invalidatedByBiometricEnrollment;
    if (typeof facts.insideSecureHardware === "boolean") v.insideSecureHardware = facts.insideSecureHardware;
    if (typeof facts.origin === "string") v.origin = facts.origin;
    if (typeof facts.blockMode === "string") v.blockMode = facts.blockMode;
    if (typeof facts.digest === "string") v.digest = facts.digest;
    if (typeof facts.encryptionPaddings === "string") v.encryptionPaddings = parseArr(facts.encryptionPaddings);
    if (typeof facts.keyClass === "string") v.keyClass = facts.keyClass;
    if (typeof facts.encodedLength === "number") v.encodedLength = facts.encodedLength;
    v.fromAndroidKeyStore = true;
    return v;
  }

  function record(view, ruleFindings) {
    for (var i = 0; i < ruleFindings.length; i++) {
      var fd = ruleFindings[i];
      var key = fd.rule + "|" + fd.alias + "|" + fd.evidence;
      if (STATE.seen[key]) continue;
      STATE.seen[key] = true;
      STATE.findings.push(fd);
      STATE.stats.hits++;
      var line = "[" + fd.severity + "] " + fd.rule + " alias=" + fd.alias + " :: " + fd.evidence;
      if (fd.severity === "HIGH") U.alert(line); else U.ok(line);
      if (CONFIG.emitJson) { try { U.sendJson(MODULE, { finding: fd }); } catch (e) { } }
    }
  }

  function evaluateAndRecord(view) {
    STATE.stats.evaluated++;
    record(view, runRules(view));
  }

  // ---------------- 密钥属性读取（自带，不依赖 monitor） ----------------

  function isAndroidKeyStoreKey(key) {
    try {
      if (key === null) return false;
      var cn = key.$className || "";
      if (cn.indexOf("AndroidKeyStore") >= 0) return true;
      return key.getFormat() === null;
    } catch (e) { return false; }
  }

  // KeyStore.getEntry 返回 Entry，取出内层 Key
  function extractKey(obj) {
    if (obj === null) return null;
    try { if (obj.getSecretKey) { var sk = obj.getSecretKey(); if (sk !== null) return sk; } } catch (e) { }
    try { if (obj.getPrivateKey) { var pk = obj.getPrivateKey(); if (pk !== null) return pk; } } catch (e) { }
    return obj;
  }

  var KEYINFO_GETTERS = [
    ["algorithm", "getKeyAlgorithm"], ["keySize", "getKeySize"], ["origin", "getOrigin"],
    ["insideSecureHardware", "isInsideSecureHardware"],
    ["userAuthRequired", "isUserAuthenticationRequired"],
    ["userAuthValidityDurationSeconds", "getUserAuthenticationValidityDurationSeconds"],
    ["invalidatedByBiometricEnrollment", "isInvalidatedByBiometricEnrollment"],
    ["blockMode", "getBlockMode"], ["digest", "getDigest"],
    ["encryptionPaddings", "getEncryptionPaddings"], ["signaturePaddings", "getSignaturePaddings"]
  ];

  function readKeyInfo(key) {
    var algo = null;
    try { algo = key.getAlgorithm(); } catch (e) { return null; }
    var KI = Java.use("android.security.keystore.KeyInfo");
    var out = null;
    try {
      var skf = Java.use("javax.crypto.SecretKeyFactory").getInstance(algo, ANDROID_KEYSTORE);
      out = Java.cast(skf.getKeySpec(key, KI.class), KI);
    } catch (e) { }
    if (out === null) {
      try {
        var kf = Java.use("java.security.KeyFactory").getInstance(algo, ANDROID_KEYSTORE);
        out = Java.cast(kf.getKeySpec(key, KI.class), KI);
      } catch (e) { return null; }
    }
    var facts = {};
    for (var i = 0; i < KEYINFO_GETTERS.length; i++) {
      var name = KEYINFO_GETTERS[i][0], fn = KEYINFO_GETTERS[i][1];
      try {
        var val = out[fn]();
        if (name === "origin") {
          var names = { 0: "GENERATED", 1: "IMPORTED", 2: "UNKNOWN" };
          facts[name] = names[val] !== undefined ? (names[val] + "(" + val + ")") : val;
        } else if (typeof val === "object" && val !== null && typeof val.length === "number") {
          facts[name] = stringify(val);
        } else {
          facts[name] = val;
        }
      } catch (e) { }
    }
    return facts;
  }

  function ingestKey(key, alias) {
    if (key === null || alias === null || alias === undefined) return;
    var facts = { keyClass: key.$className };
    try {
      var enc = key.getEncoded();
      if (enc !== null) facts.encodedLength = enc.length;
    } catch (e) { }
    facts.fromAndroidKeyStore = isAndroidKeyStoreKey(key);
    var ki = readKeyInfo(key);
    if (ki) { for (var k in ki) { if (ki.hasOwnProperty(k)) facts[k] = ki[k]; } }
    evaluateAndRecord(ingestKeyInfo(alias, facts));
  }

  // ---------------- hooks ----------------

  var BUILDER_SETTERS = [
    "setUserAuthenticationRequired", "setUserAuthenticationValidityDurationSeconds",
    "setInvalidatedByBiometricEnrollment", "setUnlockedDeviceRequired", "setIsStrongBoxBacked",
    "setRandomizedEncryptionRequired", "setKeySize", "setBlockModes", "setDigests",
    "setEncryptionPaddings", "setSignaturePaddings"
  ];

  function install() {
    var B = null;
    try { B = Java.use("android.security.keystore.KeyGenParameterSpec$Builder"); } catch (e) {
      U.fail("[keygen] KeyGenParameterSpec$Builder 不可用: " + e);
    }
    if (B !== null) {
      B.$init.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var args = [].slice.call(arguments);
          if (args.length >= 1) {
            var alias = String(args[0]);
            STATE.lastBuilderAlias = alias;
            var v = ensureView(alias);
            if (args.length >= 2) {
              v.purposesRaw = args[1];
              v.purposes = decodePurposes(args[1]);
            }
          }
          return ov.apply(this, args);
        };
      });
      BUILDER_SETTERS.forEach(function (m) {
        if (!B[m]) return;
        B[m].overloads.forEach(function (ov) {
          ov.implementation = function () {
            var args = [].slice.call(arguments);
            var alias = STATE.lastBuilderAlias;
            if (alias) {
              var raw = args.length === 1 ? stringify(args[0]) : stringify(args);
              evaluateAndRecord(ingestSpecSetter(alias, m, raw));
            }
            return ov.apply(this, args);
          };
        });
      });
    }

    try {
      var KS = Java.use("java.security.KeyStore");
      ["getKey", "getEntry"].forEach(function (m) {
        if (!KS[m]) return;
        KS[m].overloads.forEach(function (ov) {
          ov.implementation = function () {
            var args = [].slice.call(arguments);
            var r = ov.apply(this, args);
            if (r !== null && args.length >= 1) ingestKey(extractKey(r), args[0]);
            return r;
          };
        });
      });
    } catch (e) { U.fail("[keystore] KeyStore 不可用: " + e); }

    try {
      var KG = Java.use("javax.crypto.KeyGenerator");
      if (KG.generateKey) {
        KG.generateKey.overloads.forEach(function (ov) {
          ov.implementation = function () {
            var r = ov.apply(this, arguments);
            if (r !== null && STATE.lastBuilderAlias) ingestKey(r, STATE.lastBuilderAlias);
            return r;
          };
        });
      }
    } catch (e) { }
  }

  // ---------------- 安装 + REPL ----------------

  Java.perform(function () {
    U.ok("=== " + MODULE + " v" + VERSION + " ===");
    U.ok("config: severityFloor=" + CONFIG.severityFloor + " emitJson=" + CONFIG.emitJson);
    install();
    U.ok("[done] 规则 K1-K9 已就绪；判定输出 = 事实 + 规则，不含场景字段");

    global.KeystoreAudit = {
      status: function () {
        return {
          version: VERSION,
          config: { severityFloor: CONFIG.severityFloor, emitJson: CONFIG.emitJson },
          stats: STATE.stats,
          aliases: Object.keys(STATE.views).length,
          findingCount: STATE.findings.length
        };
      },
      findings: function () {
        var floor = SEV_RANK[CONFIG.severityFloor] || 1;
        return STATE.findings.filter(function (fd) { return SEV_RANK[fd.severity] >= floor; });
      },
      summary: function () {
        var bySev = { HIGH: 0, WEAK: 0, INFO: 0 }, byRule = {};
        for (var i = 0; i < STATE.findings.length; i++) {
          var fd = STATE.findings[i];
          bySev[fd.severity] = (bySev[fd.severity] || 0) + 1;
          byRule[fd.rule] = (byRule[fd.rule] || 0) + 1;
        }
        return { bySeverity: bySev, byRule: byRule, total: STATE.findings.length };
      },
      evaluate: function (view) { return runRules(view); },
      selftest: selftest,
      views: function () { return STATE.views; },
      reset: function () {
        STATE.views = {}; STATE.findings = []; STATE.seen = {};
        STATE.stats = { evaluated: 0, hits: 0 };
        return "reset";
      }
    };
  });
})(this);
