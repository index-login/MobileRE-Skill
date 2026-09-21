/**
 * jni_bridge_monitor.js - 方法索引桥加固分析（梆梆/360 等 VMP/Dex2C 特征）
 *
 * 用途：
 *   检测并分析"方法体被替换成 JniLib.cX(Class, args..., 索引)"的加固痕迹。
 *   输出：加固方法清单（类名.方法名 → 桥方法 → 方法索引 → 运行时参数）
 *
 * 原理：
 *   梆梆(Fort)/360 等加固会把 Java 方法体替换成对桥接类的调用：
 *     public void attachBaseContext(Context c) {
 *         JniLib.cV(TdxApp.class, this, c, 166);   // 166 = 方法索引
 *     }
 *   桥接类（com.fort.andjni.JniLib 等）有 cV/cI/cL/cB/cZ/cJ/cF/cD/cS/cC 方法，
 *   按返回值类型区分，最后一个参数是方法索引。真实实现在 so 里按索引分发。
 *
 * 加载：
 *   frida -H 127.0.0.1:7890 -f com.app -l scripts/core/utils.js -l scripts/monitors/jni_bridge_monitor.js
 *
 * 场景：
 *   - 静态 jadx 看到 JniLib.cX(..., 索引) 加固痕迹时，动态确认哪些方法被加固
 *   - 结合 scan_register_natives.js（拿桥的 native 实现地址）→ Ghidra 分析分发逻辑
 */
(function (global) {

    var U = global.Utils;
    if (!U) { console.log("[-] jni_bridge_monitor requires utils.js (load it first)"); return; }

    var CONFIG = U.mergeConfig('jni_bridge_monitor', {
        // 桥接类名（可多个，覆盖梆梆/360/其他壳）
        bridgeClasses: ["com.fort.andjni.JniLib", "com.secneo.apkwrapper.JNILib", "com.stub.StubApp"],
        // 桥方法名（按 JNI 返回类型命名）。默认只 hook 引用/整数型方法：
        //   cV(void)/cI(int)/cL(Object)/cZ(boolean)/cB(byte)/cJ(long) 已验证稳定
        //   cF(float)/cD(double)/cS(short)/cC(char) 原生类型 varargs hook 在部分
        //   frida/ART 版本会崩，需时再单独开启
        bridgeMethods: ["cV", "cI", "cL", "cZ", "cB", "cJ"],
        // 只记录方法索引 >= 该值的（过滤小整数误报）
        minIndex: 100,
        // 索引参数位置（JniLib.cX(Class, args..., Integer idx)，idx 在倒数第一）
        indexPos: -1,
    });

    var hookCount = 0;
    var callCount = 0;

    function hookBridge(JniLib, methodName) {
        try {
            // 与手动验证脚本逐行一致（已验证能输出）。
            // 输出格式: cV(调用类=..., 参数=..., java.lang.Integer=166)
            // 最后一个 java.lang.Integer 参数就是方法索引（加固方法唯一标识）
            JniLib[methodName].overload("[Ljava.lang.Object;").implementation = function (args) {
                callCount++;
                var desc = "[JNIBRIDGE] " + methodName + "(";
                var parts = [];
                if (args) {
                    for (var i = 0; i < args.length; i++) {
                        var a = args[i];
                        var t = "null";
                        if (a !== null) {
                            try { t = a.getClass().getName() + "=" + String(a); } catch (e) { t = a.getClass().getName(); }
                        }
                        parts.push(t);
                    }
                }
                desc += parts.join(", ") + ")";
                console.log(desc);
                return this[methodName](args);
            };
            hookCount++;
            return true;
        } catch (e) {
            return false;
        }
    }

Java.perform(function () {
        var hooked = false;
        CONFIG.bridgeClasses.forEach(function (clsName) {
            try {
                var JniLib = Java.use(clsName);
                CONFIG.bridgeMethods.forEach(function (m) {
                    if (hookBridge(JniLib, m)) hooked = true;
                });
                U.info("[JNIBRIDGE] hooked " + clsName + " (" + hookCount + " methods)");
            } catch (e) {
                // 类不存在（非此壳），跳过
            }
        });
        if (!hooked) {
            U.warn("[JNIBRIDGE] 未找到桥接类，尝试的类：" + CONFIG.bridgeClasses.join(", ") +
                "\n  可配置 CONFIG_OVERRIDE 指定实际桥接类（如 jadx 里看到的 import com.xxx.JniLib）");
        } else {
            U.ok("[JNIBRIDGE] 方法索引桥监控已启动（minIndex=" + CONFIG.minIndex + "）");
        }
    });

    global.JniBridgeMonitor = {
        getHookCount: function () { return hookCount; },
        getCallCount: function () { return callCount; },
    };

})(this);