package x;

import android.os.Handler;
import android.os.Looper;

/**
 * 最小加载桩：只在 App 主线程上执行 System.load。
 * 用途：targetSdk >= 35 时 Runtime.load(String, ClassLoader) 被系统禁用，
 * native 侧无法直接走 Java 加载；用 DexClassLoader 加载本类后调用，
 * System.load 的 caller class 属于 App classloader 命名空间。
 */
public final class L {
    public static void load(final String path) {
        new Handler(Looper.getMainLooper()).post(new Runnable() {
            public void run() {
                try {
                    System.load(path);
                    android.util.Log.i("xL", "loaded: " + path);
                } catch (Throwable t) {
                    android.util.Log.e("xL", "load failed", t);
                }
            }
        });
    }
}
