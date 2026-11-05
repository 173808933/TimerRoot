package com.kpgc.timerroot.adb;

import android.content.Context;
import android.os.Build;

import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.concurrent.TimeUnit;

import io.github.muntashirakon.adb.AbsAdbConnectionManager;
import io.github.muntashirakon.adb.AdbStream;

/**
 * 本机 adbd 的 ADB 客户端。
 *
 * 用途：不装 Shizuku 也能拿到 shell —— 用户在开发者选项里打开「无线调试」，
 * 把配对码和端口填进来，这里用 SPAKE2 + TLS 完成配对，之后 openStream("shell:…")
 * 就是 uid 2000 的 shell，和 Shizuku 的 UserService 等价。
 *
 * 只在 App 进程里跑；真正的攻击仍然由 /data/local/tmp/timer 执行，二进制不变。
 */
public final class AdbLink extends AbsAdbConnectionManager {

    private static AdbLink instance;

    private final Context appCtx;
    private final PrivateKey key;
    private final Certificate cert;

    private AdbLink(Context ctx) throws Exception {
        appCtx = ctx.getApplicationContext();
        AdbKeyStore ks = AdbKeyStore.load(ctx);
        key = ks.key;
        cert = ks.cert;
        setApi(Build.VERSION.SDK_INT);
        setTimeout(25, TimeUnit.SECONDS);
        setHostAddress("127.0.0.1");
        setThrowOnUnauthorised(false);
    }

    public static synchronized AdbLink get(Context ctx) throws Exception {
        if (instance == null) {
            instance = new AdbLink(ctx.getApplicationContext());
        }
        return instance;
    }

    @Override
    protected PrivateKey getPrivateKey() {
        return key;
    }

    @Override
    protected Certificate getCertificate() {
        return cert;
    }

    @Override
    protected String getDeviceName() {
        return "TimerRoot";
    }

    /** 配对端口和配对码都来自「无线调试 → 使用配对码配对设备」那个弹窗。 */
    public String doPair(int port, String code) {
        try {
            boolean ok = pair("127.0.0.1", port, code);
            return ok ? "配对成功（端口 " + port + "）"
                    : "配对失败：adbd 拒绝了这次配对（码错/超时/端口不对）";
        } catch (Throwable t) {
            return "配对失败：" + t;
        }
    }

    /** 连接端口是「无线调试」主界面显示的那个（和配对端口不是一个）。 */
    /**
     * 连接只能走 mDNS：LibADB 的 connect(host,port) 是明文 TCP，
     * 而 Android 11+ 的无线调试端口是 TLS，只有 autoConnect/connectTls 会做 TLS。
     */
    public String doConnect() {
        try {
            if (connectTls(appCtx, 15000)) {
                return "已连接（无线调试 TLS，mDNS 发现）";
            }
        } catch (Throwable t) {
            return "连接失败：" + t;
        }
        return "连接失败：没发现无线调试服务（确认开发者选项里的无线调试已打开）";
    }

    public boolean ready() {
        try {
            return isConnected();
        } catch (Throwable t) {
            return false;
        }
    }

    public void drop() {
        try {
            disconnect();
        } catch (Throwable ignored) {
        }
    }

    /**
     * 跑一条 shell 命令，收全部输出。超时只影响读取，不杀远端进程 ——
     * 攻击本身是 setsid 起的，跟这条流无关。
     */
    public String exec(String cmd, int timeoutSec) {
        AdbStream stream = null;
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            stream = openStream("shell:" + cmd);
            final AdbStream s = stream;
            Thread reader = new Thread(() -> {
                byte[] buf = new byte[4096];
                try {
                    int n;
                    while ((n = s.read(buf, 0, buf.length)) > 0) {
                        out.write(buf, 0, n);
                    }
                } catch (Throwable ignored) {
                }
            });
            reader.setDaemon(true);
            reader.start();
            reader.join(Math.max(1, timeoutSec) * 1000L);
        } catch (Throwable t) {
            return "ADB_ERROR:" + t;
        } finally {
            if (stream != null) {
                try {
                    stream.close();
                } catch (Throwable ignored) {
                }
            }
        }
        try {
            return out.toString("UTF-8");
        } catch (Throwable t) {
            return "";
        }
    }
}
