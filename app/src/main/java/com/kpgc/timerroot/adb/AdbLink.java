package com.kpgc.timerroot.adb;

import android.content.Context;
import android.os.Build;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.PrivateKey;
import java.util.LinkedHashSet;
import java.security.cert.Certificate;
import java.util.concurrent.TimeUnit;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import io.github.muntashirakon.adb.AbsAdbConnectionManager;
import io.github.muntashirakon.adb.AdbStream;
import io.github.muntashirakon.adb.android.AdbMdns;

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

    /**
     * mDNS 报出来的配对端点。
     *
     * host 不能写死 127.0.0.1：AOSP 的 pairing server 绑 INADDR_ANY，
     * loopback 能连；但不少厂商 ROM 只绑 wlan 地址，localhost 直接拒绝。
     * 这就是「自己手机能配对、别人手机一直失败」的根因。
     */
    static final class Endpoint {
        final String host;
        final int port;

        Endpoint(String host, int port) {
            this.host = host == null ? "" : host;
            this.port = port;
        }

        @Override
        public String toString() {
            return (host.isEmpty() ? "127.0.0.1" : host) + ":" + port;
        }
    }

    /** 配对弹窗一打开就盯着，别等用户输完码才去找端口。 */
    private static volatile AdbMdns pairWatcher;
    private static volatile Endpoint pairSeen;
    private static volatile long pairSeenAt;

    public static void startPairWatcher(Context ctx) {
        stopPairWatcher();
        try {
            AdbMdns m = new AdbMdns(ctx.getApplicationContext(),
                    AdbMdns.SERVICE_TYPE_TLS_PAIRING, (addr, p) -> {
                        if (p > 0) {
                            pairSeen = new Endpoint(addr == null ? "" : addr.getHostAddress(), p);
                            pairSeenAt = System.currentTimeMillis();
                        }
                    });
            m.start();
            pairWatcher = m;
        } catch (Throwable ignored) {
        }
    }

    public static void stopPairWatcher() {
        AdbMdns m = pairWatcher;
        pairWatcher = null;
        if (m != null) {
            try {
                m.stop();
            } catch (Throwable ignored) {
            }
        }
    }

    /** 缓存超过这个时间就当没看见（配对端口每次开弹窗都会变）。 */
    private static final long PAIR_CACHE_MS = 120_000L;

    /**
     * 取配对端点：先用 watcher 的缓存，没有再现场找 seconds 秒。
     * 返回 null 表示没发现服务。
     */
    static Endpoint discoverPairing(Context ctx, int seconds) {
        Endpoint c = pairSeen;
        if (c != null && System.currentTimeMillis() - pairSeenAt < PAIR_CACHE_MS) {
            return c;
        }
        pairSeen = null;
        final CountDownLatch latch = new CountDownLatch(1);
        try {
            AdbMdns m = new AdbMdns(ctx.getApplicationContext(),
                    AdbMdns.SERVICE_TYPE_TLS_PAIRING, (addr, p) -> {
                        if (p > 0) {
                            pairSeen = new Endpoint(addr == null ? "" : addr.getHostAddress(), p);
                            pairSeenAt = System.currentTimeMillis();
                            latch.countDown();
                        }
                    });
            m.start();
            latch.await(seconds, TimeUnit.SECONDS);
            m.stop();
        } catch (Throwable ignored) {
        }
        return pairSeen;
    }

    /** 3 秒内能建立 TCP 就算可达；用来把不可达的候选先筛掉，省得干等。 */
    private static boolean reachable(String host, int port, int ms) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), ms);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /** 配对端口和配对码都来自「无线调试 → 使用配对码配对设备」那个弹窗。 */
    public String doPair(int port, String code) {
        return doPair(new Endpoint("", port), code);
    }

    public String doPair(Endpoint ep, String code) {
        String pre = selfTest(appCtx);

        // 候选：loopback 优先（快、多数 ROM 都通），再补 mDNS 报的地址。
        // IPv6 链路本地地址没有 scope id 连不上，直接跳过。
        LinkedHashSet<String> hosts = new LinkedHashSet<>();
        hosts.add("127.0.0.1");
        if (!ep.host.isEmpty() && !ep.host.contains(":")) {
            hosts.add(ep.host);
        }

        StringBuilder tried = new StringBuilder();
        for (String h : hosts) {
            if (!reachable(h, ep.port, 3000)) {
                tried.append(h).append(": 不可达；");
                continue;
            }
            try {
                boolean ok = pair(h, ep.port, code);
                if (ok) {
                    return "配对成功（" + h + ":" + ep.port + "）\n自检 " + pre;
                }
                tried.append(h).append(": 被拒；");
            } catch (Throwable t) {
                tried.append(h).append(": ").append(t.getClass().getSimpleName()).append('；');
            }
        }
        return "配对失败：adbd 拒绝了这次配对（码错/超时/端口不对）\n"
                + "尝试 " + tried + "\n自检 " + pre;
    }

    /**
     * 配对前自检：把三层单独报出来。
     *
     * 0.70 在真机上只回一句 NoClassDefFoundError，看不出是证书生成、
     * BC 的 crypto 还是 SPAKE2 本身坏了。分开探一遍，失败就有明确落点。
     */
    static String selfTest(Context ctx) {
        StringBuilder sb = new StringBuilder();
        sb.append("bc=").append(probe("org.bouncycastle.crypto.digests.SHA256Digest"));
        try {
            AdbKeyStore ks = AdbKeyStore.load(ctx);
            sb.append(" cert=").append(ks.cert.getPublicKey().getAlgorithm())
                    .append('/').append(ks.cert.getSubjectX500Principal().getName());
        } catch (Throwable t) {
            sb.append(" cert=FAIL(").append(t).append(')');
        }
        sb.append(" spake2=").append(probe("io.github.muntashirakon.adb.PairingConnectionCtx"));
        return sb.toString();
    }

    private static String probe(String cls) {
        try {
            Class.forName(cls);
            return "ok";
        } catch (Throwable t) {
            return "FAIL(" + t.getClass().getSimpleName() + ')';
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
