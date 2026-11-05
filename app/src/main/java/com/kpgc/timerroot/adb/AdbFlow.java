package com.kpgc.timerroot.adb;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

/**
 * ADB 直连模式的一键流程：部署 -> 提权 -> 等 ksud -> 验 su。
 *
 * 和 Shizuku 那条链的差别只有「谁提供 shell」：这里用 adbd 的 shell: 服务
 * （uid 2000，u:r:shell:s0），跑的还是同一个 /data/local/tmp/timer 和同一份 conf。
 */
public final class AdbFlow {

    public interface Sink {
        void log(String line);
    }

    private static final String TMP = "/data/local/tmp";

    private AdbFlow() {
    }

    /** 返回最后一份原生日志（失败时也返回，便于贴出来看）。 */
    public static String oneTap(Context ctx, Sink sink) {
        try {
            AdbLink link = AdbLink.get(ctx);
            if (!link.ready()) {
                return "ADB 未连接：先点「配对并连接」";
            }

            String rel = firstLine(link.exec("uname -r", 10));
            if (!looksLikeRelease(rel)) {
                return "取 uname -r 失败：" + rel;
            }
            sink.log("[adb] release=" + rel);

            byte[] conf = pickConf(ctx, link, rel, sink);
            if (conf == null) {
                return "conf=none（" + rel + " 没有匹配的配置，先导入或内置一份）";
            }
            byte[] bin = readAsset(ctx, "timer");
            if (bin == null) {
                return "APK 里没有 assets/timer";
            }

            File ext = ctx.getExternalFilesDir(null);
            if (ext == null) {
                return "外部目录不可用，shell 拿不到二进制";
            }
            File fb = new File(ext, "timer");
            File fc = new File(ext, "timer.conf");
            write(fb, bin);
            write(fc, conf);

            String deploy = "cp '" + fb.getAbsolutePath() + "' " + TMP + "/timer"
                    + " && chmod 755 " + TMP + "/timer"
                    + " && cp '" + fc.getAbsolutePath() + "' " + TMP + "/timer.conf"
                    + " && echo DEPLOY_OK";
            String dr = link.exec(deploy, 30);
            if (!dr.contains("DEPLOY_OK")) {
                return "部署失败：" + dr.trim();
            }
            sink.log("[adb] timer " + bin.length + " B + conf " + conf.length + " B 已就位");

            link.exec("am kill-all 2>/dev/null; sync", 20);

            // nohup 在 toybox 里一定有；setsid 个别 ROM 没带，不能赌
            String run = "cd " + TMP + " && nohup ./timer --conf timer.conf fake"
                    + " >timer.log 2>&1 </dev/null & echo STARTED";
            String rr = link.exec(run, 15);
            sink.log("[adb] " + (rr.contains("STARTED") ? "已启动，等内核日志…" : "启动返回：" + rr.trim()));

            String log = "";
            long end = System.currentTimeMillis() + 90_000L;
            while (System.currentTimeMillis() < end) {
                Thread.sleep(2000);
                log = link.exec("cat " + TMP + "/timer.log 2>/dev/null", 15);
                if (log.contains("KSU_LOADED") || log.contains("KSU_MISSING")
                        || log.contains("parking without reap")
                        || log.contains("selinux write failed")
                        || log.contains("fake cred write failed")) {
                    break;
                }
            }
            if (!log.isEmpty()) {
                sink.log(log);
            }

            String su = link.exec("su -c id 2>&1", 15).trim();
            sink.log("[adb] su -c id → " + (su.isEmpty() ? "（无输出）" : su));
            return log;
        } catch (Throwable t) {
            return "ADB 执行失败：" + t;
        }
    }

    /** 只跑 su -c id，用于复验。 */
    public static String suCheck(Context ctx) {
        try {
            AdbLink link = AdbLink.get(ctx);
            if (!link.ready()) {
                return "ADB 未连接";
            }
            String r = link.exec("su -c id 2>&1", 15).trim();
            return r.isEmpty() ? "su 无输出（未加载）" : r;
        } catch (Throwable t) {
            return "ADB 执行失败：" + t;
        }
    }

    /** 先查用户导入的 /data/local/tmp/conf.d，再退到 APK 内置的 assets/conf。 */
    private static byte[] pickConf(Context ctx, AdbLink link, String rel, Sink sink) throws Exception {
        String q = "grep -l 'release *= *\"" + rel + "\"' " + TMP + "/conf.d/*.conf 2>/dev/null | head -1";
        String path = firstLine(link.exec(q, 10));
        if (path.startsWith("/")) {
            String text = link.exec("cat '" + path + "'", 10);
            if (text.contains("release")) {
                sink.log("[adb] conf=" + path + "（外部导入）");
                return text.getBytes("UTF-8");
            }
        }
        try (InputStream in = ctx.getAssets().open("conf/" + rel + ".conf")) {
            sink.log("[adb] conf=assets/conf/" + rel + ".conf（内置）");
            return readAll(in);
        } catch (Throwable t) {
            return null;
        }
    }

    private static boolean looksLikeRelease(String s) {
        return s.matches("[0-9]+\\.[0-9]+\\.[0-9]+.*");
    }

    private static String firstLine(String s) {
        if (s == null) {
            return "";
        }
        for (String line : s.split("\n")) {
            String t = line.trim();
            if (!t.isEmpty() && !t.startsWith("ADB_ERROR")) {
                return t;
            }
        }
        return "";
    }

    private static byte[] readAsset(Context ctx, String name) {
        try (InputStream in = ctx.getAssets().open(name)) {
            return readAll(in);
        } catch (Throwable t) {
            return null;
        }
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private static void write(File f, byte[] data) throws Exception {
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write(data);
        }
    }
}
