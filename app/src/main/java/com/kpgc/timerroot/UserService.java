package com.kpgc.timerroot;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.BufferedWriter;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Runs inside the process that Shizuku starts as the shell user (uid 2000,
 * u:r:shell:s0), which is what the exploit needs for tracefs.
 */
public class UserService extends IUserService.Stub {

    /** 服务端版本标记：用来判断当前跑的 UserService 是不是新装的那份。 */
    private static final String BUILD = "0.62";
    private static final String PKG = "com.kpgc.timerroot";
    private static final String BIN = "/data/local/tmp/timer";
    private static final String CONF = "/data/local/tmp/timer.conf";
    /** 导入的 conf 放这里：shell 可写，且重启后还在（不像 filesDir 只属于 app）。 */
    private static final String CONFDIR = "/data/local/tmp/conf.d";
    private static final String LOG = "/data/local/tmp/timer.log";
    /** Copied from whichever installed manager ships lib/arm64/libksud.so. */
    private static final String KSUD = "/data/local/tmp/ksud";
    /**
     * 手动指定的管理器包名；存在时优先于自动嗅探。
     * 自动嗅探已经能认任何带 libksud.so 的包，这里只是给"认错了"留一个出口：
     * 设备上同时装了两个管理器、或者某个普通 app 恰好打包了 libksud.so 时用得上。
     */
    private static final String KSU_OVERRIDE = "/data/local/tmp/ksud.pkg.override";
    private static final int MAX_OUTPUT = 20000;

    private Process rootProcess;
    private BufferedWriter rootInput;
    private final BlockingQueue<String> rootLines = new LinkedBlockingQueue<>();
    /** 最近一次成功采用的管理器包名，只用于 info() 展示。 */
    private String lastMgr = "";

    public UserService() {
    }

    public UserService(android.content.Context context) {
    }

    @Override
    public void destroy() {
        closeRootInternal();
        System.exit(0);
    }

    @Override
    public void exit() {
        destroy();
    }

    @Override
    public String install(String apk) {
        try {
            String release = execOut("uname -r").trim();
            String confPicked = null;
            try (ZipFile zf = new ZipFile(apk)) {
                ZipEntry entry = zf.getEntry("assets/timer");
                if (entry == null) {
                    return "assets/timer not found in " + apk;
                }
                String tmp = BIN + ".new";
                try (InputStream in = zf.getInputStream(entry);
                     FileOutputStream out = new FileOutputStream(tmp)) {
                    byte[] buf = new byte[65536];
                    int n;
                    while ((n = in.read(buf)) > 0) {
                        out.write(buf, 0, n);
                    }
                }
                // The old binary may still be mapped by a parked process; rename
                // over it instead of writing in place (ETXTBSY).
                Process move = Runtime.getRuntime().exec(new String[]{"/system/bin/sh",
                        "-c", "chmod 755 " + tmp + " && mv -f " + tmp + " " + BIN});
                move.waitFor();

                /*
                 * 选 conf 的优先级：
                 *   1) 用户导入的 /data/local/tmp/conf.d/<release>.conf
                 *   2) APK 内置的 assets/conf/
                 * 两者都要求 release 与 uname -r 逐字相同 —— 拿别的内核偏移
                 * 去写内存是 panic，不是"大概能用"。
                 */
                byte[] fallbackData = null;
                String builtinSeen = null;
                String imported = pickExternalConf(release);
                if (imported != null) {
                    try (FileInputStream in = new FileInputStream(imported)) {
                        fallbackData = readBytes(in);
                    }
                    if (fallbackData != null && fallbackData.length > 0) {
                        confPicked = imported;
                    }
                }
                java.util.Enumeration<? extends ZipEntry> en = zf.entries();
                while (confPicked == null && en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    // aapt2 on Windows may store nested asset paths with a
                    // backslash; normalize before matching.
                    String name = e.getName().replace('\\', '/');
                    if (!name.startsWith("assets/conf/") || !name.endsWith(".conf")) {
                        continue;
                    }
                    byte[] data;
                    try (InputStream in = zf.getInputStream(e)) {
                        data = readBytes(in);
                    }
                    // 记住第一份，只用于出错时报告"内置里有哪几份"
                    if (builtinSeen == null) {
                        builtinSeen = name;
                    }
                    String text = new String(data, "UTF-8");
                    Matcher m = Pattern.compile("(?m)^\\s*release\\s*=\\s*\"([^\"]+)\"")
                            .matcher(text);
                    if (m.find() && m.group(1).equals(release)) {
                        confPicked = name;
                        fallbackData = data;
                        break;
                    }
                }
                if (confPicked == null) {
                    /*
                     * No conf matches this release.  Writing the fallback would
                     * run the exploit with another kernel's offsets, which is
                     * how a run turns into a panic instead of a clean failure.
                     */
                    return "conf=none（没有与 release=" + release
                            + " 匹配的配置；内置 " + (builtinSeen == null ? "无" : builtinSeen)
                            + "，可用「导入配置」补一份）";
                }
                try (FileOutputStream out = new FileOutputStream(CONF)) {
                    out.write(fallbackData);
                }
                new File(CONF).setReadable(true, false);
            }
            String carried = backupPreviousLog();
            return "已安装 " + new File(BIN).length() + " 字节，release=" + release
                    + ", conf=" + (confPicked == null ? "none" : confPicked)
                    + " (uid=" + android.system.Os.getuid() + ")\n" + prepareKsud()
                    + "\n" + prepareSystem() + (carried.isEmpty() ? "" : "\n" + carried);
        } catch (Throwable t) {
            return "安装失败：" + t;
        }
    }

    @Override
    public String run(String args) {
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "/system/bin/sh", "-c",
                    BIN + " --conf " + CONF + " " + args + " 2>&1");
            pb.directory(new File("/data/local/tmp"));
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String text = readAll(p.getInputStream());
            if (!p.waitFor(90, TimeUnit.SECONDS)) {
                return text + "\n[超时] 90 秒仍未结束 —— 不要 kill，重启清理";
            }
            return text;
        } catch (Throwable t) {
            return "运行失败：" + t;
        }
    }

    @Override
    public String runDetached(String args) {
        try {
            String cmd = "cd /data/local/tmp && setsid " + BIN + " --conf " + CONF
                    + " " + args + " >" + LOG + " 2>&1 </dev/null &";
            Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", cmd});
            Thread.sleep(2000);
            return readLog();
        } catch (Throwable t) {
            return "启动失败：" + t;
        }
    }

    @Override
    public String readLog() {
        try (FileInputStream in = new FileInputStream(LOG)) {
            // 1 MB 上限：原来的 20 KB 只读了文件头，fake 路线最关键的结尾会被裁掉
            return readAll(in, 1024 * 1024);
        } catch (Throwable t) {
            return "";
        }
    }

    @Override
    public String openRoot() {
        if (rootProcess != null && rootProcess.isAlive()) {
            return "root Shell 已经打开";
        }
        try {
            ProcessBuilder pb = new ProcessBuilder(BIN, "--conf", CONF, "shell");
            pb.directory(new File("/data/local/tmp"));
            pb.redirectErrorStream(true);
            rootProcess = pb.start();
            rootInput = new BufferedWriter(
                    new OutputStreamWriter(rootProcess.getOutputStream()));
            final BufferedReader reader = new BufferedReader(
                    new InputStreamReader(rootProcess.getInputStream()));
            rootLines.clear();
            Thread pump = new Thread(() -> {
                try {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        rootLines.offer(line);
                    }
                } catch (IOException ignored) {
                }
            });
            pump.setDaemon(true);
            pump.start();
            Thread.sleep(2000);
            StringBuilder out = new StringBuilder();
            boolean rooted = false;
            long deadline = System.currentTimeMillis() + 60000;
            long grace = 0;
            while (System.currentTimeMillis() < deadline) {
                String line = rootLines.poll(200, TimeUnit.MILLISECONDS);
                if (line == null) {
                    if (rooted && grace > 0 && System.currentTimeMillis() > grace) {
                        break;
                    }
                    continue;
                }
                out.append(line).append('\n');
                if (!rooted && line.contains("uid=0(root)")) {
                    rooted = true;
                    // shell 启动时紧接着还会打 Uid/Gid/Cap 和 SELinux 上下文，
                    // 立刻 break 会把这几行丢掉，留 1.2 秒收尾。
                    grace = System.currentTimeMillis() + 1200;
                    continue;
                }
                if (!rooted && (line.contains("shell exec failed")
                        || line.contains("parking without reap"))) {
                    break;
                }
            }
            return (rooted ? "已获得 root\n" : "未获得 root\n")
                    + out.toString().trim();
        } catch (Throwable t) {
            return "打开 root Shell 失败：" + t;
        }
    }

    @Override
    public String execRoot(String cmd) {
        if (rootProcess == null || !rootProcess.isAlive()) {
            return "root Shell 未打开";
        }
        try {
            rootInput.write(cmd + " 2>&1\necho __END__\n");
            rootInput.flush();
            StringBuilder sb = new StringBuilder();
            long deadline = System.currentTimeMillis() + 30000;
            while (System.currentTimeMillis() < deadline) {
                String line = rootLines.poll(200, TimeUnit.MILLISECONDS);
                if (line == null) {
                    continue;
                }
                if (line.equals("__END__")) {
                    break;
                }
                sb.append(line).append('\n');
            }
            return sb.toString();
        } catch (Throwable t) {
            return "命令执行失败：" + t;
        }
    }

    @Override
    public String closeRoot() {
        closeRootInternal();
        return "root shell closed";
    }

    /** SELinux / Seccomp / ksud, as shown on the home card. */
    @Override
    public String info() {
        String selinux = execOut("getenforce");
        String seccomp = execOut("grep -m1 Seccomp /proc/self/status | awk '{print $2}'");
        String ksud = "not loaded";
        Matcher m = Pattern.compile("(?:version=|\\[ksu\\] ver=)([^\\n]*)").matcher(readLog());
        if (m.find()) {
            ksud = m.group(1).trim();
        } else if (selinux.contains("Permissive")) {
            ksud = "missing";
        }
        String ksu = execOut("timeout 3 /system/bin/su -c id 2>/dev/null").contains("u:r:ksu:s0")
                ? "active" : "not loaded";
        String manual = ksuOverride();
        String mgr = manual.isEmpty()
                ? (lastMgr.isEmpty() ? "auto" : "auto:" + lastMgr)
                : "manual:" + manual;
        return "build=" + BUILD + "\nselinux=" + selinux + "\nseccomp=" + seccomp
                + "\nksud=" + ksud + "\nksu=" + ksu + "\nmgr=" + mgr + "\n";
    }

    /**
     * 导出日志。优先写应用侧那份（所有路线都有：shell、诊断、KSU），
     * 再把 /data/local/tmp/timer.log 里的原生输出追加在后面。
     * shell 在 sdcard_rw 组里，可以直接写 FUSE 目录。
     */
    @Override
    public String exportLog(String uiText) {
        try {
            String ts = new java.text.SimpleDateFormat("MMdd-HHmmss", java.util.Locale.US)
                    .format(new java.util.Date());
            StringBuilder sb = new StringBuilder();
            if (uiText != null && !uiText.isEmpty()) {
                sb.append(uiText);
                if (!uiText.endsWith("\n")) {
                    sb.append('\n');
                }
            }
            String raw = "";
            File f = new File(LOG);
            if (f.isFile() && f.length() > 0) {
                sb.append("\n===== /data/local/tmp/timer.log =====\n");
                try (FileInputStream in = new FileInputStream(f)) {
                    sb.append(readAll(in, 1024 * 1024));
                }
            }
            byte[] data = sb.toString().getBytes("UTF-8");
            String[] dirs = {"/sdcard/Download", "/sdcard", "/data/local/tmp"};
            for (String d : dirs) {
                String out = d + "/timer-" + ts + ".log";
                try (FileOutputStream fo = new FileOutputStream(out)) {
                    fo.write(data);
                } catch (Throwable ignored) {
                    continue;
                }
                File o = new File(out);
                if (o.isFile() && o.length() > 0) {
                    return "日志已导出：" + out + "（" + o.length() + " 字节）";
                }
            }
            return "导出失败：没有可写目录，可用 adb pull " + LOG;
        } catch (Throwable t) {
            return "导出失败：" + t;
        }
    }

    /**
     * 通过 rootd 执行命令。
     *
     * rootd 的 socket 是 0600 / shell(2000)，所以 App 自己连不上 —— 必须由
     * 这个跑在 shell 域的用户服务代连。这也顺便把权限面收窄成"只有 shell"。
     */
    @Override
    public String rootdExec(String cmd) {
        android.net.LocalSocket sock = new android.net.LocalSocket();
        try {
            sock.connect(new android.net.LocalSocketAddress(
                    "/data/local/tmp/rootd.sock",
                    android.net.LocalSocketAddress.Namespace.FILESYSTEM));
            java.io.OutputStream os = sock.getOutputStream();
            os.write((cmd + "\n").getBytes("UTF-8"));
            os.flush();
            java.io.InputStream in = sock.getInputStream();
            byte[] buf = new byte[8192];
            StringBuilder sb = new StringBuilder();
            int n;
            while ((n = in.read(buf)) > 0) {
                sb.append(new String(buf, 0, n, "UTF-8"));
                int e = sb.indexOf("__END__\n");
                if (e >= 0) {
                    return sb.substring(0, e);
                }
                if (sb.length() > 262144) {
                    break;
                }
            }
            return sb.length() == 0 ? "" : sb.toString();
        } catch (Throwable t) {
            return "rootd 不可用：" + t;
        } finally {
            try {
                sock.close();
            } catch (Throwable ignored) {
            }
        }
    }

    /**
     * 在 /data/local/tmp/conf.d 里找 release 与 uname -r 完全一致的那份。
     * 用 grep 一次拿到「路径:声明」，避免逐个读文件。
     */
    private String pickExternalConf(String release) {
        String listing = shell("mkdir -p " + CONFDIR + " 2>/dev/null; "
                + "grep -H '^[[:space:]]*release[[:space:]]*=' " + CONFDIR
                + "/*.conf 2>/dev/null");
        Pattern p = Pattern.compile("release\\s*=\\s*\"([^\"]+)\"");
        for (String line : listing.split("\n")) {
            int c = line.indexOf(':');
            if (c <= 0) {
                continue;
            }
            Matcher m = p.matcher(line.substring(c + 1));
            if (m.find() && m.group(1).equals(release)) {
                return line.substring(0, c).trim();
            }
        }
        return null;
    }

    /**
     * 导入一份 conf（文本由 App 侧从文件选择器读出后经 binder 传进来）。
     * 只做校验 + 落盘，不立刻生效 —— 下次「准备」时按 release 匹配取用。
     */
    @Override
    public String importConf(String name, String text) {
        try {
            if (text == null || text.trim().isEmpty()) {
                return "导入失败：文件是空的";
            }
            Matcher m = Pattern.compile("(?m)^\\s*release\\s*=\\s*\"([^\"]+)\"")
                    .matcher(text);
            String rel = m.find() ? m.group(1).trim() : null;
            if (rel == null) {
                return "导入失败：没找到 release = \"…\" 这一行，这不像 TimerUAF 的 conf";
            }
            for (String k : new String[]{"timer_site", "selinux_state", "task_cred_off",
                    "copy_process_low21", "task_alloc_bytes", "ksu_kmi"}) {
                if (!Pattern.compile("(?m)^\\s*" + k + "\\s*=").matcher(text).find()) {
                    return "导入失败：缺少必填字段 " + k + "（二进制会拒绝启动）";
                }
            }
            File dir = new File(CONFDIR);
            if (!dir.isDirectory() && !dir.mkdirs()) {
                return "导入失败：建不了目录 " + CONFDIR;
            }
            String safe = (name == null || name.trim().isEmpty() ? rel : name.trim())
                    .replaceAll("[^A-Za-z0-9._-]", "_");
            if (!safe.endsWith(".conf")) {
                safe += ".conf";
            }
            File out = new File(dir, safe);
            try (FileOutputStream fo = new FileOutputStream(out)) {
                fo.write(text.getBytes("UTF-8"));
            }
            out.setReadable(true, false);
            String uname = execOut("uname -r").trim();
            boolean match = rel.equals(uname);
            return "已导入 " + out.getAbsolutePath() + "（" + out.length() + " 字节）\n"
                    + "  release = " + rel + "\n"
                    + (match ? "  与本机一致，会自动用于准备"
                             : "  注意：本机是 " + uname + "，不匹配，不会被使用");
        } catch (Throwable t) {
            return "导入失败：" + t;
        }
    }

    /**
     * 端到端验证：以 shell(2000) 身份跑 su，看拿到的到底是不是 u:r:ksu:s0。
     * 这是 KSU 是否真的可用的唯一判据 —— 模块载入不等于 su 能用。
     */
    @Override
    public String suCheck() {
        String su = "/system/bin/su";
        if (!new File(su).exists()) {
            return "su 不存在：" + su + "\n模块可能只加载了一半，或管理器路径不同";
        }
        String id = shell("timeout 5 " + su + " -c id 2>&1");
        String enf = shell("timeout 5 " + su + " -c getenforce 2>&1");
        String mods = shell("grep -c '^kernelsu ' /proc/modules 2>/dev/null");
        return "su=" + su + "\n"
                + "id=" + id.trim() + "\n"
                + "getenforce=" + enf.trim() + "\n"
                + "modules_kernelsu=" + mods.trim();
    }

    @Override
    public String rebootDevice() {
        int rc = execCode("/system/bin/svc power reboot");
        if (rc != 0) {
            rc = execCode("/system/bin/su -c reboot");
        }
        if (rc != 0) {
            rc = execCode("/system/bin/reboot");
        }
        return rc == 0 ? "rebooting" : "reboot failed (rc=" + rc + ")";
    }

    private int execCode(String cmd) {
        try {
            Process p = new ProcessBuilder("/system/bin/sh", "-c", cmd)
                    .redirectErrorStream(true).start();
            return p.waitFor();
        } catch (Throwable t) {
            return -1;
        }
    }

    /**
     * Finds a root manager by content, not by package name: any installed app
     * whose nativeLibraryDir holds libksud.so is a valid manager, so forks and
     * renamed builds work without a rebuild.  The first hit is copied to
     * /data/local/tmp/ksud, which is what the late-load stage prefers; an
     * existing copy (manual push, or a manager that was since uninstalled) is
     * kept.
     */
    /**
     * 跑漏洞前的固定步骤：清掉后台进程并刷盘。
     *
     * 抢页输掉的典型原因是"页刚释放就被别的分配拿走"，后台进程越少，
     * 竞态窗口里发生的分配就越少。am kill-all 走 binder，shell 有
     * KILL_BACKGROUND_PROCESSES 权限；失败了也继续跑，只是记一行警告。
     */
    /**
     * 上一次运行的原生日志在 /data/local/tmp/timer.log，重启后仍在，但只有 shell
     * 读得到；而重启后 Shizuku 一定是停的，App 根本连不上用户服务，也就导不出来。
     * 所以在每次开跑之前，先把它拷到 App 自己的外部目录（shell 可写、App 免权限可读），
     * 这样即使这次把内核跑崩，证据也留在了 /sdcard 上。
     */
    private String backupPreviousLog() {
        try {
            File log = new File(LOG);
            if (!log.isFile() || log.length() == 0) {
                return "";
            }
            String dir = "/sdcard/Android/data/" + PKG + "/files";
            String dst = dir + "/last-run.log";
            String r = shell("mkdir -p " + dir + " 2>&1; cp -f " + LOG + " " + dst
                    + " 2>&1; echo __bk=$?").trim();
            if (r.contains("__bk=0")) {
                return "上一次的日志已备份：" + dst + "（" + log.length() + " 字节）";
            }
            /* 外部目录不可写时退回 /data/local/tmp，等 Shizuku 起来还能导 */
            shell("cp -f " + LOG + " " + LOG + ".prev 2>/dev/null");
            return "日志备份失败（" + r + "），已保留 " + LOG + ".prev";
        } catch (Throwable t) {
            return "日志备份异常：" + t;
        }
    }

    private String prepareSystem() {
        String before = memAvailableMb();
        String r = shell("am kill-all 2>&1; sync; echo __prep_done__");
        String after = memAvailableMb();
        boolean ok = r.contains("__prep_done__");
        return (ok ? "已清理后台：" : "清理后台失败（继续跑）：")
                + "MemAvailable " + before + " -> " + after + " MB";
    }

    private String memAvailableMb() {
        String v = shell("grep MemAvailable /proc/meminfo 2>/dev/null"
                + " | awk '{print int($2/1024)}'").trim();
        return v.isEmpty() ? "?" : v;
    }

    /**
     * 找 root 管理器：按内容找 libksud.so，不看包名。
     *
     * /data/app 从 Android 11 起对 shell 是 0771（只有 x、没有 r），find 第一步
     * opendir 就 EACCES；但通过 pm 走 binder 列包、拿到完整 apk 路径之后直接
     * stat 是允许的。所以顺序是：
     *   1. pm list packages -f，逐个看 <apk 同目录>/lib/<abi>/libksud.so
     *   2. 没解压出来（extractNativeLibs=false）就从管理器 APK 里抽
     *   3. 老设备上 find /data/app 兜底
     */
    /** 已知的管理器包名，排在前面；其余带 libksud.so 的包只作后备。 */
    private static final String[] KSU_PACKAGES = {
            "me.weishu.kernelsu", "me.weishu.kernelsu.pr", "me.weishu.kernelsu.next",
            "com.rifsxd.ksunext", "com.sukisu.ultra", "com.resukisu.resukisu",
            "org.bakasu.bakasu", "me.yuki.fina", "com.kowx712.supermanager"
    };

    private static int ksuRank(String pkg) {
        for (int i = 0; i < KSU_PACKAGES.length; i++) {
            if (KSU_PACKAGES[i].equals(pkg)) {
                return i;
            }
        }
        return KSU_PACKAGES.length;
    }

    private String prepareKsud() {
        String auto = prepareKsudAuto();
        String want = ksuOverride();

        if (want.isEmpty()) {
            return auto;
        }
        String forced = adoptFromApks(listApks(), want);
        if (forced != null) {
            return forced + "（手动指定 " + want + "）";
        }
        return "指定的 " + want + " 上没有 libksud.so，已回落自动\n" + auto;
    }

    /** pm 列包并排序；prepareKsud 和管理器列表共用。 */
    private java.util.List<String[]> listApks() {
        java.util.ArrayList<String[]> apks = new java.util.ArrayList<>();
        String listing = shell("pm list packages -f 2>/dev/null");
        for (String line : listing.split("\n")) {
            line = line.trim();
            if (!line.startsWith("package:")) {
                continue;
            }
            String body = line.substring(8);
            int eq = body.lastIndexOf('=');
            if (eq <= 0) {
                continue;
            }
            apks.add(new String[]{body.substring(0, eq), body.substring(eq + 1)});
        }
        // pm 是按下标顺序输出的，com.* 会排在 me.* 前面；不排序就会选中
        // 某个碰巧带 libksud.so 的普通 app（实测选到了 com.sevenk.core）。
        apks.sort((a, b) -> Integer.compare(ksuRank(a[1]), ksuRank(b[1])));
        return apks;
    }

    private String prepareKsudAuto() {
        java.util.List<String[]> apks = listApks();

        // 1) lib 目录里就有 libksud.so
        for (String[] a : apks) {
            File dir = new File(a[0]).getParentFile();
            if (dir == null) {
                continue;
            }
            for (String abi : new String[]{"arm64", "arm"}) {
                File c = new File(dir, "lib/" + abi + "/libksud.so");
                if (c.isFile()) {
                    return adoptKsud(c.getAbsolutePath(), a[1], "lib/" + abi);
                }
            }
        }

        // 2) 从管理器的 APK 里抽（只打开名字像管理器的包，避免几百次解压）
        for (String[] a : apks) {
            if (!looksLikeManager(a[1])) {
                continue;
            }
            String r = extractKsud(a[0], a[1]);
            if (r != null) {
                return r;
            }
        }

        // 3) 老设备兜底
        String found = shell("find /data/app -name libksud.so -path '*/lib/arm64/*'"
                + " 2>/dev/null | head -1").trim();
        if (found.isEmpty()) {
            found = shell("find /data/app -name libksud.so 2>/dev/null | head -1").trim();
        }
        if (!found.isEmpty()) {
            return adoptKsud(found, "", "find");
        }
        return "ksud=none（pm 列出 " + apks.size() + " 个包，都没有 libksud.so；"
                + "设备上没有装 KernelSU / Next / SukiSU 这类管理器）";
    }

    private static boolean looksLikeManager(String pkg) {
        String p = pkg.toLowerCase();
        /* 只做"要不要打开 APK 抽一下"的粗筛，命中率不重要；
         * 真正的判据始终是包里有没有 libksud.so。 */
        return p.contains("ksu") || p.contains("sukisu") || p.contains("kernelsu")
                || p.contains("supermanager") || p.contains("bakasu")
                || p.contains("yuki.fina");
    }

    /** 手动指定：从指定包取 libksud.so，取不到返回 null（调用方回落自动）。 */
    private String adoptFromApks(java.util.List<String[]> apks, String pkg) {
        for (String[] a : apks) {
            if (!pkg.equals(a[1])) {
                continue;
            }
            File dir = new File(a[0]).getParentFile();
            if (dir != null) {
                for (String abi : new String[]{"arm64", "arm"}) {
                    File c = new File(dir, "lib/" + abi + "/libksud.so");
                    if (c.isFile()) {
                        return adoptKsud(c.getAbsolutePath(), pkg, "lib/" + abi);
                    }
                }
            }
            // extractNativeLibs=false：libksud.so 只在 APK 里
            return extractKsud(a[0], pkg);
        }
        return null;
    }

    private String ksuOverride() {
        try {
            String s = shell("cat " + KSU_OVERRIDE + " 2>/dev/null | head -1").trim();
            return s.contains(".") ? s : "";
        } catch (Throwable t) {
            return "";
        }
    }

    /**
     * 列出可用的管理器，供界面手选。
     * 每行 "包名<TAB>apk 路径<TAB>来源"，只列真正带 libksud.so 的包，
     * 外加名字像管理器的包（它们的 libksud.so 可能在 APK 里，要抽才知道）。
     */
    @Override
    public String ksuManagers() {
        StringBuilder sb = new StringBuilder();
        for (String[] a : listApks()) {
            String how = "";
            File dir = new File(a[0]).getParentFile();
            if (dir != null) {
                for (String abi : new String[]{"arm64", "arm"}) {
                    if (new File(dir, "lib/" + abi + "/libksud.so").isFile()) {
                        how = "lib/" + abi;
                        break;
                    }
                }
            }
            if (how.isEmpty()) {
                if (!looksLikeManager(a[1])) {
                    continue;
                }
                how = "apk";
            }
            sb.append(a[1]).append('\t').append(a[0]).append('\t').append(how).append('\n');
        }
        return sb.toString();
    }

    /** 写/清覆盖文件，然后立刻按新选择重跑一次 ksud 定位。 */
    @Override
    public String setKsuManager(String pkg) {
        if (pkg == null || pkg.isEmpty() || "auto".equals(pkg)) {
            shell("rm -f " + KSU_OVERRIDE);
            return "已恢复自动识别\n" + prepareKsud();
        }
        if (!pkg.matches("[A-Za-z0-9._]+")) {
            return "包名不合法：" + pkg;
        }
        shell("printf '%s' '" + pkg + "' > " + KSU_OVERRIDE);
        return "已指定 " + pkg + "\n" + prepareKsud();
    }

    /** 复用已有副本（必须是真 ELF），否则从 src 复制并写包名 sidecar。 */
    private String adoptKsud(String src, String pkg, String how) {
        String sidecar = shell("cat " + KSUD + ".pkg 2>/dev/null | head -1").trim();
        boolean existing = new File(KSUD).isFile()
                && "7f454c46".equals(shell("head -c 4 '" + KSUD
                        + "' 2>/dev/null | od -An -tx1 | tr -d ' \\n'"))
                && pkg.equals(sidecar);
        if (!pkg.isEmpty()) {
            lastMgr = pkg;
        }
        if (existing) {
            return "ksud=" + KSUD + "（沿用现有文件，来源=" + src
                    + "，方式=" + how + "，ver=" + ksudVersion() + "）";
        }
        shell("cp '" + src + "' " + KSUD + ".new 2>&1; chmod 755 " + KSUD
                + ".new 2>/dev/null; mv -f " + KSUD + ".new " + KSUD);
        if (!new File(KSUD).isFile()) {
            return "ksud=复制失败，来源 " + src;
        }
        writePkg(pkg);
        return "ksud=" + KSUD + "（来源=" + src + "，方式=" + how
                + (pkg.isEmpty() ? "" : "，pkg=" + pkg)
                + "，ver=" + ksudVersion() + "）";
    }

    /** ksud 的版本串里带 KMI，准备阶段就能看出和内核是否匹配。 */
    private String ksudVersion() {
        String v = shell(KSUD + " --version 2>&1 | head -1").trim();
        return v.isEmpty() ? "unknown" : v;
    }

    /** libksud.so 打包在 APK 里时直接抽出来。 */
    private String extractKsud(String apk, String pkg) {
        try (ZipFile zf = new ZipFile(apk)) {
            ZipEntry e = zf.getEntry("lib/arm64/libksud.so");
            if (e == null) {
                e = zf.getEntry("lib/arm/libksud.so");
            }
            if (e == null) {
                return null;
            }
            String tmp = KSUD + ".new";
            try (InputStream in = zf.getInputStream(e);
                 FileOutputStream out = new FileOutputStream(tmp)) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                }
            }
            shell("chmod 755 " + tmp + " 2>/dev/null; mv -f " + tmp + " " + KSUD);
            if (!new File(KSUD).isFile()) {
                return null;
            }
            writePkg(pkg);
            return "ksud=" + KSUD + "（从 APK 抽取：" + apk + "，pkg=" + pkg + "）";
        } catch (Throwable t) {
            return null;
        }
    }

    private void writePkg(String pkg) {
        if (pkg == null || pkg.isEmpty() || !pkg.contains(".")) {
            return;
        }
        try (FileOutputStream out = new FileOutputStream(KSUD + ".pkg")) {
            out.write(pkg.getBytes("UTF-8"));
        } catch (Throwable ignored) {
        }
    }

    /** Shell output without the "unknown" placeholder execOut uses. */
    private String shell(String cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder("/system/bin/sh", "-c", cmd);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            // pm list packages -f 能到几十 KB，这里不能用日志的 20 KB 上限
            String text = readAll(p.getInputStream(), 4 * 1024 * 1024).trim();
            p.waitFor();
            return text;
        } catch (Throwable t) {
            return "";
        }
    }

    private String execOut(String cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder("/system/bin/sh", "-c", cmd);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String text = readAll(p.getInputStream()).trim();
            p.waitFor();
            return text.isEmpty() ? "unknown" : text;
        } catch (Throwable t) {
            return "unknown";
        }
    }

    private void closeRootInternal() {
        try {
            if (rootInput != null) {
                rootInput.write("exit\n");
                rootInput.flush();
            }
        } catch (IOException ignored) {
        }
        if (rootProcess != null) {
            rootProcess.destroy();
            rootProcess = null;
        }
        rootInput = null;
    }

    private static byte[] readBytes(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) > 0) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }

    private static String readAll(InputStream in) throws IOException {
        return readAll(in, MAX_OUTPUT);
    }

    private static String readAll(InputStream in, int limit) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        int total = 0;
        while ((n = in.read(buf)) > 0) {
            bos.write(buf, 0, n);
            total += n;
            if (total > limit) {
                break;
            }
        }
        return bos.toString("UTF-8");
    }
}
