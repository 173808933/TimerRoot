package com.kpgc.timerroot;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ComponentName;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.ServiceConnection;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Toast;
import android.widget.TextView;

import java.io.File;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.io.InputStream;
import java.io.FileOutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import rikka.shizuku.Shizuku;

/**
 * Front end for CVE-2026-98260 (posix CPU timer UAF).
 *
 * The exploit cannot run in this process (an app is untrusted_app and cannot
 * read /sys/kernel/tracing), so it runs through a Shizuku user service that
 * Shizuku starts as the shell user (uid 2000, u:r:shell:s0).
 */
public class MainActivity extends Activity {

    private static final String TAG = "TimerRoot";
    private static final int REQUEST_CODE = 1001;

    private static final int BG = 0xFF0B0B0B;
    private static final int CARD = 0xFF1C1C1E;
    private static final int LINE = 0xFF2A2A2C;
    private static final int TEXT = 0xFFFFFFFF;
    private static final int MUTED = 0xFF9A9A9A;
    private static final int GREEN = 0xFF2FD06B;
    private static final int GREEN_DARK = 0xFF123D24;
    private static final int RED = 0xFFFF5C5C;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final SimpleDateFormat clock = new SimpleDateFormat("HH:mm:ss", Locale.US);

    private IUserService service;
    private boolean bound;
    private boolean rootOpen;

    private LinearLayout statusCard;
    private TextView statusTitle;
    private TextView statusSubtitle;
    private TextView statusBadge;
    private TextView detailModel;
    private TextView detailKernel;
    private TextView detailKsud;
    private TextView detailKsu;
    private TextView detailSelinux;
    private TextView detailSeccomp;
    private TextView logText;
    private LinearLayout homePage;
    private LinearLayout logPage;
    private TextView tabHome;
    private TextView tabLog;
    private String ksud = "-";
    private String ksu = "unknown";
    private String selinux = "-";
    private String seccomp = "-";

    private final ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            service = IUserService.Stub.asInterface(binder);
            bound = true;
            addLog("用户服务已连接");
            refreshDetails();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            service = null;
            bound = false;
            addLog("用户服务已断开");
            refreshDetails();
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(TAG, "onCreate");

        final FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(BG);
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            v.setPadding(0, insets.getSystemWindowInsetTop(), 0,
                    insets.getSystemWindowInsetBottom());
            return insets;
        });

        homePage = buildHome();
        logPage = buildLog();
        logPage.setVisibility(View.GONE);

        FrameLayout.LayoutParams fill = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT);
        fill.bottomMargin = dp(58);
        root.addView(homePage, fill);
        root.addView(logPage, fill);

        LinearLayout bottom = buildBottomBar();
        FrameLayout.LayoutParams barParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(58), Gravity.BOTTOM);
        root.addView(bottom, barParams);

        setContentView(root);
        showTab(0);
        refreshDetails();
        addLog("TimerRoot 已就绪");
        if (safePing() && safePermission() == 0) {
            bindService();
        }
    }

    // ------------------------------------------------------------------ UI

    private LinearLayout buildHome() {
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setBackgroundColor(BG);

        ScrollView scroll = new ScrollView(this);
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(16), dp(12), dp(16), dp(16));
        scroll.addView(body);
        page.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        TextView title = new TextView(this);
        title.setText("TimerRoot Neo7");
        title.setTextColor(TEXT);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 26);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        header.addView(title, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        header.addView(pill("重启", RED, CARD, v -> reboot()));
        body.addView(header);
        body.addView(spacer(12));

        statusCard = new LinearLayout(this);
        statusCard.setOrientation(LinearLayout.HORIZONTAL);
        statusCard.setGravity(Gravity.CENTER_VERTICAL);
        statusCard.setPadding(dp(18), dp(18), dp(18), dp(18));
        statusCard.setBackground(cardBackground(CARD));
        LinearLayout texts = new LinearLayout(this);
        texts.setOrientation(LinearLayout.VERTICAL);
        statusTitle = new TextView(this);
        statusTitle.setText("未连接");
        statusTitle.setTextColor(TEXT);
        statusTitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 22);
        statusTitle.setTypeface(Typeface.DEFAULT_BOLD);
        statusSubtitle = new TextView(this);
        statusSubtitle.setText("请先启动 Shizuku");
        statusSubtitle.setTextColor(0xFFBFD8C6);
        statusSubtitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        texts.addView(statusTitle);
        texts.addView(spacer(4));
        texts.addView(statusSubtitle);
        statusCard.addView(texts, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        statusBadge = new TextView(this);
        statusBadge.setText("?");
        statusBadge.setTextColor(GREEN);
        statusBadge.setTextSize(TypedValue.COMPLEX_UNIT_SP, 44);
        statusBadge.setTypeface(Typeface.DEFAULT_BOLD);
        statusCard.addView(statusBadge);
        body.addView(statusCard);
        body.addView(spacer(14));

        LinearLayout details = new LinearLayout(this);
        details.setOrientation(LinearLayout.VERTICAL);
        details.setBackground(cardBackground(CARD));
        detailModel = addRow(details, "机型", "-", true);
        detailKernel = addRow(details, "内核", "-", true);
        detailKsud = addRow(details, "ksud", "-", true);
        detailKsu = addRow(details, "KernelSU", "-", true);
        detailSelinux = addRow(details, "SELinux", "-", true);
        detailSeccomp = addRow(details, "Seccomp", "-", false);
        body.addView(details);
        body.addView(spacer(14));

        LinearLayout tools = new LinearLayout(this);
        tools.setOrientation(LinearLayout.HORIZONTAL);
        tools.addView(pill("Shizuku", TEXT, CARD, v -> showShizuku()), rowParams());
        tools.addView(pill("准备", TEXT, CARD, v -> prepare()), rowParams());
        tools.addView(pill("诊断", TEXT, CARD, v -> run("ids", "ids")), rowParams());
        tools.addView(pill("日志", TEXT, CARD, v -> showTab(1)), rowParams());
        body.addView(tools);

        LinearLayout tools2 = new LinearLayout(this);
        tools2.setOrientation(LinearLayout.HORIZONTAL);
        tools2.addView(pill("自检", TEXT, CARD, v -> selfCheck()), rowParams());
        tools2.addView(pill("root 命令", TEXT, CARD, v -> rootdPrompt()), rowParams());
        body.addView(tools2);

        LinearLayout tools3 = new LinearLayout(this);
        tools3.setOrientation(LinearLayout.HORIZONTAL);
        tools3.addView(pill("上次日志", TEXT, CARD, v -> showLastRun()), rowParams());
        tools3.addView(pill("导入配置", TEXT, CARD, v -> pickConf()), rowParams());
        tools3.addView(pill("推导配置", TEXT, CARD, v -> pickImage()), rowParams());
        body.addView(tools3);

        body.addView(bigButton("获取 root Shell", GREEN, 0xFF04140A, v -> confirmRoot()));
        body.addView(spacer(8));
        body.addView(bigButton("加载 KernelSU", 0xFF1F7A3D, 0xFFE8FFF0, v -> confirmKsu()));
        body.addView(spacer(8));
        body.addView(bigButton("停止", CARD, RED, v -> stopRoot()));

        body.addView(spacer(18));
        body.addView(smallHint("第一次使用：先授权 Shizuku，再点「准备」。准备会把 Neo7 的漏洞程序和与 uname -r 匹配的配置写入设备。"
                + "「诊断」只跑事件 id 发现，不触发漏洞；日志里要能看到 burst hit=1 才算真正命中。"));
        body.addView(spacer(8));



        return page;
    }

    private LinearLayout buildLog() {
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setBackgroundColor(BG);
        page.setPadding(dp(16), dp(12), dp(16), dp(8));

        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        TextView title = new TextView(this);
        title.setText("日志");
        title.setTextColor(TEXT);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 26);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        header.addView(title, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        header.addView(pill("导出", TEXT, CARD, v -> exportLog()));
        header.addView(pill("复制", TEXT, CARD, v -> copyLog()));
        header.addView(pill("清空", TEXT, CARD, v -> {
            logText.setText("");
            addLog("日志已清空");
        }));
        page.addView(header);
        page.addView(spacer(12));

        logText = new TextView(this);
        logText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        logText.setTypeface(Typeface.MONOSPACE);
        logText.setTextColor(0xFFD6D6D6);
        logText.setTextIsSelectable(true);
        ScrollView scroll = new ScrollView(this);
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(14), dp(14), dp(14), dp(14));
        card.setBackground(cardBackground(CARD));
        card.addView(logText);
        scroll.addView(card);
        page.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return page;
    }

    private LinearLayout buildBottomBar() {
        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setBackgroundColor(0xFF141416);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        tabHome = tab("Home", v -> showTab(0));
        tabLog = tab("Log", v -> showTab(1));
        bar.addView(tabHome, rowParams());
        bar.addView(tabLog, rowParams());
        return bar;
    }

    private void showTab(int index) {
        homePage.setVisibility(index == 0 ? View.VISIBLE : View.GONE);
        logPage.setVisibility(index == 1 ? View.VISIBLE : View.GONE);
        tabHome.setTextColor(index == 0 ? GREEN : MUTED);
        tabLog.setTextColor(index == 1 ? GREEN : MUTED);
    }

    // ------------------------------------------------------------ widgets

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density);
    }

    private View spacer(int height) {
        View view = new View(this);
        view.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(height)));
        return view;
    }

    private LinearLayout.LayoutParams rowParams() {
        return new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
    }

    private GradientDrawable cardBackground(int color) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(dp(24));
        if (color == GREEN_DARK) {
            drawable.setGradientType(GradientDrawable.LINEAR_GRADIENT);
            drawable.setOrientation(GradientDrawable.Orientation.LEFT_RIGHT);
            drawable.setColors(new int[]{0xFF0F3A22, 0xFF1E7A46});
        }
        return drawable;
    }

    private TextView pill(String text, int color, int background, View.OnClickListener click) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextColor(color);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        view.setPadding(dp(14), dp(8), dp(14), dp(8));
        view.setGravity(Gravity.CENTER);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(background);
        bg.setCornerRadius(dp(18));
        view.setBackground(bg);
        view.setOnClickListener(click);
        return view;
    }

    private TextView tab(String text, View.OnClickListener click) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextColor(MUTED);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        view.setGravity(Gravity.CENTER);
        view.setOnClickListener(click);
        return view;
    }

    private TextView bigButton(String text, int background, int color,
                               View.OnClickListener click) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextColor(color);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        view.setTypeface(Typeface.DEFAULT_BOLD);
        view.setGravity(Gravity.CENTER);
        view.setPadding(dp(16), dp(16), dp(16), dp(16));
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(background);
        bg.setCornerRadius(dp(26));
        view.setBackground(bg);
        view.setOnClickListener(click);
        return view;
    }

    private TextView smallHint(String text) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextColor(MUTED);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        view.setLineSpacing(dp(3), 1f);
        return view;
    }

    private TextView addRow(LinearLayout parent, String label, String value,
                            boolean divider) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(dp(16), dp(12), dp(16), dp(12));

        LinearLayout texts = new LinearLayout(this);
        texts.setOrientation(LinearLayout.VERTICAL);
        TextView name = new TextView(this);
        name.setText(label);
        name.setTextColor(TEXT);
        name.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        name.setTypeface(Typeface.DEFAULT_BOLD);
        TextView val = new TextView(this);
        val.setText(value);
        val.setTextColor(MUTED);
        val.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        texts.addView(name);
        texts.addView(spacer(2));
        texts.addView(val);
        row.addView(texts, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        parent.addView(row);
        if (divider) {
            View line = new View(this);
            line.setBackgroundColor(LINE);
            parent.addView(line, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, 1));
        }
        return val;
    }

    // ------------------------------------------------------------- state

    private void refreshDetails() {
        detailModel.setText(Build.MODEL + " / " + Build.PRODUCT);
        detailKernel.setText(System.getProperty("os.version", "?"));
        if (service != null) {
            new Thread(() -> {
                try {
                    parseInfo(service.info());
                    ui.post(this::applyDetails);
                } catch (Throwable t) {
                    Log.i(TAG, "info failed: " + t);
                }
            }).start();
        }
        applyDetails();
    }

    private String serviceBuild = "";

    private void parseInfo(String raw) {
        for (String line : raw.split("\n")) {
            int eq = line.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String key = line.substring(0, eq);
            String value = line.substring(eq + 1).trim();
            if (key.equals("selinux")) {
                selinux = value;
            } else if (key.equals("seccomp")) {
                seccomp = value;
            } else if (key.equals("ksud")) {
                ksud = value;
            } else if (key.equals("ksu")) {
                ksu = value;
            } else if (key.equals("build") && !value.equals(serviceBuild)) {
                serviceBuild = value;
                addLog("用户服务版本：" + value);
            }
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshDetails();
    }

    private void applyDetails() {
        if (statusCard != null) {
            statusCard.setBackground(cardBackground(
                    rootOpen || "active".equals(ksu) ? GREEN_DARK : CARD));
        }
        detailKsud.setText("not loaded".equals(ksud) ? "未加载"
                : ("missing".equals(ksud) ? "缺失" : ksud));
        detailKsu.setText("active".equals(ksu) ? "越狱模式（u:r:ksu:s0）" : "未启用");
        detailSelinux.setText(selinux);
        detailSeccomp.setText(seccomp);
        boolean shizuku = safePing();
        if ("active".equals(ksu)) {
            statusTitle.setText("越狱模式");
            statusSubtitle.setText("KernelSU 已加载 · su 为 u:r:ksu:s0 · 重启后失效");
            statusBadge.setText("✓");
            statusBadge.setTextColor(GREEN);
        } else if (rootOpen) {
            statusTitle.setText("Root Shell");
            statusSubtitle.setText("uid=0 · u:r:shell:s0 · 重启后失效");
            statusBadge.setText("✓");
            statusBadge.setTextColor(GREEN);
        } else if (shizuku && bound) {
            statusTitle.setText("就绪");
            statusSubtitle.setText("Shizuku 已连接 · 尚未提权");
            statusBadge.setText("•");
            statusBadge.setTextColor(MUTED);
        } else {
            statusTitle.setText("未连接");
            statusSubtitle.setText(shizuku
                    ? (safePermission() == 0
                        ? "Shizuku is running · connecting..."
                        : "Shizuku is running · grant permission")
                    : "Start Shizuku first");
            statusBadge.setText("?");
            statusBadge.setTextColor(MUTED);
        }
    }

    private boolean safePing() {
        try {
            return Shizuku.pingBinder();
        } catch (Throwable t) {
            return false;
        }
    }

    private void showShizuku() {
        StringBuilder sb = new StringBuilder();
        try {
            sb.append("running: ").append(Shizuku.pingBinder()).append('\n');
            sb.append("permission: ").append(Shizuku.checkSelfPermission()).append('\n');
            sb.append("pre-v11: ").append(Shizuku.isPreV11()).append('\n');
            sb.append("bound: ").append(bound);
        } catch (Throwable t) {
            sb.append("Shizuku not available: ").append(t);
        }
        addLog(sb.toString());
        if (safePing() && safePermission() != 0) {
            try {
                Shizuku.requestPermission(REQUEST_CODE);
                addLog("已请求权限");
            } catch (Throwable t) {
                addLog("请求权限失败：" + t);
            }
        } else if (safePing() && !bound) {
            bindService();
        }
    }

    private int safePermission() {
        try {
            return Shizuku.checkSelfPermission();
        } catch (Throwable t) {
            return -1;
        }
    }

    /**
     * 在已打开的 root shell 里跑一组只读检查：caps、SELinux 域、/data 访问、
     * su / ksud 是否存在。用来判断这份 uid=0 到底能干什么，以及 KSU 链路的前置条件。
     */
    private static final int REQ_CONF = 0x0C0F;

    /**
     * 选一份 conf 导入。conf 由 PC 侧的 cve98260_auto.py 从 boot.img 生成，
     * 或者手工写；导入后下次「准备」按 release 匹配自动取用，不用重新打包 APK。
     */
    private static final int REQ_IMG = 0x0C10;

    /**
     * 选一份 boot.img，在设备上直接推导 conf（不用 PC）。
     *
     * 解析跑在 [com.kpgc.timerroot.ota.Deriver] 里（Kotlin，反射调用）：
     * carve → kallsyms → 反汇编 call site → BTF。推导结果和 PC 版
     * cve98260_auto.py 的 20 个字段逐项一致（Neo7 / GT6 都对拍过）。
     */
    private void pickImage() {
        if (service == null) {
            toast("请先绑定服务");
            return;
        }
        try {
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            startActivityForResult(i, REQ_IMG);
        } catch (Throwable t) {
            addLog("打不开文件选择器：" + t);
        }
    }

    private void deriveFromImage(Uri uri, String fileName) {
        new Thread(() -> {
            File tmp = new File(getCacheDir(), "boot.img");
            try {
                addLog("正在读取 " + fileName + " …");
                long total = 0;
                try (InputStream in = getContentResolver().openInputStream(uri);
                     FileOutputStream out = new FileOutputStream(tmp)) {
                    if (in == null) {
                        addLog("推导失败：读不到文件");
                        return;
                    }
                    byte[] buf = new byte[1 << 20];
                    int n;
                    while ((n = in.read(buf)) > 0) {
                        out.write(buf, 0, n);
                        total += n;
                        if (total > 512L * 1024 * 1024) {
                            addLog("推导失败：文件超过 512 MB，不像是 boot.img");
                            return;
                        }
                    }
                }
                addLog("镜像已就位（" + total + " 字节），开始解析，可能要几十秒…");
                Class<?> c = Class.forName("com.kpgc.timerroot.ota.Deriver");
                Object r = c.getMethod("derive", String.class).invoke(null, tmp.getAbsolutePath());
                String text = String.valueOf(r);
                if (text.startsWith("ERR:")) {
                    addLog("推导失败：" + text.substring(4).trim());
                    return;
                }
                Matcher m = Pattern.compile("(?m)^\\s*release\\s*=\\s*\"([^\"]+)\"")
                        .matcher(text);
                String rel = m.find() ? m.group(1) : "derived";
                String res = service.importConf(rel + ".conf", text);
                addLog("推导完成（release=" + rel + "）\n" + res);
                ui.post(() -> toast("已生成并导入：" + rel));
            } catch (ClassNotFoundException e) {
                addLog("此构建没有内置推导（编译时未找到 kotlinc）；"
                        + "请用 PC 的 cve98260_auto.py 生成后再点「导入配置」");
            } catch (Throwable t) {
                addLog("推导失败：" + t);
            } finally {
                //noinspection ResultOfMethodCallIgnored
                tmp.delete();
            }
        }).start();
    }

    private void pickConf() {
        if (service == null) {
            toast("请先绑定服务");
            return;
        }
        try {
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            startActivityForResult(i, REQ_CONF);
        } catch (Throwable t) {
            addLog("打不开文件选择器：" + t);
        }
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if ((request != REQ_CONF && request != REQ_IMG) || result != RESULT_OK
                || data == null || data.getData() == null) {
            return;
        }
        final Uri uri = data.getData();
        String name = "imported.conf";
        try (Cursor c = getContentResolver().query(uri, null, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (idx >= 0) {
                    String s = c.getString(idx);
                    if (s != null && !s.isEmpty()) {
                        name = s;
                    }
                }
            }
        } catch (Throwable ignored) {
            // 名字拿不到就退回默认名，conf 里的 release 才是关键
        }
        final String fileName = name;
        if (request == REQ_IMG) {
            deriveFromImage(uri, fileName);
            return;
        }
        new Thread(() -> {
            try (java.io.InputStream in = getContentResolver().openInputStream(uri)) {
                if (in == null) {
                    addLog("导入失败：读不到文件");
                    return;
                }
                java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) {
                    bos.write(buf, 0, n);
                    if (bos.size() > 256 * 1024) {
                        addLog("导入失败：文件超过 256 KB，不像 conf");
                        return;
                    }
                }
                String text = new String(bos.toByteArray(), "UTF-8");
                String r = service.importConf(fileName, text);
                addLog(r);
                ui.post(() -> toast(r.split("\n")[0]));
            } catch (Throwable t) {
                addLog("导入失败：" + t);
            }
        }).start();
    }

    /**
     * 读上一次运行的原生日志。走 App 私有外部目录，不需要 Shizuku、不需要权限，
     * 所以重启后第一件事就能看上一轮到底死在哪一行。
     */
    private void showLastRun() {
        File f = new File(getExternalFilesDir(null), "last-run.log");
        if (!f.isFile() || f.length() == 0) {
            addLog("没有上一次的日志（" + f.getAbsolutePath() + "）");
            return;
        }
        try (java.io.FileInputStream in = new java.io.FileInputStream(f)) {
            int len = (int) Math.min(f.length(), 256 * 1024);
            byte[] b = new byte[len];
            int n = 0;
            while (n < len) {
                int r = in.read(b, n, len - n);
                if (r <= 0) {
                    break;
                }
                n += r;
            }
            addLog("===== 上次运行（" + f.length() + " 字节）=====");
            addLog(new String(b, 0, n, "UTF-8").trim());
        } catch (Throwable t) {
            addLog("读取上次日志失败：" + t);
        }
    }

    /** rootd 命令输入框：只对 fake 路线成功后的开机有效。 */
    private void rootdPrompt() {
        if (service == null) {
            toast("请先绑定服务");
            return;
        }
        final EditText input = new EditText(this);
        input.setText("id");
        input.setTextSize(14);
        new AlertDialog.Builder(this)
                .setTitle("通过 rootd 执行")
                .setMessage("只在「加载 KernelSU」成功那次开机内有效；重启后失效。")
                .setView(input)
                .setPositiveButton("执行", (d, w) -> runRootd(input.getText().toString()))
                .setNegativeButton("取消", null)
                .show();
    }

    private void runRootd(String cmd) {
        if (cmd == null || cmd.trim().isEmpty()) {
            return;
        }
        new Thread(() -> {
            try {
                String out = service.rootdExec(cmd.trim());
                addLog("$ " + cmd.trim() + "\n" + (out == null ? "" : out.trim()));
            } catch (Throwable t) {
                addLog("rootd 失败：" + t);
            }
        }).start();
    }

    private void selfCheck() {
        if (service == null) {
            toast("请先绑定服务");
            return;
        }
        new Thread(() -> {
            try {
                String out = service.execRoot(
                        "id;"
                        + " grep -E '^(Uid|Gid|Cap)' /proc/self/status;"
                        + " cat /proc/self/attr/current;"
                        + " echo '-- /data --'; ls -ld /data/data /data/adb 2>&1;"
                        + " echo '-- su --'; ls -l /system/bin/su /data/adb/ksu/bin/ksud 2>&1");
                addLog("自检结果：\n" + out.trim());
                ui.post(() -> toast("自检完成，见日志"));
            } catch (Throwable t) {
                addLog("自检失败：" + t);
            }
        }).start();
    }

    private void prepare() {
        if (!safePing()) {
            new AlertDialog.Builder(this)
                    .setTitle("Shizuku 未运行")
                    .setMessage("请先启动 Shizuku：\n\n"
                            + "1. 打开 Shizuku 应用\n"
                            + "2. 用「无线调试」启动（或通过 USB 配对启动）\n"
                            + "3. 回到这里再点一次「准备」")
                    .setPositiveButton("确定", null)
                    .show();
            return;
        }
        if (service == null) {
            bindService();
            toast("正在连接 Shizuku…");
            return;
        }
        toast("正在准备…");
        new Thread(() -> {
            try {
                final String result = service.install(getPackageCodePath());
                addLog(result);
                ui.post(() -> {
                    toast(result);
                    refreshDetails();
                });
            } catch (Throwable t) {
                addLog("准备失败：" + t);
                ui.post(() -> toast("准备失败：" + t));
            }
        }).start();
    }

    private void toast(String text) {
        Toast.makeText(this, text, Toast.LENGTH_SHORT).show();
    }

    private void confirmRoot() {
        new AlertDialog.Builder(this)
                .setTitle("获取 root Shell？")
                .setMessage("运行一次 CVE-2026-98260，并保持一个 uid=0 的 shell。\n\n"
                        + "- 失败时进程会挂起（park），只有重启能清理\n"
                        + "- 重启后 root 消失\n"
                        + "- 运行期间不要操作设备")
                .setPositiveButton("运行", (d, w) -> runRoot())
                .setNegativeButton("取消", null)
                .show();
    }

    private void runRoot() {
        if (service == null) {
            addLog("请先绑定服务");
            return;
        }
        new Thread(() -> {
            try {
                // Always (re)install before running: the binary may not exist
                // yet (Prepare skipped) or may have been replaced by a new build.
                String inst = service.install(getPackageCodePath());
                addLog(inst);
                if (inst.startsWith("安装失败") || inst.contains("conf=none")) {
                    addLog("准备未完成，不启动提权");
                    ui.post(() -> {
                        toast(inst);
                        refreshDetails();
                    });
                    return;
                }
                String out = service.openRoot();
                rootOpen = out.startsWith("已获得 root");
                addLog(out);
                ui.post(this::applyDetails);
                if (rootOpen && !"active".equals(ksu)) {
                    // Do not auto-load KernelSU: the fake-cred stage needs its
                    // own verified conf fields and parks on failure. Keep it a
                    // manual, deliberate second step.
                    addLog("已获得 root Shell —— KernelSU 是需要手动执行的第二步");
                }
            } catch (Throwable t) {
                addLog("提权失败：" + t);
            }
        }).start();
    }

    private void confirmKsu() {
        new AlertDialog.Builder(this)
                .setTitle("加载 KernelSU？")
                .setMessage("用伪造的 cred 走一次 ksud late-load。\n\n"
                        + "- 成功后 su 可在 u:r:ksu:s0 下使用\n"
                        + "- 父进程会挂起（park），需要重启清理\n"
                        + "- 运行期间不要操作设备")
                .setPositiveButton("运行", (d, w) -> runKsu())
                .setNegativeButton("取消", null)
                .show();
    }

    private long ksuStartedAt;

    private void runKsu() {
        if (service == null) {
            addLog("请先绑定服务");
            return;
        }
        /*
         * 22:32 那次日志里出现了两条一模一样的流程（:27 和 :28）——
         * 重复点击会让两个 glk 进程各自 park，白白浪费一次开机。
         * 两分钟内直接忽略。
         */
        if (System.currentTimeMillis() - ksuStartedAt < 120_000L) {
            addLog("KernelSU 流程刚跑过，忽略这次点击（失败请先重启）");
            return;
        }
        ksuStartedAt = System.currentTimeMillis();
        new Thread(() -> {
            try {
                // The fake stage re-execs the binary from /data/local/tmp; if
                // the user never pressed Prepare, that path does not exist yet.
                String inst = service.install(getPackageCodePath());
                addLog(inst);
                if (inst.startsWith("安装失败") || inst.contains("conf=none")) {
                    addLog("准备未完成，不加载 KernelSU");
                    return;
                }
                String first = service.runDetached("fake");
                addLog(first);
                // runDetached 只带回启动后 2 秒的内容；后面整段在文件里，
                // 不主动拉就会在一次 park 之后全部丢掉。
                int seen = first.length();
                final long start = System.currentTimeMillis();
                boolean loaded = false;
                String failure = null;
                while (System.currentTimeMillis() - start < 90000) {
                    Thread.sleep(1000);
                    String tail = service.readLog();
                    if (tail.length() > seen) {
                        addLog(tail.substring(seen).trim());
                        seen = tail.length();
                    }
                    if (tail.contains("KSU_LOADED")) {
                        loaded = true;
                        break;
                    }
                    if (tail.contains("selinux write failed")) {
                        failure = "the selinux stage missed its race";
                        break;
                    }
                    if (tail.contains("parking without reap")) {
                        failure = "the exploit parked before loading ksud";
                        break;
                    }
                    final long secs = (System.currentTimeMillis() - start) / 1000;
                    if (secs % 5 == 0) {
                        ui.post(() -> {
                            if (statusSubtitle != null) {
                                statusSubtitle.setText("正在加载 KernelSU… " + secs + " 秒");
                            }
                        });
                    }
                }
                if (!loaded && failure == null) {
                    failure = "timed out after 90s";
                }
                if (!loaded) {
                    // park 之后进程会一直挂着，先把 UI 日志 + 原生日志一起导出
                    addLog(service.exportLog(uiLogText()));
                }
                if (loaded) {
                    parseInfo(service.info());
                }
                /*
                 * 只追加 seen 之后的部分。原来这里直接 addLog(readLog())，
                 * 会把整个文件再贴一遍 —— 23:21 / 23:22 的日志里整段重复
                 * 就是这个（同一个 pid 出现两次全流程）。
                 */
                String rest = service.readLog();
                if (rest.length() > seen) {
                    addLog(rest.substring(seen).trim());
                    seen = rest.length();
                }
                final String suOut = loaded ? service.suCheck() : "";
                if (loaded) {
                    addLog("—— 验证 su ——\n" + suOut.trim());
                }
                final boolean ok = loaded;
                final boolean suOk = suOut.contains("u:r:ksu:s0");
                final String reason = failure;
                ui.post(() -> {
                    applyDetails();
                    if (ok) {
                        toast(suOk ? "KernelSU 已加载，su 可用（u:r:ksu:s0）"
                                : "KernelSU 已加载，但 su 还没通过验证，看日志");
                        refreshDetails();
                    } else {
                        statusTitle.setText("KernelSU 失败");
                        statusSubtitle.setText(reason + " - reboot, then retry");
                        statusBadge.setText("!");
                        statusBadge.setTextColor(RED);
                        toast("KernelSU 失败：" + reason);
                        addLog("KernelSU 失败：" + reason
                                + " - parked processes remain; reboot to clean up");
                    }
                });
            } catch (Throwable t) {
                addLog("KernelSU 执行失败：" + t);
            }
        }).start();
    }

    private void stopRoot() {
        if (service == null) {
            return;
        }
        new Thread(() -> {
            try {
                addLog(service.closeRoot());
                rootOpen = false;
                ui.post(this::applyDetails);
            } catch (Throwable t) {
                addLog("停止失败：" + t);
            }
        }).start();
    }

    private void reboot() {
        new AlertDialog.Builder(this)
                .setTitle("重启设备？")
                .setMessage("这是清理挂起（park）进程的唯一办法。")
                .setPositiveButton("重启", (d, w) -> {
                    if (service == null) {
                        toast("请先绑定服务");
                        return;
                    }
                    new Thread(() -> {
                        try {
                            final String result = service.rebootDevice();
                            ui.post(() -> toast(result));
                        } catch (Throwable t) {
                            ui.post(() -> toast("reboot failed: " + t));
                        }
                    }).start();
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void run(String label, String args) {
        if (service == null) {
            addLog("请先绑定服务");
            return;
        }
        new Thread(() -> {
            try {
                addLog("[" + label + "]\n" + service.run(args));
            } catch (Throwable t) {
                addLog("[" + label + "] failed: " + t);
            }
        }).start();
    }

    // ------------------------------------------------------------ plumbing

    private void bindService() {
        try {
            // bindUserService() throws SecurityException while the permission
            // is still denied; ask for it instead of logging a failure.
            if (safePermission() != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                Shizuku.requestPermission(REQUEST_CODE);
                addLog("已请求权限，授权后会自动连接");
                return;
            }
            Shizuku.bindUserService(serviceArgs(), connection);
            addLog("正在连接用户服务…");
        } catch (Throwable t) {
            addLog("绑定失败：" + t);
        }
    }

    private Shizuku.UserServiceArgs serviceArgs() {
        return new Shizuku.UserServiceArgs(
                new ComponentName(getPackageName(), UserService.class.getName()))
                .daemon(false)
                .processNameSuffix("timer")
                .debuggable(false)
                /*
                 * 每次改 IUserService 都要 +1：Shizuku 只按这个数字判断能不能复用
                 * 已经跑着的用户服务进程，数字不变就会拿到旧进程的 binder，
                 * 新加的 AIDL 方法在旧进程里不存在（表现为 unknown transaction）。
                 * 7 -> 8：importConf
                 */
                .version(8);
    }

    /** 当前 UI 上的全部日志（导出和复制都用它）。 */
    private String uiLogText() {
        String text = logText == null ? "" : logText.getText().toString();
        // Binder 事务上限 1 MB，留一半余量
        return text.length() > 512 * 1024 ? text.substring(text.length() - 512 * 1024) : text;
    }

    private void exportLog() {
        if (service == null) {
            toast("请先绑定服务");
            return;
        }
        final String text = uiLogText();
        new Thread(() -> {
            try {
                String r = service.exportLog(text);
                addLog(r);
                ui.post(() -> toast(r));
            } catch (Throwable t) {
                addLog("导出失败：" + t);
            }
        }).start();
    }

    private void copyLog() {
        try {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText("TimerRoot", uiLogText()));
                addLog("log copied");
            }
        } catch (Throwable t) {
            addLog("copy failed: " + t);
        }
    }

    private void addLog(String text) {
        String stamp = clock.format(new Date());
        StringBuilder sb = new StringBuilder();
        for (String line : text.split("\n")) {
            sb.append(stamp).append("  ").append(line).append('\n');
        }
        Log.i(TAG, text.replace('\n', ' '));
        ui.post(() -> {
            if (logText != null) {
                logText.append(sb.toString());
            }
        });
    }
}