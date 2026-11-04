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
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;

import rikka.shizuku.Shizuku;

import java.lang.reflect.Method;

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

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final SimpleDateFormat clock = new SimpleDateFormat("HH:mm:ss", Locale.US);

    private IUserService service;
    private boolean bound;
    /** 准备阶段正在跑，防止自动+手动同时触发两次 install。 */
    private boolean preparing;
    /** 本次进程是否已经自动准备过（失败也置位，避免反复清后台）。 */
    private boolean autoPrepared;
    private boolean rootOpen;

    // ---- 状态总览卡 (A) ----
    private TextView statusTitle;
    private TextView statusSubtitle;
    private TextView statusSummary;

    // ---- 引导/依赖卡 (B) ----
    private LinearLayout guideCard;
    private TextView[] stepDots;
    private TextView[] stepLabels;
    private LinearLayout guideBanner;
    private TextView bannerText;

    // ---- 主操作区 (C) ----
    private TextView actionShellOnlyBtn;
    private TextView actionShellOnlyHint;
    private TextView actionOneTapBtn;
    private TextView actionOneTapHint;
    private TextView actionStopBtn;

    // ---- 设备详情卡 (D) ----
    private LinearLayout detailBody;
    private TextView detailChevron;
    private TextView detailModel;
    private TextView detailKernel;
    private TextView detailKernelVer;
    private TextView detailKsud;
    private TextView detailKsu;
    private TextView detailMgr;
    private TextView detailVivo;
    private TextView detailSelinux;
    private TextView detailSeccomp;
    private TextView detailRootState;

    // ---- 日志 (Log 页) ----
    private TextView logText;
    private LinearLayout homePage;
    private LinearLayout logPage;
    private TextView tabHome;
    private TextView tabLog;
    private ScrollView logScroll;
    private boolean autoScroll = true;
    private TextView backToBottomBtn;
    private FrameLayout logContainer;

    private String ksud = "-";
    private String ksu = "unknown";
    private String mgr = "auto";
    private String selinux = "-";
    private String seccomp = "-";

    private int colorBg;
    private int colorTextPrimary;
    private int colorTextSecondary;
    private int colorTextWeak;
    private int colorGreen;
    private int colorRed;
    private int colorAmber;

    private final ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            service = IUserService.Stub.asInterface(binder);
            bound = true;
            addLog("用户服务已连接");
            pushVivoMode();
            refreshDetails();
            maybeAutoPrepare();
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

        // 背景模糊：API 31+ 用窗口级模糊，API 30 降级为玻璃 solid alpha 提到 18%。
        // setBackgroundBlur* 是隐藏 API（@hide），不能直接引用（纯 SDK 编译会失败），
        // 故走反射，失败则静默降级为 solid alpha 玻璃。
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            applyBackgroundBlur();
        }

        loadColors();

        final FrameLayout root = new FrameLayout(this);
        // 背景：风景照（居中裁剪铺满），玻璃卡片叠在其上
        android.widget.ImageView bg = new android.widget.ImageView(this);
        bg.setScaleType(android.widget.ImageView.ScaleType.CENTER_CROP);
        bg.setImageResource(R.drawable.bg_landscape);
        bg.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        root.addView(bg, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
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

    private void loadColors() {
        colorBg = getResources().getColor(R.color.bg);
        colorTextPrimary = getResources().getColor(R.color.text_primary);
        colorTextSecondary = getResources().getColor(R.color.text_secondary);
        colorTextWeak = getResources().getColor(R.color.text_weak);
        colorGreen = getResources().getColor(R.color.state_green);
        colorRed = getResources().getColor(R.color.state_red);
        colorAmber = getResources().getColor(R.color.state_amber);
    }

    /** 反射调用 Window#setBackgroundBlurEnabled / setBackgroundBlurRadius（隐藏 API）。 */
    private void applyBackgroundBlur() {
        try {
            android.view.Window w = getWindow();
            Method enable = android.view.Window.class.getMethod("setBackgroundBlurEnabled", boolean.class);
            enable.invoke(w, true);
            Method radius = android.view.Window.class.getMethod("setBackgroundBlurRadius", int.class);
            radius.invoke(w, 64);
        } catch (Throwable t) {
            Log.i(TAG, "background blur unavailable (fallback to solid alpha): " + t);
        }
    }

    // ------------------------------------------------------------------ UI

    private LinearLayout buildHome() {
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setBackgroundColor(android.graphics.Color.TRANSPARENT);

        ScrollView scroll = new ScrollView(this);
        scroll.setVerticalScrollBarEnabled(false);
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(20), dp(12), dp(20), dp(20));
        scroll.addView(body);
        page.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        // 大标题
        TextView title = new TextView(this);
        title.setText(R.string.title_home);
        title.setTextColor(colorTextPrimary);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 28);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        title.setLineSpacing(0f, 1.3f);
        body.addView(title);
        body.addView(spacer(12));

        // ---- A 状态总览卡（置顶不折叠） ----
        body.addView(buildStatusCard());
        body.addView(spacer(12));

        // ---- B 引导/依赖卡 ----
        guideCard = buildGuideCard();
        body.addView(guideCard);
        body.addView(spacer(12));

        // ---- C 主操作区 ----
        body.addView(buildActionsCard());
        body.addView(spacer(12));

        // ---- D 设备详情卡（默认折叠） ----
        body.addView(buildDetailsCard());
        body.addView(spacer(12));

        // ---- E 工具区 ----
        body.addView(buildToolsCard());

        return page;
    }

    private LinearLayout buildStatusCard() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(16), dp(16), dp(16), dp(16));
        card.setBackgroundResource(R.drawable.bg_glass_card);

        statusTitle = new TextView(this);
        statusTitle.setText(R.string.status_disconnected);
        statusTitle.setTextColor(colorTextPrimary);
        statusTitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 28);
        statusTitle.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        statusTitle.setLineSpacing(0f, 1.3f);
        card.addView(statusTitle);

        statusSubtitle = new TextView(this);
        statusSubtitle.setText(R.string.status_disconnected);
        statusSubtitle.setTextColor(colorTextSecondary);
        statusSubtitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        statusSubtitle.setLineSpacing(0f, 1.5f);
        card.addView(statusSubtitle);

        card.addView(spacer(8));

        statusSummary = new TextView(this);
        statusSummary.setTextColor(colorTextWeak);
        statusSummary.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        statusSummary.setLineSpacing(0f, 1.5f);
        card.addView(statusSummary);

        return card;
    }

    private LinearLayout buildGuideCard() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(16), dp(16), dp(16), dp(16));
        card.setBackgroundResource(R.drawable.bg_glass_card);

        TextView title = new TextView(this);
        title.setText(R.string.guide_title);
        title.setTextColor(colorTextPrimary);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 17);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        title.setLineSpacing(0f, 1.3f);
        card.addView(title);
        card.addView(spacer(12));

        // 3 步进度：Shizuku → 准备 → 一键 root + KernelSU
        String[] labels = {
                getString(R.string.step_shizuku),
                getString(R.string.step_prepare),
                getString(R.string.step_root)
        };
        stepDots = new TextView[labels.length];
        stepLabels = new TextView[labels.length];
        for (int i = 0; i < labels.length; i++) {
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(0, dp(6), 0, dp(6));

            TextView dot = new TextView(this);
            dot.setText("•");
            dot.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
            dot.setGravity(Gravity.CENTER);
            dot.setLayoutParams(new LinearLayout.LayoutParams(dp(24), dp(24)));
            dot.setTextColor(colorTextWeak);
            stepDots[i] = dot;
            row.addView(dot);

            TextView label = new TextView(this);
            label.setText(labels[i]);
            label.setTextColor(colorTextSecondary);
            label.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
            label.setLineSpacing(0f, 1.5f);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
            lp.leftMargin = dp(12);
            row.addView(label, lp);
            stepLabels[i] = label;

            card.addView(row);
        }

        card.addView(spacer(4));

        // 未授权时的琥珀提示条 + 去授权按钮（默认隐藏）
        guideBanner = new LinearLayout(this);
        guideBanner.setOrientation(LinearLayout.VERTICAL);
        guideBanner.setPadding(dp(12), dp(12), dp(12), dp(12));
        GradientDrawable bannerBg = new GradientDrawable();
        bannerBg.setColor(0x1AFFB020);
        bannerBg.setCornerRadius(dp(16));
        bannerBg.setStroke(dp(1), 0x33FFB020);
        guideBanner.setBackground(bannerBg);
        bannerText = new TextView(this);
        bannerText.setTextColor(colorAmber);
        bannerText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        bannerText.setLineSpacing(0f, 1.5f);
        guideBanner.addView(bannerText);
        guideBanner.addView(spacer(8));
        TextView grant = new TextView(this);
        grant.setText(R.string.grant_shizuku);
        grant.setTextColor(colorAmber);
        grant.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        grant.setGravity(Gravity.CENTER);
        grant.setPadding(dp(12), dp(10), dp(12), dp(10));
        GradientDrawable grantBg = new GradientDrawable();
        grantBg.setColor(0x26FFB020);
        grantBg.setCornerRadius(dp(999));
        grant.setBackground(grantBg);
        grant.setOnClickListener(v -> showShizuku());
        guideBanner.addView(grant);
        guideBanner.setVisibility(View.GONE);
        card.addView(guideBanner);

        return card;
    }

    private LinearLayout buildActionsCard() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(16), dp(16), dp(16), dp(16));
        card.setBackgroundResource(R.drawable.bg_glass_card);

        // 主路径：一次跑完 提权 + KernelSU（fake cred 那条本来就自带 rootd）
        actionOneTapBtn = actionButton(R.string.action_ksu, true, v -> confirmOneTap());
        card.addView(actionOneTapBtn);
        actionOneTapHint = actionHint(R.string.action_ksu);
        card.addView(actionOneTapHint);
        card.addView(spacer(10));

        // 备选：只要一个 uid=0 的 shell，不碰 KernelSU（调试/排障用）
        actionShellOnlyBtn = secondaryButton(R.string.action_root, v -> confirmShellOnly());
        card.addView(actionShellOnlyBtn);
        actionShellOnlyHint = actionHint(R.string.action_root);
        card.addView(actionShellOnlyHint);
        card.addView(spacer(12));

        // 停止
        actionStopBtn = actionButton(R.string.action_stop, false, v -> stopRoot());
        card.addView(actionStopBtn);
        card.addView(spacer(4));

        // 常驻风险提示
        TextView risk = new TextView(this);
        risk.setText(R.string.risk_hint);
        risk.setTextColor(colorTextWeak);
        risk.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        risk.setLineSpacing(0f, 1.5f);
        card.addView(risk);

        return card;
    }

    private TextView actionButton(int textRes, boolean primary, View.OnClickListener click) {
        TextView view = new TextView(this);
        view.setText(textRes);
        view.setTextColor(primary ? colorBg : 0xFFFFFFFF);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        view.setGravity(Gravity.CENTER);
        view.setPadding(dp(16), dp(14), dp(16), dp(14));
        view.setMinimumHeight(dp(48));
        view.setBackgroundResource(primary
                ? R.drawable.bg_primary_btn_selector : R.drawable.bg_danger_btn);
        view.setOnClickListener(click);
        return view;
    }

    /** 次级按钮：玻璃胶囊底，字号小一号，用来放"备选路径"。 */
    private TextView secondaryButton(int textRes, View.OnClickListener click) {
        TextView view = new TextView(this);
        view.setText(textRes);
        view.setTextColor(colorTextPrimary);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        view.setGravity(Gravity.CENTER);
        view.setPadding(dp(16), dp(12), dp(16), dp(12));
        view.setMinimumHeight(dp(48));
        view.setBackgroundResource(R.drawable.bg_glass_pill_selector);
        view.setOnClickListener(click);
        return view;
    }

    private TextView actionHint(int textRes) {
        TextView view = new TextView(this);
        view.setText(textRes);
        view.setTextColor(colorTextWeak);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        view.setLineSpacing(0f, 1.5f);
        view.setPadding(0, dp(4), 0, 0);
        return view;
    }

    private LinearLayout buildDetailsCard() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.bg_glass_card);

        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setPadding(dp(16), dp(14), dp(16), dp(14));
        header.setMinimumHeight(dp(48));

        TextView title = new TextView(this);
        title.setText(R.string.detail_title);
        title.setTextColor(colorTextPrimary);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 17);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        title.setLineSpacing(0f, 1.3f);
        header.addView(title, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        detailChevron = new TextView(this);
        detailChevron.setCompoundDrawablesWithIntrinsicBounds(0, 0, R.drawable.ic_chevron_down, 0);
        header.addView(detailChevron);

        header.setOnClickListener(v -> toggleDetails());
        card.addView(header);

        detailBody = new LinearLayout(this);
        detailBody.setOrientation(LinearLayout.VERTICAL);
        detailBody.setPadding(dp(16), 0, dp(16), dp(12));

        detailModel = addRow(detailBody, R.string.detail_model, "-");
        detailKernel = addRow(detailBody, R.string.detail_kernel, "-");
        detailKernelVer = addRow(detailBody, R.string.detail_kernel_ver, "-");
        detailKsud = addRow(detailBody, R.string.detail_ksud, "-");
        detailKsu = addRow(detailBody, R.string.detail_ksu, "-");
        detailSelinux = addRow(detailBody, R.string.detail_selinux, "-");
        detailSeccomp = addRow(detailBody, R.string.detail_seccomp, "-");
        detailRootState = addRow(detailBody, R.string.detail_root, "-");
        detailMgr = addRow(detailBody, R.string.detail_manager, "-");
        detailMgr.setText(describeManager());
        if (detailVivo != null) {
            detailVivo.setText(describeVivo());
        }
        ((View) detailMgr.getParent()).setOnClickListener(v -> showManagerPicker());

        detailVivo = addRow(detailBody, R.string.detail_vivo, "-");
        detailVivo.setText(describeVivo());
        ((View) detailVivo.getParent()).setOnClickListener(v -> showVivoPicker());

        card.addView(detailBody);

        // 默认折叠
        detailBody.setVisibility(View.GONE);
        return card;
    }

    private void toggleDetails() {
        boolean visible = detailBody.getVisibility() == View.VISIBLE;
        detailBody.setVisibility(visible ? View.GONE : View.VISIBLE);
        detailChevron.setRotation(visible ? 0f : 180f);
    }

    private LinearLayout buildToolsCard() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(16), dp(16), dp(16), dp(16));
        card.setBackgroundResource(R.drawable.bg_glass_card);

        // 配置类
        card.addView(toolGroupTitle(R.string.tool_config));
        LinearLayout cfg = new LinearLayout(this);
        cfg.setOrientation(LinearLayout.HORIZONTAL);
        cfg.addView(toolPill(R.string.tool_import, v -> pickConf()), rowParams());
        cfg.addView(spacerX(8));
        cfg.addView(toolPill(R.string.tool_derive, v -> pickImage()), rowParams());
        card.addView(cfg);
        LinearLayout cfg2 = new LinearLayout(this);
        cfg2.setOrientation(LinearLayout.HORIZONTAL);
        cfg2.addView(toolPill(R.string.tool_derive_ota, v -> promptOtaUrl()), rowParams());
        card.addView(spacer(8));
        card.addView(cfg2);
        card.addView(spacer(12));

        // 诊断类
        card.addView(toolGroupTitle(R.string.tool_diagnose));
        LinearLayout diag = new LinearLayout(this);
        diag.setOrientation(LinearLayout.HORIZONTAL);
        diag.addView(toolPill(R.string.tool_prepare, v -> prepare()), rowParams());
        diag.addView(spacerX(8));
        diag.addView(toolPill(R.string.tool_diag, v -> run("ids", "ids")), rowParams());
        diag.addView(spacerX(8));
        diag.addView(toolPill(R.string.tool_selfcheck, v -> selfCheck()), rowParams());
        card.addView(diag);
        card.addView(spacer(12));

        // 日志类
        card.addView(toolGroupTitle(R.string.tool_log));
        LinearLayout lg = new LinearLayout(this);
        lg.setOrientation(LinearLayout.HORIZONTAL);
        lg.addView(toolPill(R.string.tool_lastlog, v -> showLastRun()), rowParams());
        lg.addView(spacerX(8));
        lg.addView(toolPill(R.string.tool_rootcmd, v -> rootdPrompt()), rowParams());
        lg.addView(spacerX(8));
        lg.addView(toolPill(R.string.tool_shizuku, v -> showShizuku()), rowParams());
        card.addView(lg);

        return card;
    }

    private TextView toolGroupTitle(int textRes) {
        TextView view = new TextView(this);
        view.setText(textRes);
        view.setTextColor(colorTextWeak);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        view.setLineSpacing(0f, 1.3f);
        view.setPadding(0, 0, 0, dp(8));
        return view;
    }

    private TextView toolPill(int textRes, View.OnClickListener click) {
        TextView view = new TextView(this);
        view.setText(textRes);
        view.setTextColor(colorTextSecondary);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        view.setGravity(Gravity.CENTER);
        view.setPadding(dp(8), dp(12), dp(8), dp(12));
        view.setMinimumHeight(dp(48));
        view.setBackgroundResource(R.drawable.bg_glass_pill_selector);
        view.setOnClickListener(click);
        return view;
    }

    private View spacerX(int heightDp) {
        View v = new View(this);
        v.setLayoutParams(new LinearLayout.LayoutParams(dp(heightDp), 1));
        return v;
    }

    private LinearLayout buildLog() {
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setBackgroundColor(android.graphics.Color.TRANSPARENT);
        page.setPadding(dp(20), dp(12), dp(20), dp(12));

        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        TextView title = new TextView(this);
        title.setText(R.string.title_log);
        title.setTextColor(colorTextPrimary);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 28);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        title.setLineSpacing(0f, 1.3f);
        header.addView(title, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        header.addView(toolPill(R.string.log_export, v -> exportLog()));
        header.addView(spacerX(8));
        header.addView(toolPill(R.string.log_copy, v -> copyLog()));
        header.addView(spacerX(8));
        header.addView(toolPill(R.string.log_clear, v -> confirmClearLog()));
        page.addView(header);
        page.addView(spacer(12));

        logContainer = new FrameLayout(this);

        logText = new TextView(this);
        logText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        logText.setTypeface(Typeface.MONOSPACE);
        logText.setTextColor(colorTextSecondary);
        logText.setTextIsSelectable(true);
        logText.setLineSpacing(0f, 1.4f);

        logScroll = new ScrollView(this);
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(14), dp(14), dp(14), dp(14));
        card.setBackgroundResource(R.drawable.bg_glass_log);
        card.addView(logText);
        logScroll.addView(card);

        logScroll.setOnScrollChangeListener((v, sx, sy, osx, osy) -> {
            int diff = (logText.getHeight() - logScroll.getHeight() - sy);
            autoScroll = diff <= dp(40);
            backToBottomBtn.setVisibility(autoScroll ? View.GONE : View.VISIBLE);
        });

        logContainer.addView(logScroll, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        // 「回到底部」浮钮
        backToBottomBtn = new TextView(this);
        backToBottomBtn.setText(R.string.log_back_bottom);
        backToBottomBtn.setTextColor(colorBg);
        backToBottomBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        backToBottomBtn.setGravity(Gravity.CENTER);
        backToBottomBtn.setPadding(dp(14), dp(8), dp(14), dp(8));
        GradientDrawable fbBg = new GradientDrawable();
        fbBg.setColor(0xCC2FD06B);
        fbBg.setCornerRadius(dp(999));
        backToBottomBtn.setBackground(fbBg);
        backToBottomBtn.setOnClickListener(v -> scrollToBottom());
        FrameLayout.LayoutParams fbLp = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL);
        fbLp.bottomMargin = dp(12);
        backToBottomBtn.setVisibility(View.GONE);
        logContainer.addView(backToBottomBtn, fbLp);

        page.addView(logContainer, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return page;
    }

    private void scrollToBottom() {
        logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
        autoScroll = true;
        backToBottomBtn.setVisibility(View.GONE);
    }

    private void confirmClearLog() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.log_clear_title)
                .setMessage(R.string.log_clear_msg)
                .setPositiveButton(R.string.log_clear, (d, w) -> {
                    logText.setText("");
                    addLog(getString(R.string.log_clear_done));
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private LinearLayout buildBottomBar() {
        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setBackgroundColor(0xD9FFFFFF);   // 亮色磨砂底，深色 Tab 文字可读
        bar.setGravity(Gravity.CENTER_VERTICAL);
        tabHome = tab(R.string.tab_home, v -> showTab(0));
        tabLog = tab(R.string.tab_log, v -> showTab(1));
        bar.addView(tabHome, rowParams());
        bar.addView(tabLog, rowParams());
        return bar;
    }

    private void showTab(int index) {
        homePage.setVisibility(index == 0 ? View.VISIBLE : View.GONE);
        logPage.setVisibility(index == 1 ? View.VISIBLE : View.GONE);
        tabHome.setTextColor(index == 0 ? colorGreen : colorTextWeak);
        tabLog.setTextColor(index == 1 ? colorGreen : colorTextWeak);
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

    private TextView tab(int textRes, View.OnClickListener click) {
        TextView view = new TextView(this);
        view.setText(textRes);
        view.setTextColor(colorTextWeak);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        view.setGravity(Gravity.CENTER);
        view.setMinHeight(dp(48));
        view.setOnClickListener(click);
        return view;
    }

    private TextView addRow(LinearLayout parent, int labelRes, String value) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(8), 0, dp(8));

        TextView name = new TextView(this);
        name.setText(labelRes);
        name.setTextColor(colorTextWeak);
        name.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        name.setLineSpacing(0f, 1.5f);
        row.addView(name, new LinearLayout.LayoutParams(dp(88),
                ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView val = new TextView(this);
        val.setText(value);
        val.setTextColor(colorTextSecondary);
        val.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        val.setLineSpacing(0f, 1.5f);
        row.addView(val, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        parent.addView(row);
        return val;
    }

    // ------------------------------------------------------------- state

    private void refreshDetails() {
        detailModel.setText(Build.MODEL + " / " + Build.PRODUCT);
        detailKernel.setText(System.getProperty("os.version", "?"));
        detailKernelVer.setText(Build.VERSION.RELEASE);
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
            } else if (key.equals("mgr")) {
                mgr = value;
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
        boolean shizuku = safePing();
        boolean authorized = shizuku && safePermission() == 0;

        detailKsud.setText("not loaded".equals(ksud) ? "未加载"
                : ("missing".equals(ksud) ? "缺失" : ksud));
        detailKsu.setText("active".equals(ksu) ? "越狱模式（u:r:ksu:s0）" : "未启用");
        detailMgr.setText(describeManager());
        if (detailVivo != null) {
            detailVivo.setText(describeVivo());
        }
        detailSelinux.setText(selinux);
        detailSeccomp.setText(seccomp);
        detailRootState.setText(rootOpen ? "uid=0 · 本次开机有效" : "未获取");

        // ---- A 状态总览 ----
        String summary = "内核 " + System.getProperty("os.version", "?")
                + " · " + Build.MODEL;
        if ("active".equals(ksu)) {
            statusTitle.setText(R.string.status_rooted);
            statusTitle.setTextColor(colorGreen);
            statusSubtitle.setText("KernelSU 已加载 · su 为 u:r:ksu:s0");
            summary += " · root 已获取 · 本次开机有效";
        } else if (rootOpen) {
            statusTitle.setText(R.string.status_rooted);
            statusTitle.setTextColor(colorGreen);
            statusSubtitle.setText("uid=0 · u:r:shell:s0 · 重启后失效");
            summary += " · root 已获取 · 本次开机有效";
        } else if (shizuku && bound) {
            statusTitle.setText(R.string.status_ready);
            statusTitle.setTextColor(colorGreen);
            statusSubtitle.setText("Shizuku 已连接 · 尚未提权");
        } else if (shizuku) {
            statusTitle.setText(R.string.status_connected);
            statusTitle.setTextColor(colorAmber);
            statusSubtitle.setText(authorized
                    ? "Shizuku is running · connecting..."
                    : "Shizuku is running · grant permission");
        } else {
            statusTitle.setText(R.string.status_disconnected);
            statusTitle.setTextColor(colorTextSecondary);
            statusSubtitle.setText("Start Shizuku first");
        }
        statusSummary.setText(summary);

        // ---- B 引导 4 步进度 ----
        updateSteps(authorized, bound, rootOpen);

        // ---- C 主操作区 ----
        updateActions(authorized, bound, rootOpen);
    }

    /** 3 步进度：Shizuku → 准备 → root + KernelSU。 */
    private void updateSteps(boolean authorized, boolean bound, boolean rooted) {
        // 状态位：第 0 步 = Shizuku 已授权；第 1 步 = 已连接(bound)；
        // 第 2 步 = 已拿到 root（KSU 那条一次跑完，不再单列诊断步）。
        boolean[] done = {
                authorized,
                bound,
                rooted
        };
        // 当前高亮：第一个未完成的步骤
        int current = -1;
        for (int i = 0; i < done.length; i++) {
            if (!done[i]) {
                current = i;
                break;
            }
        }
        for (int i = 0; i < stepDots.length; i++) {
            if (done[i]) {
                stepDots[i].setText("✓");
                stepDots[i].setTextColor(colorGreen);
                stepLabels[i].setTextColor(colorTextSecondary);
            } else if (i == current) {
                stepDots[i].setText("•");
                stepDots[i].setTextColor(colorAmber);
                stepLabels[i].setTextColor(colorTextPrimary);
            } else {
                stepDots[i].setText("•");
                stepDots[i].setTextColor(colorTextWeak);
                stepLabels[i].setTextColor(colorTextWeak);
            }
        }

        // 未授权 → 显示琥珀提示条
        if (!authorized) {
            guideBanner.setVisibility(View.VISIBLE);
            bannerText.setText(safePing()
                    ? "Shizuku 正在运行，但尚未授权本应用"
                    : "Shizuku 未运行，请先启动并授权");
        } else {
            guideBanner.setVisibility(View.GONE);
        }
    }

    private void updateActions(boolean authorized, boolean bound, boolean rooted) {
        // 一键流程不再依赖"先拿到 root shell"：fake 那条自己会提权。
        boolean canRun = authorized && bound;

        actionOneTapBtn.setEnabled(canRun);
        actionOneTapBtn.setAlpha(canRun ? 1f : 0.45f);
        actionOneTapHint.setText("active".equals(ksu)
                ? "已加载（u:r:ksu:s0）· 再点一次只复验 su，不重跑漏洞"
                : (canRun ? "一次跑完：提权 + ksud late-load，约 15 秒"
                : missingStep(authorized, bound)));

        actionShellOnlyBtn.setEnabled(canRun);
        actionShellOnlyBtn.setAlpha(canRun ? 1f : 0.45f);
        actionShellOnlyHint.setText(rooted
                ? "已获取 root Shell（本次开机有效）"
                : (canRun ? "只提权，不加载 KernelSU（排障用）"
                : missingStep(authorized, bound)));
    }

    private String missingStep(boolean authorized, boolean bound) {
        if (!authorized) {
            return "需先授权 Shizuku";
        }
        if (!bound) {
            return "需先连接用户服务";
        }
        return "";
    }

    private boolean safePing() {
        try {
            return Shizuku.pingBinder();
        } catch (Throwable t) {
            return false;
        }
    }

    private void showShizuku() {
        /*
         * 没在跑的时候，请求权限是空转（binder 都不在）。这一步真正有用的动作
         * 是把管理器拉起来，让人在"无线调试"里点 Start —— 少一步自己去桌面找。
         */
        if (!safePing()) {
            android.content.Intent i = getPackageManager()
                    .getLaunchIntentForPackage("moe.shizuku.privileged.api");
            if (i != null) {
                addLog("Shizuku 未运行，已打开管理器：无线调试 → Start");
                try {
                    startActivity(i);
                    return;
                } catch (Throwable t) {
                    addLog("打开 Shizuku 失败：" + t);
                }
            }
        }
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
     * cve98260_auto.py 的 20 个字段逐项一致（多台 6.1 真机都对拍过）。
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

    /** 本地镜像：先拷到缓存目录，再走统一的推导入口。 */
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
                deriveFromFile(tmp, fileName);
            } catch (Throwable t) {
                addLog("推导失败：" + t);
            } finally {
                //noinspection ResultOfMethodCallIgnored
                tmp.delete();
            }
        }).start();
    }

    /** 输入 OTA 链接：只把 payload 里的 boot 分区按 Range 拉下来。 */
    private void promptOtaUrl() {
        final EditText input = new EditText(this);
        input.setSingleLine(true);
        input.setHint("https://…/payload.bin 或 OTA zip 直链");
        /*
         * 每次都从空开始。上一次的链接还留着（成功推过一次才存），但不自动填 ——
         * 过期链接带签名参数，直接塞进输入框很容易让人以为"这次用的是新的"。
         * 需要复用就点「上次」，不点就是干净的空框。
         */
        input.setText("");
        final String last = getSharedPreferences("timerroot", MODE_PRIVATE)
                .getString("ota_url", "");
        AlertDialog.Builder builder = new AlertDialog.Builder(this)
                .setTitle("从 OTA 链接推导")
                .setMessage("只下载 boot 分区（通常几十 MB），不会整包下载几个 GB。\n"
                        + "支持直链 payload.bin，也支持 payload.bin 以 Stored 方式存放的 OTA zip。")
                .setView(input)
                .setPositiveButton("开始", (d, w) -> {
                    String url = input.getText().toString().trim();
                    if (!url.startsWith("http://") && !url.startsWith("https://")) {
                        toast("请输入 http/https 链接");
                        return;
                    }
                    showTab(1);
                    deriveFromOta(url);
                })
                .setNegativeButton("取消", null);
        if (!last.isEmpty()) {
            // 有记录才给这个按钮；点了只把文本填进去，不关对话框
            builder.setNeutralButton("上次", null);
        }
        AlertDialog dialog = builder.show();
        if (!last.isEmpty()) {
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v -> {
                input.setText(last);
                input.setSelection(input.getText().length());
            });
        }
    }

    private void deriveFromOta(String url) {
        new Thread(() -> {
            File tmp = new File(getCacheDir(), "boot_ota.img");
            try {
                addLog("开始从 OTA 拉取 boot：" + url);
                Class<?> c = Class.forName("com.kpgc.timerroot.ota.OtaBoot");
                java.util.function.Consumer<String> sink = line -> addLog(line);
                Object r = c.getMethod("fetchBoot", String.class, File.class,
                                java.util.function.Consumer.class)
                        .invoke(null, url, tmp, sink);
                String err = String.valueOf(r);
                if (!err.isEmpty()) {
                    addLog("OTA 拉取失败：" + err.replace("ERR:", "").trim());
                    ui.post(() -> toast("OTA 拉取失败，看日志"));
                    return;
                }
                getSharedPreferences("timerroot", MODE_PRIVATE).edit()
                        .putString("ota_url", url).apply();
                addLog("boot 分区已下载，开始解析…");
                deriveFromFile(tmp, "OTA 链接");
            } catch (ClassNotFoundException e) {
                addLog("此构建没有内置 OTA 解析（编译时未找到 kotlinc）");
            } catch (Throwable t) {
                addLog("OTA 推导失败：" + t);
            } finally {
                //noinspection ResultOfMethodCallIgnored
                tmp.delete();
            }
        }).start();
    }

    /** 拿到 boot.img 之后的共同部分：解析 → 导入 → 自动重跑准备。 */
    private void deriveFromFile(File img, String label) {
        if (service == null) {
            addLog("请先连接 Shizuku（需要它把 conf 写进 /data/local/tmp/conf.d）");
            ui.post(() -> toast("请先连接 Shizuku"));
            return;
        }
        try {
            Class<?> c = Class.forName("com.kpgc.timerroot.ota.Deriver");
            Object r = c.getMethod("derive", String.class).invoke(null, img.getAbsolutePath());
            String text = String.valueOf(r);
            if (text.startsWith("ERR:")) {
                addLog("推导失败：" + text.substring(4).trim());
                return;
            }
            Matcher m = Pattern.compile("(?m)^\\s*release\\s*=\\s*\"([^\"]+)\"")
                    .matcher(text);
            String rel = m.find() ? m.group(1) : "derived";
            String res = service.importConf(rel + ".conf", text);
            addLog("推导完成（release=" + rel + "，来源 " + label + "）\n" + res);
            ui.post(() -> {
                toast("已生成并导入：" + rel);
                if (!res.startsWith("导入失败")) {
                    // 新 conf 已落地，自动重跑一次准备，换掉 /data/local/tmp/timer.conf
                    autoPrepared = false;
                    maybeAutoPrepare();
                }
            });
        } catch (ClassNotFoundException e) {
            addLog("此构建没有内置推导（编译时未找到 kotlinc）；"
                    + "请用 PC 的 cve98260_auto.py 生成后再点「导入配置」");
        } catch (Throwable t) {
            addLog("推导失败：" + t);
        }
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
        if (request == REQUEST_CODE) {
            // 有的 Shizuku 版本授权后仍回 RESULT_CANCELED，以实际权限位为准
            if (result == RESULT_OK
                    || safePermission() == android.content.pm.PackageManager.PERMISSION_GRANTED) {
                addLog("Shizuku 授权成功，接着自动准备");
                bindService();
            } else {
                addLog("Shizuku 授权被拒绝 —— 没有权限就建不了工作目录");
                toast("需要 Shizuku 授权才能继续");
                refreshDetails();
            }
            return;
        }
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
                ui.post(() -> {
                    toast(r.split("\n")[0]);
                    if (!r.startsWith("导入失败")) {
                        autoPrepared = false;
                        maybeAutoPrepare();
                    }
                });
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

    /* ------------------------------------------------------------ vivo 适配
     *
     * 为什么要开关：vivo 的 sys_exit 回调表清零 + riskdetect 只对 OriginOS 有意义。
     * 其它机型跑同一份二进制时，App 会显式下发 TIMER_VIVO=0，二进制那边再要求
     * conf 里有 vivo_disarm=1 才动手 —— 两层都关着，等同于旧行为。
     *
     * 识别只认 Build.MANUFACTURER/BRAND，不读隐藏属性，避免被 Android 的
     * hidden-API 限制绊住。iQOO 的 manufacturer 同样是 vivo。
     */
    private static final String PREF_VIVO = "vivo_mode";   // auto | on | off

    private boolean detectedVivo() {
        String m = Build.MANUFACTURER == null ? "" : Build.MANUFACTURER.toLowerCase(Locale.US);
        String b = Build.BRAND == null ? "" : Build.BRAND.toLowerCase(Locale.US);
        return m.contains("vivo") || b.contains("vivo") || b.contains("iqoo");
    }

    private String vivoModePref() {
        return getSharedPreferences("timer", MODE_PRIVATE)
                .getString(PREF_VIVO, "auto");
    }

    /** 回给服务的值："1" 强制走、"0" 强制跳过。自动模式按机型判定。 */
    private String effectiveVivoMode() {
        String mode = vivoModePref();
        if ("on".equals(mode)) {
            return "1";
        }
        if ("off".equals(mode)) {
            return "0";
        }
        return detectedVivo() ? "1" : "0";
    }

    private String describeVivo() {
        String mode = vivoModePref();
        String who = detectedVivo() ? "检测到 vivo" : "非 vivo 机型";
        String eff = "1".equals(effectiveVivoMode()) ? "启用" : "跳过";
        if ("auto".equals(mode)) {
            return who + " · 自动（" + eff + "）· 点此更改";
        }
        return who + " · 强制" + ("on".equals(mode) ? "开启" : "关闭")
                + "（当前" + eff + "）· 点此更改";
    }

    private void pushVivoMode() {
        if (service == null) {
            return;
        }
        new Thread(() -> {
            try {
                String r = service.setVivoMode(effectiveVivoMode());
                Log.i(TAG, "setVivoMode: " + r);
            } catch (Throwable t) {
                Log.i(TAG, "setVivoMode failed: " + t);
            }
        }).start();
    }

    private void showVivoPicker() {
        final String[] labels = {
                "自动（检测到 vivo 才启用）",
                "强制开启（vivo 收尾：清 sys_exit 回调 + 停 riskdetect）",
                "强制关闭（其它机型用这个）"
        };
        final String[] vals = {"auto", "on", "off"};
        String cur = vivoModePref();
        int checked = 0;
        for (int i = 0; i < vals.length; i++) {
            if (vals[i].equals(cur)) {
                checked = i;
            }
        }
        new AlertDialog.Builder(this)
                .setTitle("vivo 适配")
                .setSingleChoiceItems(labels, checked, (d, w) -> {
                    getSharedPreferences("timer", MODE_PRIVATE).edit()
                            .putString(PREF_VIVO, vals[w]).apply();
                    d.dismiss();
                    pushVivoMode();
                    applyDetails();
                    toast("vivo 适配：" + labels[w]);
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private String describeManager() {
        if (mgr == null || mgr.isEmpty() || "auto".equals(mgr)) {
            return "自动识别 · 点此指定";
        }
        if (mgr.startsWith("manual:")) {
            return "手动 · " + mgr.substring(7) + " · 点此更改";
        }
        if (mgr.startsWith("auto:")) {
            return "自动 · " + mgr.substring(5) + " · 点此更改";
        }
        return mgr + " · 点此更改";
    }

    /** 列出设备上所有可用管理器，选一个写进覆盖文件。 */
    private void showManagerPicker() {
        if (service == null) {
            toast("正在连接 Shizuku…");
            bindService();
            return;
        }
        new Thread(() -> {
            String raw;
            try {
                raw = service.ksuManagers();
            } catch (Throwable t) {
                raw = "";
                addLog("列管理器失败：" + t);
            }
            final String list = raw;
            ui.post(() -> {
                ArrayList<String> labels = new ArrayList<>();
                ArrayList<String> pkgs = new ArrayList<>();
                labels.add("自动识别（推荐）");
                pkgs.add("auto");
                for (String line : list.split("\n")) {
                    String s1 = line.trim();
                    if (s1.isEmpty()) {
                        continue;
                    }
                    String[] f = s1.split("\t");
                    if (f.length < 3) {
                        continue;
                    }
                    labels.add(f[0] + "   [" + f[2] + "]");
                    pkgs.add(f[0]);
                }
                if (labels.size() == 1) {
                    toast("没有发现带 libksud.so 的管理器");
                }
                new AlertDialog.Builder(this)
                        .setTitle("KernelSU 管理器")
                        .setItems(labels.toArray(new String[0]),
                                (d, which) -> applyManager(pkgs.get(which)))
                        .setNegativeButton("取消", null)
                        .show();
            });
        }).start();
    }

    private void applyManager(String pkg) {
        if (service == null) {
            return;
        }
        toast("auto".equals(pkg) ? "恢复自动识别…" : "指定 " + pkg + "…");
        new Thread(() -> {
            try {
                final String r = service.setKsuManager(pkg);
                addLog(r);
                ui.post(() -> {
                    toast("auto".equals(pkg) ? "已恢复自动识别" : "已指定 " + pkg);
                    refreshDetails();
                });
            } catch (Throwable t) {
                addLog("指定失败：" + t);
                ui.post(() -> toast("指定失败：" + t));
            }
        }).start();
    }

    private void prepare() {
        prepareInternal(false);
    }

    /** 自动或手动执行准备阶段；auto=true 时不弹 toast 打断。 */
    private void prepareInternal(boolean auto) {
        if (preparing) {
            addLog("准备正在进行，忽略这次触发");
            return;
        }
        if (!safePing()) {
            if (!auto) {
                new AlertDialog.Builder(this)
                        .setTitle("Shizuku 未运行")
                        .setMessage("请先启动 Shizuku：\n\n"
                                + "1. 打开 Shizuku 应用\n"
                                + "2. 用「无线调试」启动（或通过 USB 配对启动）\n"
                                + "3. 回到这里，授权后会自动准备")
                        .setPositiveButton("确定", null)
                        .show();
            }
            return;
        }
        if (service == null) {
            bindService();
            if (!auto) {
                toast("正在连接 Shizuku…");
            }
            return;
        }
        preparing = true;
        addLog(auto ? "已获得 Shizuku 授权，自动执行准备" : "手动准备…");
        if (!auto) {
            toast("正在准备…");
        }
        new Thread(() -> {
            try {
                final String result = service.install(getPackageCodePath());
                addLog(result);
                ui.post(() -> {
                    preparing = false;
                    autoPrepared = true;
                    if (!auto) {
                        toast(result);
                    } else if (result.startsWith("安装失败") || result.contains("conf=none")) {
                        toast("准备未完成，请看日志");
                    }
                    refreshDetails();
                });
            } catch (Throwable t) {
                addLog("准备失败：" + t);
                ui.post(() -> {
                    preparing = false;
                    autoPrepared = true;
                    toast("准备失败：" + t);
                });
            }
        }).start();
    }

    /**
     * Shizuku 授权 + 用户服务连上之后自动跑一次准备。
     *
     * 只在本次进程里跑一次：失败也置位。install() 里含 am kill-all，每次都跑
     * 会把用户后台反复清掉，所以宁可让用户手动补一次，也不做无条件重试。
     */
    private void maybeAutoPrepare() {
        if (autoPrepared || preparing) {
            return;
        }
        if (!safePing()
                || safePermission() != android.content.pm.PackageManager.PERMISSION_GRANTED
                || service == null) {
            return;
        }
        prepareInternal(true);
    }

    private void toast(String text) {
        Toast.makeText(this, text, Toast.LENGTH_SHORT).show();
    }

    private void confirmShellOnly() {
        new AlertDialog.Builder(this)
                .setTitle("获取 root Shell？")
                .setMessage("运行一次 CVE-2026-98260，并保持一个 uid=0 的 shell。\n\n"
                        + "- 失败时进程会挂起（park），只有重启能清理\n"
                        + "- 重启后 root 消失\n"
                        + "- 运行期间不要操作设备")
                .setPositiveButton("运行", (d, w) -> runShellOnly())
                .setNegativeButton("取消", null)
                .show();
    }

    private void runShellOnly() {
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
                    // 备选路径：只提权。要走 KernelSU 直接点上面那个一键按钮，
                    // 它会自己再跑一次（fake cred），不需要这里的 shell。
                    addLog("已获得 root Shell —— 要 KernelSU 请点「一键 root + KernelSU」");
                }
            } catch (Throwable t) {
                addLog("提权失败：" + t);
            }
        }).start();
    }

    private void confirmOneTap() {
        /*
         * 已经加载过就不要再跑一遍漏洞：fake cred 那次会把父进程 park 住，
         * 再跑只会多留一个僵尸，还得重启。这里改成"复验 su" —— 开机内随时能点。
         */
        if ("active".equals(ksu)) {
            verifySu();
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("一键 root + KernelSU？")
                .setMessage("一次跑完：清 panic_on_warn → 伪造 cred → 关 SELinux → "
                        + "启动 rootd → ksud late-load。\n\n"
                        + "- 约 10~20 秒，成功后 su 在 u:r:ksu:s0\n"
                        + "- 父进程会挂起（park），用完重启清理\n"
                        + "- 运行期间不要操作设备\n\n"
                        + "不必先点「只获取 root Shell」，那条是排障用的备选路径。")
                .setPositiveButton("开始", (d, w) -> runOneTap())
                .setNegativeButton("取消", null)
                .show();
    }

    private long oneTapStartedAt;

    /** 单独复验 su，不碰内核 —— 已加载后想再确认一次时用。 */
    private void verifySu() {
        if (service == null) {
            addLog("请先绑定服务");
            return;
        }
        new Thread(() -> {
            try {
                final String out = service.suCheck();
                addLog("—— 验证 su ——\n" + out.trim());
                final boolean ok = out.contains("u:r:ksu:s0");
                ui.post(() -> toast(ok ? "su 可用（u:r:ksu:s0）" : "su 未通过验证，看日志"));
            } catch (Throwable t) {
                addLog("验证 su 失败：" + t);
            }
        }).start();
    }

    private void runOneTap() {
        if (service == null) {
            addLog("请先绑定服务");
            return;
        }
        /*
         * 22:32 那次日志里出现了两条一模一样的流程（:27 和 :28）——
         * 重复点击会让两个 glk 进程各自 park，白白浪费一次开机。
         * 两分钟内直接忽略。
         */
        if (System.currentTimeMillis() - oneTapStartedAt < 120_000L) {
            addLog("KernelSU 流程刚跑过，忽略这次点击（失败请先重启）");
            return;
        }
        oneTapStartedAt = System.currentTimeMillis();
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
                        // fake 那条跑通就说明 rootd 已经在监听，root 是确实拿到的
                        rootOpen = true;
                        applyDetails();
                        refreshDetails();
                        if (suOk) {
                            showKsuReady();
                        } else {
                            toast("KernelSU 模块已加载，但 su 还没通过验证，看日志");
                        }
                    } else {
                        statusTitle.setText(R.string.status_failed);
                        statusTitle.setTextColor(colorRed);
                        statusSubtitle.setText(reason + " - reboot, then retry");
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

    /** 成功落地页：只剩两个动作 —— 去管理器授权，或者稍后自己用。 */
    private void showKsuReady() {
        new AlertDialog.Builder(this)
                .setTitle("KernelSU 已就绪")
                .setMessage("su 已在 u:r:ksu:s0 下可用。\n\n"
                        + "· 打开管理器给应用授权，模块/超级用户都在那里\n"
                        + "· 本次开机有效，重启即失效（也顺便清掉 park 的进程）\n"
                        + "· 想再确认一次 su，再点「一键 root + KernelSU」只会复验，不重跑漏洞")
                .setPositiveButton("打开管理器", (d, w) -> openManager())
                .setNeutralButton("重启设备", (d, w) -> reboot())
                .setNegativeButton("稍后", null)
                .show();
    }

    private void openManager() {
        String pkg = mgr == null ? "" : mgr.replaceFirst("^(auto|manual):", "");
        for (String cand : new String[]{pkg, "me.weishu.kernelsu", "me.weishu.kernelsu.next"}) {
            if (cand == null || cand.isEmpty()) {
                continue;
            }
            android.content.Intent i = getPackageManager().getLaunchIntentForPackage(cand);
            if (i != null) {
                startActivity(i);
                return;
            }
        }
        toast("没找到 KernelSU 管理器，先安装或手动打开");
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
                 * 8 -> 9：ksuManagers / setKsuManager
                 * 9 -> 10：内建 su 的验证方式（不再看 /system/bin/su 是否存在）
                 * 10 -> 11：setVivoMode（vivo 收尾开关）
                 */
                .version(11);
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
                if (autoScroll) {
                    logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
                }
            }
        });
    }
}
