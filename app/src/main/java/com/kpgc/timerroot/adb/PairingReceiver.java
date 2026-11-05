package com.kpgc.timerroot.adb;

import android.app.RemoteInput;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;

import java.util.function.Consumer;

/**
 * 接住通知栏里输入的配对码，配对完成后自动连接。
 *
 * 结果除了更新通知，还会通过 UI_LOG 回传给正在运行的 Activity（如果它在），
 * 这样日志页能直接看到 [adb] 那几行。
 */
public class PairingReceiver extends BroadcastReceiver {

    public static final String ACTION_PAIR = "com.kpgc.timerroot.action.PAIR";
    public static final String KEY_CODE = "pair_code";
    private static final int PAIR_TIMEOUT_SEC = 25;

    /** Activity 在前台时挂上来收日志；为 null 就只写通知。 */
    public static volatile Consumer<String> UI_LOG;

    @Override
    public void onReceive(Context context, Intent intent) {
        Bundle results = RemoteInput.getResultsFromIntent(intent);
        CharSequence raw = results == null ? null : results.getCharSequence(KEY_CODE);
        if (raw == null) {
            raw = intent.getCharSequenceExtra(KEY_CODE);
        }
        final String code = raw == null ? "" : raw.toString().trim();
        if (code.isEmpty()) {
            log("[adb] 配对码为空");
            return;
        }

        final Context app = context.getApplicationContext();
        final PendingResult pending = goAsync();
        new Thread(() -> {
            String pair = "配对异常";
            String conn = "";
            try {
                // 配对端口只在「使用配对码配对设备」弹窗打开时才广播，这里现找
                int port = AdbLink.discoverPairingPort(app, PAIR_TIMEOUT_SEC);
                if (port <= 0) {
                    pair = "没发现配对服务：确认配对弹窗还开着，再点一次「输入配对码」";
                    PairingNotification.result(app, false, pair);
                    pending.finish();
                    return;
                }
                log("[adb] 配对端口 " + port);
                AdbLink link = AdbLink.get(app);
                pair = link.doPair(port, code);
                if (pair.startsWith("配对成功")) {
                    Thread.sleep(800);
                    conn = link.doConnect();
                }
            } catch (Throwable t) {
                pair = "配对异常：" + t;
            }
            log("[adb] " + pair);
            if (!conn.isEmpty()) {
                log("[adb] " + conn);
            }
            PairingNotification.result(app, pair.startsWith("配对成功"),
                    pair + (conn.isEmpty() ? "" : "\n" + conn));
            pending.finish();
        }).start();
    }

    private static void log(String s) {
        Consumer<String> sink = UI_LOG;
        if (sink != null) {
            sink.accept(s);
        }
    }
}
