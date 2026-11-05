package com.kpgc.timerroot.adb;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.RemoteInput;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

/**
 * 配对码输入走通知栏，和 Shizuku 一样。
 *
 * 原因：开发者选项里的「使用配对码配对设备」是个系统对话框，切到 App 去输码
 * 很容易把它顶掉（各家 ROM 行为不一样）；而下拉通知栏不会离开那个界面，
 * 在通知里直接输入 6 位数字，配对在后台完成。
 */
public final class PairingNotification {

    static final String CHANNEL = "adb_pairing";
    static final int ID = 0xADB01;

    private PairingNotification() {
    }

    public static void show(Context ctx) {
        NotificationManager nm = ctx.getSystemService(NotificationManager.class);
        if (nm == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(CHANNEL, "无线调试配对",
                    NotificationManager.IMPORTANCE_HIGH);
            ch.setDescription("输入 6 位配对码");
            nm.createNotificationChannel(ch);
        }

        RemoteInput input = new RemoteInput.Builder(PairingReceiver.KEY_CODE)
                .setLabel("6 位配对码")
                .build();
        Intent i = new Intent(ctx, PairingReceiver.class)
                .setAction(PairingReceiver.ACTION_PAIR);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            flags |= PendingIntent.FLAG_MUTABLE;   // RemoteInput 需要可变 PendingIntent
        }
        PendingIntent pi = PendingIntent.getBroadcast(ctx, 1, i, flags);

        Notification.Action action = new Notification.Action.Builder(
                android.graphics.drawable.Icon.createWithResource(ctx,
                        android.R.drawable.ic_lock_lock),
                "输入配对码", pi)
                .addRemoteInput(input)
                .build();

        Notification n = new Notification.Builder(ctx, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle("输入无线调试配对码")
                .setContentText("打开「使用配对码配对设备」弹窗后，下拉通知栏点这里输入 6 位数字")
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .addAction(action)
                .build();
        nm.notify(ID, n);
    }

    public static void result(Context ctx, boolean ok, String text) {
        NotificationManager nm = ctx.getSystemService(NotificationManager.class);
        if (nm == null) {
            return;
        }
        Notification n = new Notification.Builder(ctx, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle(ok ? "配对成功" : "配对失败")
                .setContentText(text)
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .setAutoCancel(true)
                .build();
        nm.notify(ID, n);
    }
}
