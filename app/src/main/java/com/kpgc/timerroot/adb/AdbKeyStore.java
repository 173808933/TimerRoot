package com.kpgc.timerroot.adb;

import android.content.Context;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * ADB 客户端身份：一把 RSA-2048 私钥 + 一张自签证书。
 *
 * 无线调试的配对（SPAKE2）和之后的 TLS 都认这对东西；首次连接时 adbd 会把
 * 公钥记进 /data/adb/misc/adb/adb_keys，之后同一台设备不用再配对。
 * 私钥只存在 App 私有目录，文件权限 0600。
 */
final class AdbKeyStore {

    private static final String DIR = "adblink";
    private static final String KEY = "adb.key";
    private static final String CRT = "adb.crt";

    final PrivateKey key;
    final X509Certificate cert;

    private AdbKeyStore(PrivateKey key, X509Certificate cert) {
        this.key = key;
        this.cert = cert;
    }

    static synchronized AdbKeyStore load(Context ctx) throws Exception {
        File dir = new File(ctx.getFilesDir(), DIR);
        File kf = new File(dir, KEY);
        File cf = new File(dir, CRT);
        if (kf.isFile() && cf.isFile()) {
            try {
                PrivateKey k = KeyFactory.getInstance("RSA")
                        .generatePrivate(new PKCS8EncodedKeySpec(readAll(kf)));
                X509Certificate c = (X509Certificate) CertificateFactory
                        .getInstance("X.509")
                        .generateCertificate(new FileInputStream(cf));
                return new AdbKeyStore(k, c);
            } catch (Throwable ignored) {
                // 文件坏了就重新生成，最多重配一次
            }
        }
        return generate(dir, kf, cf);
    }

    private static AdbKeyStore generate(File dir, File kf, File cf) throws Exception {
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new IllegalStateException("cannot create " + dir);
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        long now = System.currentTimeMillis();
        // BouncyCastle 的 JcaContentSignerBuilder 在真机上被 ART 判成 erroneous class
        // （NoClassDefFoundError），改用自己拼的 DER，见 SelfSignedCert。
        byte[] der = SelfSignedCert.build("TimerRoot", kp,
                now - 24L * 3600 * 1000,
                now + 3650L * 24 * 3600 * 1000);
        X509Certificate cert = (X509Certificate) CertificateFactory
                .getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));

        write(kf, kp.getPrivate().getEncoded());
        write(cf, cert.getEncoded());
        return new AdbKeyStore(kp.getPrivate(), cert);
    }

    private static void write(File f, byte[] data) throws Exception {
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write(data);
        }
        //noinspection ResultOfMethodCallIgnored
        f.setReadable(false, false);
        //noinspection ResultOfMethodCallIgnored
        f.setReadable(true, true);
    }

    private static byte[] readAll(File f) throws Exception {
        byte[] buf = new byte[(int) f.length()];
        try (FileInputStream in = new FileInputStream(f)) {
            int off = 0;
            while (off < buf.length) {
                int n = in.read(buf, off, buf.length - off);
                if (n <= 0) {
                    break;
                }
                off += n;
            }
        }
        return buf;
    }
}
