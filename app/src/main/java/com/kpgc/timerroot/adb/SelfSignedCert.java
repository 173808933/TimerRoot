package com.kpgc.timerroot.adb;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/**
 * 最小 X.509 v3 自签证书构造器 —— 纯 JDK，不依赖 BouncyCastle。
 *
 * 为什么要自己拼 DER：0.70 用 bcpkix 的 JcaContentSignerBuilder 生成证书，
 * 在真机上抛 NoClassDefFoundError（类确实在 dex 里，是 ART 校验阶段就把它
 * 判成 erroneous 了）。证书只用来给 adbd 交一个 RSA 公钥，不需要任何扩展，
 * 与其和 5 MB 的密码学库较劲，不如自己拼几十行 DER。
 *
 * 结构（RFC 5280）：
 *   Certificate  ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
 *   TBSCertificate ::= SEQUENCE {
 *       [0] version(2=v3), serialNumber, signature, issuer,
 *       validity, subject, subjectPublicKeyInfo }
 *
 * subjectPublicKeyInfo 直接用 {@code PublicKey.getEncoded()} —— 它本身就是
 * 一个完整的 SubjectPublicKeyInfo DER，原样嵌进去即可。
 *
 * adbd 不验证证书链、不看扩展，只取公钥记进 adb_keys，所以这里
 * 一个扩展都不写，v1 也能用；写 v3 只是为了别家工具看着正常。
 */
final class SelfSignedCert {

    /** 1.2.840.113549.1.1.11 sha256WithRSAEncryption */
    private static final byte[] OID_SHA256_RSA = {
            0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86,
            (byte) 0xF7, 0x0D, 0x01, 0x01, 0x0B};
    /** 2.5.4.3 commonName */
    private static final byte[] OID_CN = {0x06, 0x03, 0x55, 0x04, 0x03};
    private static final byte[] ASN1_NULL = {0x05, 0x00};

    private SelfSignedCert() {
    }

    /**
     * @param cn       subject/issuer 的 commonName
     * @param kp       RSA 密钥对
     * @param notBeforeMs 生效时间（毫秒）
     * @param notAfterMs  失效时间（毫秒）
     * @return 证书的 DER 编码
     */
    static byte[] build(String cn, KeyPair kp, long notBeforeMs, long notAfterMs)
            throws Exception {
        byte[] algId = seq(OID_SHA256_RSA, ASN1_NULL);
        byte[] name = seq(set(seq(OID_CN, utf8(cn))));
        byte[] validity = seq(utcTime(notBeforeMs), utcTime(notAfterMs));
        byte[] spki = kp.getPublic().getEncoded();
        byte[] serial = integer(BigInteger.valueOf(System.currentTimeMillis()));

        byte[] tbs = seq(
                ctx0(integer(BigInteger.valueOf(2))),   // [0] version = v3
                serial,
                algId,
                name,
                validity,
                name,
                spki);

        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(kp.getPrivate());
        s.update(tbs);
        return seq(tbs, algId, bitString(s.sign()));
    }

    /* ------------------------------------------------------------- DER --- */

    private static byte[] seq(byte[]... p) {
        return tlv(0x30, p);
    }

    private static byte[] set(byte[]... p) {
        return tlv(0x31, p);
    }

    /** [0] EXPLICIT —— version 必须包在这一层里 */
    private static byte[] ctx0(byte[] p) {
        return tlv(0xA0, new byte[][]{p});
    }

    private static byte[] bitString(byte[] v) {
        byte[] body = new byte[v.length + 1];
        body[0] = 0;                    // 未使用位数
        System.arraycopy(v, 0, body, 1, v.length);
        return tlv(0x03, new byte[][]{body});
    }

    private static byte[] utf8(String s) {
        return tlv(0x0C, new byte[][]{s.getBytes(StandardCharsets.UTF_8)});
    }

    /** BigInteger.toByteArray() 已经是最小补码表示，正数会自动补 0x00 前缀 */
    private static byte[] integer(BigInteger v) {
        return tlv(0x02, new byte[][]{v.toByteArray()});
    }

    private static byte[] utcTime(long ms) {
        SimpleDateFormat f = new SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US);
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        return tlv(0x17, new byte[][]{
                f.format(new Date(ms)).getBytes(StandardCharsets.US_ASCII)});
    }

    private static byte[] tlv(int tag, byte[][] parts) {
        int len = 0;
        for (byte[] p : parts) {
            len += p.length;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(len + 6);
        out.write(tag);
        if (len < 0x80) {
            out.write(len);
        } else {
            int n = 0;
            for (int t = len; t > 0; t >>>= 8) {
                n++;
            }
            out.write(0x80 | n);
            for (int i = n - 1; i >= 0; i--) {
                out.write((len >>> (8 * i)) & 0xFF);
            }
        }
        for (byte[] p : parts) {
            out.write(p, 0, p.length);
        }
        return out.toByteArray();
    }
}
