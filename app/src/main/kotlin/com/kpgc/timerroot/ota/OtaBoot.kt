package com.kpgc.timerroot.ota

import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.util.Locale
import java.util.function.Consumer
import kotlin.math.min

/**
 * 从 OTA 链接里只把 boot 分区拉下来，产出可以直接喂给 [Deriver] 的 boot.img。
 *
 * 支持两种链接：
 *   - 直接指向 payload.bin（AB OTA 里那个文件）
 *   - 指向完整 OTA zip（payload.bin 以 Stored 方式放在里面）
 *
 * 全程只用 HTTP Range：先把 24 字节 header 和 manifest 读下来，算出 boot 在
 * data blob 里的偏移，然后只下载 boot 的那几个 block（通常几十 MB），
 * 不会整包下载几个 GB。
 *
 * 移植自 GhostLock 的 OtaPayloadExtractor，做了三处简化：
 *   - 去掉了协程（调用方本来就在后台线程，阻塞即可）
 *   - 只取 boot，不再顺带 xbl_config（推导只需要内核）
 *   - 不支持 REPLACE_BZ（需要 commons-compress）；遇到就明确报错
 */
object OtaBoot {

    private const val END_BYTES_SIZE = 65536
    private const val LOCAL_HEADER_PROBE_SIZE = 256
    /** update_engine 把数据切成 2 MB 左右的 op，超过这个数说明解析错了。 */
    private const val MAX_OP_BYTES = 64L * 1024 * 1024

    /**
     * @return 成功返回 ""，失败返回 "ERR: 原因"
     */
    @JvmStatic
    fun fetchBoot(url: String, outFile: File, log: Consumer<String>): String {
        return try {
            val reader = HttpRangeReader()
            val fileLength = reader.fileLength(url)
                ?: return "ERR: 连不上目标地址，或服务器不支持 Range（拿不到文件长度）"
            if (fileLength <= 0) {
                return "ERR: 远端文件长度为 0"
            }
            log.accept("远端文件 " + formatSize(fileLength) + "，正在定位 payload…")

            val payloadStart = locatePayloadStart(reader, url, fileLength, log)
            val headerBytes = reader.read(url, payloadStart, PayloadBinUtils.HEADER_SIZE)
                ?: return "ERR: 读不到 payload header"
            val header = PayloadBinUtils.parseHeader(headerBytes)
                ?: return "ERR: payload header 无效（没有 CrAU 魔数）"

            val manifestBytes = reader.read(
                url, payloadStart + PayloadBinUtils.HEADER_SIZE, header.manifestSize.toInt()
            ) ?: return "ERR: 读不到 payload manifest"

            val partitions = PayloadBinUtils.listPartitions(manifestBytes)
            if ("boot" !in partitions) {
                return "ERR: 这个 payload 里没有 boot 分区（有：${partitions.joinToString()}）"
            }
            val ops = PayloadBinUtils.partitionOperations(manifestBytes, "boot")
            if (ops.isEmpty()) {
                return "ERR: boot 分区在 payload 里没有任何操作"
            }

            val blockSize = PayloadBinUtils.blockSize(manifestBytes)
            val dataBase = payloadStart + PayloadBinUtils.HEADER_SIZE +
                    header.manifestSize + header.signatureSize
            val totalBytes = ops.sumOf { it.dataLength }
            log.accept(
                "boot 共 " + ops.size + " 个 op / " + formatSize(totalBytes) +
                        "，blockSize=" + blockSize
            )

            val maxEnd = ops.flatMap { it.destExtents }
                .maxOfOrNull { (it.startBlock + it.numBlocks) * blockSize }
                ?: return "ERR: boot 分区长度为 0"

            var done = 0L
            var lastLog = 0L
            if (outFile.exists() && !outFile.delete()) {
                return "ERR: 删不掉旧文件 " + outFile.absolutePath
            }

            RandomAccessFile(outFile, "rw").use { raf ->
                raf.setLength(maxEnd)
                for (op in ops) {
                    when (op.type) {
                        PayloadBinUtils.OP_ZERO, PayloadBinUtils.OP_DISCARD -> {
                            // setLength 已经把这块填 0
                        }

                        PayloadBinUtils.OP_REPLACE -> {
                            if (op.dataLength > MAX_OP_BYTES) {
                                return "ERR: REPLACE op 长度异常（" + op.dataLength + "），疑似解析错位"
                            }
                            val data = reader.read(
                                url, dataBase + op.dataOffset, op.dataLength.toInt()
                            ) ?: return "ERR: 下载 REPLACE 数据失败"
                            writeExtents(raf, data, op.destExtents, blockSize)
                        }

                        PayloadBinUtils.OP_REPLACE_XZ -> {
                            if (op.dataLength > MAX_OP_BYTES) {
                                return "ERR: XZ op 长度异常（" + op.dataLength + "），疑似解析错位"
                            }
                            val compressed = reader.read(
                                url, dataBase + op.dataOffset, op.dataLength.toInt()
                            ) ?: return "ERR: 下载 XZ 数据失败"
                            val rawSize = op.destExtents.sumOf { it.numBlocks } * blockSize
                            val plain = XzDecoder.decode(compressed, rawSize.toInt())
                            writeExtents(raf, plain, op.destExtents, blockSize)
                        }

                        PayloadBinUtils.OP_REPLACE_BZ ->
                            return "ERR: 该 OTA 的 boot 用了 BZ 压缩，当前版本不支持；" +
                                    "请改用本地 boot.img 或换一个 OTA 包"

                        else -> return "ERR: 不支持的 payload 操作类型 " + op.type
                    }
                    done += op.dataLength
                    val now = System.currentTimeMillis()
                    if (now - lastLog >= 2000) {
                        lastLog = now
                        val pct = if (totalBytes > 0) done * 100.0 / totalBytes else 0.0
                        log.accept(
                            "下载中 " + formatSize(done) + " / " + formatSize(totalBytes) +
                                    "（" + String.format(Locale.US, "%.0f", pct) + "%）"
                        )
                    }
                }
            }
            if (!outFile.isFile || outFile.length() == 0L) {
                return "ERR: 写出后文件为空"
            }
            log.accept("boot.img 已就位：" + formatSize(outFile.length()))
            ""
        } catch (e: Throwable) {
            "ERR: " + (e.message ?: e.toString())
        }
    }

    private fun locatePayloadStart(
        reader: HttpRangeReader, url: String, fileLength: Long, log: Consumer<String>
    ): Long {
        // 1) 直接就是 payload.bin？
        val head = reader.read(url, 0L, 4)
        if (head != null && head.size >= 4 &&
            head.contentEquals(PayloadBinUtils.PAYLOAD_MAGIC)
        ) {
            log.accept("检测到直链 payload.bin")
            return 0L
        }

        // 2) 当成 zip，从尾部找中央目录
        val tailSize = min(fileLength, END_BYTES_SIZE.toLong()).toInt()
        val tail = reader.read(url, fileLength - tailSize, tailSize)
            ?: throw IOException("读不到文件尾部（zip 中央目录）")

        val cd = ZipFileUtils.locateCentralDirectory(tail, fileLength)
        if (cd.offset < 0 || cd.size <= 0 || cd.offset + cd.size > fileLength) {
            throw IOException("这个链接既不是 payload.bin，也不像 OTA zip")
        }
        val cdBytes = reader.read(url, cd.offset, cd.size.toInt())
            ?: throw IOException("读不到 zip 中央目录")

        val entry = ZipFileUtils.locateEntries(cdBytes, setOf(PayloadBinUtils.PAYLOAD_ENTRY))[
                PayloadBinUtils.PAYLOAD_ENTRY
        ] ?: throw IOException("zip 里没有 " + PayloadBinUtils.PAYLOAD_ENTRY)

        if (entry.method != 0) {
            throw IOException(
                "zip 里的 payload.bin 是压缩存放的（method=" + entry.method +
                        "），只支持 Stored 方式"
            )
        }
        val headerOffset = entry.localHeaderOffset
        if (headerOffset !in 0..<fileLength) {
            throw IOException("zip local header 偏移越界")
        }
        val probeSize = min(fileLength - headerOffset, LOCAL_HEADER_PROBE_SIZE.toLong()).toInt()
        val localHeader = reader.read(url, headerOffset, probeSize)
            ?: throw IOException("读不到 payload.bin 的 local header")
        val innerOffset = ZipFileUtils.locateLocalFileOffset(localHeader)
        if (innerOffset !in 0..probeSize.toLong()) {
            throw IOException("解析 payload.bin local header 失败")
        }
        val payloadStart = headerOffset + innerOffset
        log.accept(
            "在 OTA zip 里定位到 payload.bin：偏移 " + payloadStart +
                    "（" + formatSize(entry.uncompressedSize) + "）"
        )
        return payloadStart
    }

    private fun writeExtents(
        raf: RandomAccessFile, data: ByteArray, extents: List<PayloadBinUtils.Extent>,
        blockSize: Long
    ) {
        var pos = 0
        for (ext in extents) {
            val len = (ext.numBlocks * blockSize).toInt()
            if (len <= 0) {
                continue
            }
            if (pos + len > data.size) {
                throw IOException("解压出来的数据不够写满 extent（需要 " + (pos + len) + "，只有 " + data.size + "）")
            }
            raf.seek(ext.startBlock * blockSize)
            raf.write(data, pos, len)
            pos += len
        }
    }

    private fun formatSize(bytes: Long): String {
        if (bytes < 1024) {
            return "$bytes B"
        }
        val kb = bytes / 1024.0
        if (kb < 1024) {
            return String.format(Locale.US, "%.0f KB", kb)
        }
        val mb = kb / 1024.0
        if (mb < 1024) {
            return String.format(Locale.US, "%.1f MB", mb)
        }
        return String.format(Locale.US, "%.2f GB", mb / 1024.0)
    }
}
