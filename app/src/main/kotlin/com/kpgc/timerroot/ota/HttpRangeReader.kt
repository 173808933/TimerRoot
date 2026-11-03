package com.kpgc.timerroot.ota

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/**
 * 用标准 HttpURLConnection 读远端文件的任意字节区间。
 *
 * OTA 包动辄几个 GB，但 boot 分区在 payload 里只占几十 MB，所以整条链路
 * 都靠 Range 请求：先读 24 字节的 payload header，再读 manifest，最后只下载
 * boot 的那几个 block。没有 Range 支持的服务器（返回 200 而不是 206）会被
 * 当成失败 —— 那种情况只能退回本地镜像。
 *
 * 原实现（GhostLock）用协程把阻塞 IO 挪到 IO 线程；这里整条链本来就在
 * 后台 Thread 里跑，所以改成阻塞版，省掉 coroutines 依赖。
 */
class HttpRangeReader(
    private val connectTimeoutMs: Int = 15000,
    private val readTimeoutMs: Int = 30000,
    private val userAgent: String = "Dalvik/2.1.0 (Linux; Android) TimerRoot"
) {

    private fun open(urlStr: String, headers: Map<String, String>): HttpURLConnection {
        var currentUrl = urlStr
        var redirects = 0
        while (redirects < 6) {
            val conn = URL(currentUrl).openConnection() as HttpURLConnection
            conn.connectTimeout = connectTimeoutMs
            conn.readTimeout = readTimeoutMs
            conn.instanceFollowRedirects = true
            conn.setRequestProperty("User-Agent", userAgent)
            for ((k, v) in headers) {
                conn.setRequestProperty(k, v)
            }
            conn.connect()
            val code = conn.responseCode
            if (code in 301..303 || code in 307..308) {
                val location = conn.getHeaderField("Location")
                conn.disconnect()
                if (!location.isNullOrBlank()) {
                    currentUrl = if (location.startsWith("http://", true)
                        || location.startsWith("https://", true)
                    ) {
                        location
                    } else {
                        URL(URL(currentUrl), location).toString()
                    }
                    redirects++
                    continue
                }
            }
            return conn
        }
        throw IOException("重定向次数过多：$urlStr")
    }

    /** 文件总长度；服务器不返回 Content-Range / Content-Length 时返回 null。 */
    fun fileLength(url: String): Long? {
        return try {
            val conn = open(url, mapOf("Range" to "bytes=0-0"))
            try {
                val contentRange = conn.getHeaderField("Content-Range")
                if (contentRange != null) {
                    val slash = contentRange.lastIndexOf('/')
                    if (slash != -1) {
                        contentRange.substring(slash + 1).trim().toLongOrNull()?.let {
                            if (it > 0) {
                                return it
                            }
                        }
                    }
                }
                val length = conn.contentLengthLong
                if (length > 0) length else null
            } finally {
                conn.disconnect()
            }
        } catch (e: Exception) {
            null
        }
    }

    /** 读 [start, start+size) 这一段；失败返回 null。 */
    fun read(url: String, start: Long, size: Int): ByteArray? {
        if (size == 0) {
            return ByteArray(0)
        }
        if (size < 0 || start < 0) {
            return null
        }
        return try {
            val conn = open(url, mapOf("Range" to "bytes=$start-${start + size - 1}"))
            try {
                val code = conn.responseCode
                if (code == 200 && start > 0) {
                    // 服务器忽略了 Range，从头开始发的 —— 不能当成分片
                    return null
                }
                if (code !in 200..299) {
                    return null
                }
                val stream = conn.inputStream
                val buffer = ByteArray(size)
                var total = 0
                while (total < size) {
                    val n = stream.read(buffer, total, size - total)
                    if (n == -1) {
                        break
                    }
                    total += n
                }
                if (total == size) buffer else buffer.copyOf(total)
            } finally {
                conn.disconnect()
            }
        } catch (e: Exception) {
            null
        }
    }
}
