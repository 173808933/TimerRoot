把 TimerUAF 链路搬到别的机型
============================

一句话：**代码不用改，只要重新算一份 conf。** Neo7 上这套的二进制是 conf 驱动的，
机型差异全部落在 20 个数值里，而它们都能从 boot.img 自动推出来
（`python cve98260_auto.py boot.img --out profiles/` → `<release>.timer.conf`）。


一、跨机型真正不变的东西
------------------------
这些是链路的"骨架"，换机型不用动、也不要动：

1. 触发：非 leader 线程 execve，在 exec_mmap() 取 mmap 写锁时用 SIGKILL 打断
   `mmap_read_lock_killable`，让 `begin_new_exec` 半途返回；
2. UAF 对象：`k_itimer`（posix_timers cache），节点在 `it` 成员上；
3. 写原语：伪造 rb_node，借 `cleanup_timerqueue → rb_erase` 写目标；
   `__rb_parent_color == node` 时 `rb_next()` 返回 NULL，清理循环自然终止；
4. 运行期自校准：slide 用 trace 里 `kmem_cache_alloc` 的调用点减静态地址；
   线性映射基址用 `slab - (pfn<<12)` 投票（>=8 票）；
5. 收尾两条路：
   - 真 cred 零写 → 子进程 setresuid(0,0,0) → exec sh（只需 3 个常量对）；
   - fake cred + 关 SELinux + ksud late-load（要 10 来个常量全对）。

Neo7 上四发 plant 全部 first-try（33/73/46/37 ms），说明这套骨架对 6.1 是稳的。


二、每机型必须重算的 10 个量
----------------------------
按"错了会怎样"排序。前 4 个错了直接白跑，中间 3 个错了崩内核，最后 3 个只是漏匹配。

| 字段 | 来源 | 错了的表现 |
|---|---|---|
| `timer_site` | `do_timer_create` 里 `bl kmem_cache_alloc` 的**返回地址** | `recs=0` → victim not captured |
| `copy_process_low21` | `copy_process` 里 `bl kmem_cache_alloc_node(task)` 的返回地址 `& 0x1fffff` | `task_recs=0` → fake 路线拿不到 task |
| `selinux_state` | kallsyms | 写飞 → 直接 panic |
| `panic_on_warn` | kallsyms（可选，但 fake 路线强烈建议） | WARN 即 panic（OEM 出厂常是 1） |
| `root_user` / `init_user_ns` / `init_ucounts` / `init_groups` | kallsyms | fake cred 的子对象是野指针 → 崩 |
| `timer_alloc` | `sizeof(struct k_itimer)`（BTF） | trace 过滤漏掉分配记录 |
| `cred_req` / `cred_alloc` | `sizeof(cred)` / 向上对齐 64（HW_CACHE_ALIGN） | cred 记录漏 |
| `task_alloc_bytes` | `sizeof(task_struct)`（BTF） | task 分配记录漏 |
| `task_cred_off` | `task_struct.cred`（BTF） | 写偏 → 崩 |
| `cred_uid_off` | `cred.uid`（BTF） | 6.1 是 4；写成 8 会打到 gid 上 |

一个实测到的好消息：**6.1 各机型（Ace 3 Pro / GT6 / Neo7 / PHY110）的结构偏移完全一致**
（k_itimer=264、it@0x78、cred=176、task.cred@0x838、enforcing@0），
变的只有 kallsyms 地址。所以对 6.1 机型，conf 里真正"每台不同"的只有 6 个符号地址
+ 2 个 call site 低 21 位。

版本分支差异（这是唯一需要看版本号的地方）：
- 6.1：`cred.usage` 4 字节 → `cred_uid_off = 0x4`，fake cred 按 0xa0 排；
- 6.6 / 6.12：`usage` 8 字节 → `cred_uid_off = 0x8`，fake cred 按 0xb8 排；
- 代码里已经按 `cred_uid_off == 4` 自动切换两套布局，conf 写对就不用管。


三、四条硬门槛（决定"做了也白做"）
----------------------------------
满足不了就不用花时间了：

1. **漏洞未修补**：符号表里有 `posixtimer_exec` 就是已修；或者看
   `begin_new_exec` 里 `posix_cpu_timers_exit` 是否早于 `exec_mmap` 的写锁。
   脚本会直接给 PATCHED。
2. **tracefs 可写**：shell 域必须能往 `events/kmem/rss_stat/trigger` 写
   `enable_event:kmem:kmem_cache_alloc`（rss_stat 是"跳板"，kmem 的 enable 通常 EACCES）。
   写不进去 → 整套泄漏和竞态判定都做不了。
3. **页面大小 4 KiB**：payload 落在 `(V & 0x1fff) + 0x78`，16K 页内核要改成 `& 0x3fff`。
   （6.1 全是 4K；部分 6.6 机型是 16K，那种要改代码不只是改 conf。）
4. **KSU 路线额外要求**：`CONFIG_MODULES=y`；`MODULE_SIG_FORCE` 未开（否则只收签名模块）；
   `MODULE_FORCE_LOAD` 开着更好（KMI 对不上还能硬上）。这些脚本会打印在 conf 注释里。

**降级策略**：门槛 2/3/4 里只坏 4 的话，真 cred 零写路线仍然能拿到 uid=0 的 shell
（Neo7 实测 CapEff=0，够改文件不够 insmod）。所以先跑 shell 路线验证 conf，
再决定要不要折腾 KSU。


四、换机型的完整流程
--------------------
```bash
# 1) 从 rom 或 boot.img 直接生成 conf（boot.img / boot_a.img / Image / Image.gz / zip 都吃）
python cve98260_auto.py boot.img --out profiles/
#    → profiles/<release>.conf        给 GhostKey 用
#    → profiles/<release>.timer.conf  给 TimerRoot 用（本文说的这套）

# 2) 塞进 APK：assets/conf/ 下，二进制不用换
cp profiles/<release>.timer.conf <timerroot>/app/src/main/assets/conf/

# 3) 构建（同一把签名密钥，能覆盖安装）
pwsh scripts/build.ps1 -Sdk <android-sdk> -ShizukuApi <Shizuku-API> -VersionCode N -VersionName "N-<机型>"
```

APK 里的 `assets/timer` 是**通用**的 —— 它按 `uname -r` 在 assets/conf 里找
release 完全匹配的那份。所以做"多机型合一"的包时，只要往 assets/conf 里堆 conf，
一个 APK 可以同时带十几台机型（GhostKey 就是这么干的，17 份 profile）。


五、上机判定阶梯（每一步的失败都能定位到具体字段）
--------------------------------------------------
| 阶段 | 通过标志 | 不通过说明什么 |
|---|---|---|
| ids | `[ids] alloc-phase recs≈1024` / `free-phase recs≈1029` | tracefs 权限或 buffer 太小（先看 `buffer_size_kb` 那行） |
| leak | `[cred] … recs>0`、`task_recs=1` | `timer_site` / `copy_process_low21` / `cred_req/alloc` 不对 |
| plant | `[+] plant1 … burst hit=1 stolen_by=0` | `stolen_by` 有 pid = 输给别的分配（运气）；=0 = 记录丢了（配置） |
| reap | `[+] plant1 reaped status=0x9` | 写原语的形状错了（见下面第 4 条坑） |
| root | `[child] … resuid=0/0/0` | `task_cred_off` 或 `cred_uid_off` 不对 |
| ksu | `[ksu] rc=0` + `KSU_LOADED` | KMI / vermagic / CRC，见门槛 4 |


六、实战踩过的坑（按代价从高到低）
----------------------------------
1. **tracefs 默认每 CPU 只有 7 KB**。不抬 `buffer_size_kb` 就会看到
   "`pairs=196` 但一个都不配对"的假失败，很像布局错，其实是环形缓冲区写满丢记录。
   抬到 8192 后 1026/1029 条一条不少。
2. **`/data/app` 对 shell 是 0771**，`find /data/app -name libksud.so` 永远返回空。
   必须走 `pm list packages -f` 拿完整路径再 stat。
3. **Shizuku 的用户服务进程跨安装存活**。`UserServiceArgs.version` 不变，它就一直复用
   旧进程，装了新包还是跑旧代码（表现为"日志是英文的/字节数不对"，很容易误判）。
   每次改 UserService 就 +1。
4. **fake cred 必须叠在 rb_node 上（pc == node）**。看起来"分离更安全"，
   实际会让 `rb_erase_cached` 里的 `leftmost = rb_next(node)` 拿到 cred 地址，
   清理循环把 cred 当成节点再删一次 → 用 `usage` 当 parent 解引用 → panic。
   叠上去的代价只是 `WARN_ON_ONCE(RB_EMPTY_NODE)`，把它换来的 panic 用
   `panic_on_warn=0` 消掉即可（所以要先 probe 拿 slide，再清，再写 cred）。
5. **归一化只能在 fork 出的孙子进程里做**。父/子进程里 `cred != real_cred`，
   `commit_creds()` 的 `BUG_ON(task->cred != old)` 会当场 BUG。
6. **`task_security_struct` 四个 sid 槽位都要写 1**（osid/sid/exec_sid/create_sid）。
   只写 +8/+0xc 会让真正的 `sid@4` 留 0，permissive 只放宽 denied、不放宽
   `avc_has_perm` 的 -EINVAL，`setresuid` 会失败。
7. **抢页失败要看归因**：`stolen_by` 有 pid 是输给别的分配（重试就行），
   是 0 说明自己的 `page_alloc` 记录没到（缓冲区或过滤的问题）。
8. 失败一律 park，**不能 kill**（reap 会触发清理），只能重启。
9. `ksud late-load` 的 `rc=0` 不代表成功，唯一判据是 `/proc/modules` 里有 `kernelsu`。
10. ksud 3.3.1 自带的 `android14-6.1` 模块能直接载入 6.1.157 OEM 内核
    （vermagic / CRC / kCFI 全过），所以**不需要为每台机器自编 kernelsu.ko** —— 
    只有当管理器版本老到不带对应 KMI 模块时才需要。


七、哪些机型大概率不行
----------------------
- 2025 年下半年之后的安全更新可能回填补丁 → `posixtimer_exec` 存在，直接放弃；
- 16K 页内核（部分 6.6）→ payload 偏移要改代码；
- 没有 BTF 的内核（`CONFIG_DEBUG_INFO_BTF` 关掉）→ 结构偏移无法自动推导，
  只能手工反汇编核对，脚本会给 INCOMPLETE；
- SELinux 把 tracefs 完全封死、shell 域连 `rss_stat/trigger` 都写不了的 → 无解。
