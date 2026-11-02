native/timer.c — conf 驱动的 exploit
===================================

这份源码是 APK 里 `assets/timer` 的来源。它不是上游 `kpgc10kai/TimerRoot` 那份
写死 6.12.69 的二进制，而是 **`rikumi/TimerRoot` 的 conf 驱动版本**，
再叠加了本 fork 为 6.1（Neo7）做的修改。

    rikumi/TimerRoot native/timer.c  (PKT110, 6.6.118)
      └─ 本 fork: 6.1 布局 + rb_node 形状 + probe/panic_on_warn 顺序
                 + 抢页重试 + rootd + ksu 阶梯

上游链条：`woshigenm/CVE-2026-98260` → `YuKongA/CVE-2026-98260` →
`rikumi/TimerRoot` → 这里。均为 MIT / 公开研究用途，保留原文件头的署名。

构建
----
```bash
NDK=/opt/android-ndk sh native/build.sh
# 产出 app/src/main/assets/timer（aarch64 静态、约 310 KB）
```

Windows（Git Bash）同样可用；`NDK` 下找不到 clang 时会自动试 `.cmd` 包装器。
也可以直接给 `CC=aarch64-linux-android35-clang`。

运行期读的 conf
---------------
APK 侧按 `uname -r` 在 `assets/conf/` 里找 **release 完全匹配**的那份，
写到 `/data/local/tmp/timer.conf` 再启动。字段与含义：

| 字段 | 含义 | 错了会怎样 |
|---|---|---|
| `release` | `uname -r` 全串 | 匹配不上就拒绝启动 |
| `timer_site` | `do_timer_create` 里 `bl kmem_cache_alloc` 的返回地址 | `recs=0`，拿不到 victim |
| `timer_alloc` | `sizeof(struct k_itimer)` | trace 过滤漏分配 |
| `cred_req` / `cred_alloc` | `sizeof(cred)` / 对齐到 64 后的大小 | cred 记录漏 |
| `cred_uid_off` | `cred.uid` 偏移（6.1=4，6.6+=8） | 写到 gid 上，uid 不变 |
| `task_cred_off` | `task_struct.cred` | 写偏，崩 |
| `copy_process_low21` | `copy_process` 里分配 task 的返回地址低 21 位 | `task_recs=0` |
| `task_alloc_bytes` | `sizeof(task_struct)` | task 记录漏 |
| `selinux_state` / `panic_on_warn` | kallsyms 地址 | 写飞 / WARN 直接 panic |
| `root_user` `init_user_ns` `init_ucounts` `init_groups` | fake cred 的子对象 | 崩 |
| `selinux_blob_off` / `selinux_sid_kernel` | task_security_struct 的 sid 槽 | setresuid EINVAL |
| `ksu_kmi` | `android14-6.1` 这种 | late-load 挑错模块 |

这些值全都能从 boot.img 自动推：

```bash
python cve98260_auto.py boot.img --out profiles/
#  → profiles/<release>.timer.conf
```

模式
----
```
timer --conf <conf> ids      # 只发现 trace 的 event id，安全
timer --conf <conf> leak     # 泄漏 base / cred，不触发 UAF
timer --conf <conf> shell    # 真 cred 零写，拿 uid=0 的 sh
timer --conf <conf> fake     # fake cred + 关 SELinux + ksud late-load
timer rootd '<cmd>'          # 客户端：连 /data/local/tmp/rootd.sock 执行
```

失败处理
--------
fake 路线失败会 **park**（父进程持有的那页就是伪造 cred 所在页），
**不要 kill**，重启是唯一清理方式。日志每行 `fsync`，panic 前的都在
`/data/local/tmp/timer.log`。
