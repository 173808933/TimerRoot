# cve98260_auto.py — 一条命令判定「这台机器能不能用」

输入任意形态的内核容器（`boot.img` / `boot_a.img` / 裸 `Image` / `Image.gz` / 全量包 zip），
输出**能不能用**的判定 + 两份可直接用的 conf：

- `<release>.conf` —— GhostKey 格式（整数、`timer_link/cred_link` 那套）
- `<release>.timer.conf` —— TimerRoot 格式（十六进制字符串、20 字段，真机实测能直接吃）

换机型的完整方法见 [PORTING.md](PORTING.md)。

就是把之前手工做的那套流程固化：

```
boot.img ──carve──▶ arm64 Image（自动解 gzip / lz4-legacy / xz / zstd）
         ──kallsyms──▶ 符号表（自动定位，基址取 _text）
         ──反汇编──▶ ① 98260 是否已修补 ② 三个分配 call site
         ──BTF──▶ k_itimer / cred / task_struct / selinux_state 偏移
         ──IKCONFIG──▶ 页大小 + 加固项
         ──▶ 判定 + <release>.conf
```

## 用法

```bash
# 单个镜像
python cve98260_auto.py boot.img --out profiles/

# 批量（目录下所有 *.img / Image*）
python cve98260_auto.py roms/ --out profiles/

# 机器可读
python cve98260_auto.py boot.img --json
```

依赖（pip）：

```bash
pip install capstone numpy
pip install zstandard     # 只有镜像用 zstd 压的时候才需要
pip install lz4           # 只有镜像用 lz4-legacy 压的时候才需要
```

`carve.py` 和 `extract_symbols_auto.py` 就在本目录，不用另外找；
要复用别处的工具链时用 `AUTOPORT_TOOLS=<目录>` 覆盖。

## 判定语义

| 判定 | 含义 | 退出码 |
|---|---|---|
| `USABLE` | 漏洞未修补 + 符号/结构齐全 → 已生成 profile | 0 |
| `INCOMPLETE` | 内核能拆，但缺 BTF 或关键符号 → 生成不了可信 profile | 1 |
| `PATCHED` | 已修补（`posixtimer_exec` 存在，或 timer 清理早于 `exec_mmap` 写锁） | 2 |
| `FAIL` | 拆不开内核 | 3 |

## 已验证（4 台真机镜像，全部 USABLE）

| 镜像 | release | timer_link | 备注 |
|---|---|---|---|
| Ace 3 Pro | `6.1.141-…-gffc54a6d2287` | `0xffffffc008439de8` | boot v4 |
| 真我 GT6 | `6.1.141-…-g7598c3221214` | `0xffffffc00843a438` | 裸 Image |
| 真我 Neo7 | `6.1.157-…-ga43993466696` | `0xffffffc00859c1dc` | boot v4 + **lz4-legacy** |
| PHY110 | `6.1.141-…-ge9a81736fafc` | `0xffffffc008439db8` | 裸 Image |

四台的 `timer_link` **互不相同**（同 6.1.141 的两个构建就差 0x650），
而 `cred_link` / `selinux_state` / `user_ns` / `root_user` / `groups` / `ucounts`
完全相同 —— 这正是「同版本号也必须单独推导」的直接证据。

脚本输出的 8 个 `offset` 与手工逐项核对**逐字节一致**（GT6 / Neo7 对拍通过）。

`*.timer.conf` 又验了一次 harder 的：拿 Neo7 的 Image 生成，与**真机上跑通的那份
手工 conf 对比 20 个字段全部相同**（含 `panic_on_warn`、`copy_process_low21`、
`cred_uid_off=4`、`ksu_kmi=android14-6.1`）。也就是说这台机器的 profile
现在可以完全由镜像复现，不再依赖手工反汇编。

## 关键实现点

1. **不被版本号骗**：只看 `begin_new_exec` 里 `posix_cpu_timers_exit` 与
   `exec_mmap` 的**先后**，以及符号表里有没有补丁新增的 `posixtimer_exec`。
   分界线的取法随内核版本变：6.1 及更早 `exec_mmap()` 是内联的，函数体里直接
   能看到 mmap 写锁，就用那个 `down_write_killable`；6.6+ 它是独立函数，必须用
   `bl exec_mmap` 的位置当分界——否则会在函数后段抓到另一个
   `down_write_killable`（6.6.118 在 +0x758，前面紧跟 `exec_mm_release`），
   把「timer 清理在 mm 切换之后」误判成「早于写锁 ⇒ 已修补」。
2. **call site 靠扫、不写死**：
   `do_timer_create` 里第一条目标为 `kmem_cache_alloc` 的 `bl`，返回地址即 `timer_link`；
   `prepare_creds` 同理（返回 `+0x20`，**不是**上游写死的 `+0x24`）；
   `copy_process` 里第一条 `kmem_cache_alloc_node`（**不是**写死的 `+0x140`）。
3. **结构体只取 BTF**：没有 BTF 直接判 `INCOMPLETE`，不猜。

## 与 app 内「OTA 链接推导」的关系

app 侧（`ota/Deriver`）在设备上做同一件事，判断逻辑一致：

- 扫出三个 call site，不写死 `+0xa8 / +0x24 / +0x140`；
- 判 `patched` 就拒绝生成 conf，而不是拿错偏移去写内核。

本目录的脚本是它的 PC 版：同样输入、同样输出。两边对拍过 ——
同一份 boot.img，设备端与 PC 端 20 个字段逐项相同。


## 附：`*.timer.conf` 是怎么来的

| 字段 | 来源 |
|---|---|
| `timer_site` / `copy_process_low21` | 反汇编里两条 `bl kmem_cache_alloc*` 的返回地址 |
| `selinux_state` / `panic_on_warn` / `root_user` / `init_user_ns` / `init_ucounts` / `init_groups` | kallsyms |
| `timer_alloc` / `cred_req` / `cred_alloc` / `task_alloc_bytes` | BTF 的 sizeof（cred 因 SLAB_HWCACHE_ALIGN 对齐到 64） |
| `cred_uid_off` / `task_cred_off` / `selinux_blob_off` | BTF 的字段偏移 |
| `ksu_kmi` | 从 release 串推（`6.1.157-android14-11-…` → `android14-6.1`） |
| `fullcap` / `selinux_sid_kernel` | 常量（CAP_LAST_CAP=40 → 41 位全 1；SECINITSID_KERNEL=1） |

conf 注释里还会打印"环境门"（`CONFIG_MODULES` / `MODULE_FORCE_LOAD` /
`MODVERSIONS` / `MODULE_SIG_FORCE` / `CFI_CLANG`），这些决定 KSU 那条路能不能走。
