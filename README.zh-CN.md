# TimerRoot（中文自述）

[English](README.md) · **简体中文**

**下载**：[最新 Release](https://github.com/173808933/TimerRoot/releases/latest) · [全部版本](https://github.com/173808933/TimerRoot/releases)

> 上游 `kpgc10kai/TimerRoot` 没有发布任何 release，APK 只在这个 fork 里。
> 如果你从 "forked from …" 点进了上游，看到空的 Releases 是正常的。

> 本文件是 [README.md](README.md) 的中文版，**重点说明本分支相对上游改了什么**。
> 代码注释、提交信息用中文；文件名、API、日志保持英文。

面向 **CVE-2026-98260**（POSIX CPU 定时器 use-after-free）的 Android 前端。
一次点击拿到 root shell，再 late-load **KernelSU**（`u:r:ksu:s0`）。

本仓库**不含** exploit 本体，是它外面那层壳：UI、状态判定、以及从普通应用
把 shell 域 exploit 跑起来所需要的 Shizuku / ADB 管线。

---

## 与上游的关系

| | |
|---|---|
| 上游 | [kpgc10kai/TimerRoot](https://github.com/kpgc10kai/TimerRoot) |
| 分叉点 | `main`（上游镜像 `b97535b`） |
| 本仓库 | `173808933/TimerRoot`，分支 **`conf-driven`** |
| exploit 源码 | 基于 [rikumi/TimerRoot](https://github.com/rikumi/TimerRoot) 的 conf 驱动版，收在 `native/timer.c` |

**全部是增量改动。** 不使用这些新特性的设备（6.6 / 6.12 内核）走的是上游原代码路径，
行为不变。下面每一条都对应一个可查的提交。

---

## 相对上游的 8 项改动

| # | 改了什么 | 提交 |
|---|---|---|
| 1 | 用源码构建的 exploit，由 conf 驱动，不再写死偏移 | `4562388` `bce859b` |
| 2 | 运行期导入 conf，换机型不必重编 APK | `bed3d95` `cda31a3` |
| 3 | 设备端从 boot.img 推导 profile | `7573859` |
| 4 | KSU 管理器可手动指定 | `439036b` |
| 5 | KernelSU 是否可用，改用「真的跑一次 su」判定 | `7eaad4e` |
| 6 | vivo 收尾动作，按机型自动识别 + 用户开关 | `eb6d074` |
| 7 | 内置 ADB 客户端，不装 Shizuku 也能跑 | `eb65168` `7a1abf1` |
| 8 | PC 端推导工具 `tools/derive/` | 本次 |

### 1. exploit 由 conf 驱动

`native/timer.c`（约 2.6k 行）与 `native/build.sh`：把上游写死的 6.12 偏移换成
一份文本 profile。所有内核常量（`timer_site` / `task_cred_off` /
`copy_process_low21` / `cred_uid_off` …）都从 `--conf` 读，代码里没有任何
「按机型分支」的逻辑。

**加一个机型 = 加一份 conf 文件**，不改代码、不重编二进制。

### 2. 运行期导入 conf

以前换机型要重编 APK。现在 conf 可以推到 `/data/local/tmp/conf.d`，也可以从
UI 导入，用之前先跟 `uname -r` 比对，对不上直接拒绝启动——宁可不动，也不拿
别人的偏移去写内存。

`IUserService.aidl` 因此多了几个方法，`UserServiceArgs.version` 从 7 升到 11。
Shizuku 会按这个号缓存用户服务进程，旧进程反序列化新 AIDL 会出错，所以每加
一个方法必须加一。

### 3. 设备端推导 profile

三个类，共约 1.4k 行：

- `ota/BootImageParser.kt` — 解 boot v2–v4，解 gzip / lz4 / lz4-legacy 内核，定位 arm64 `Image`
- `ota/KallsymsExtractor.kt` — 从 Image 里还原压缩过的 kallsyms（token 表、markers、names、offsets、relative base）
- `ota/Deriver.kt` — 符号 + BTF → 完整 conf

验证方式：用两份真实 boot.img 生成 profile，与手工写的 conf 逐项对比 20 个字段，完全相同。

### 4. KSU 管理器可手选

自动嗅探仍然是默认，但嗅探不准时可以指定。覆盖文件
`/data/local/tmp/ksud.pkg.override`，认 `kernelsu` / `ksunext` / `sukisu` /
`baka` / `fina` 五套包名。

### 5. KernelSU 判定看结果，不看文件

上游（以及本分支 0.62 之前）用 `/system/bin/su` 是否存在来判断，这在
KernelSU-Next 上必然误判：su 是**内核内建**的，`sucompat` 在
`do_execveat_common` 里把这条路径换成内核里的 blob，用 memfd 起进程，磁盘上
根本没有这个文件。

现在改成阶梯式真跑一遍（`su` / `/system/bin/su` / `/data/adb/ksu/bin/su` /
`ksud su`），拿到 `uid=0` 才算成功，失败打第一条真实报错。已 active 再点主按钮
只复验，不重跑漏洞。

### 6. vivo 收尾（opt-in）

OriginOS 会在 `sys_exit` 上挂回调，检查退出进程的 cred 是不是刚被改过；
root 一出现，`ksud` / `su` 退出就被杀。另有 `riskdetect` 盯着。

收尾动作两条，且**必须赶在 ksud 启动前**：

1. 把 `__tracepoint_sys_exit.funcs`（`+0x48`）清零 —— 迭代器看到 `NULL` 直接跳过，
   厂商挂在这条 tracepoint 上的回调整条不执行
2. `stop riskdetect`

顺序反了没用：先清再加载；加载完再清会把 KSU 自己的 `tp_marker` 一起清掉。

三道闸门保证不影响别的机型：App 下发的 `TIMER_VIVO`、conf 里的 `vivo_disarm=1`、
`sys_exit_tp` 必须落在内核映射区间。非 vivo 机型第一道就返回，plant 次数与旧版一致。

### 7. ADB 模式：不装 Shizuku

Shizuku 从来不是权限来源，它只是拿 shell 的一种方式。这个分支让 App 自己当 adb
客户端连本机 adbd：

- 配对走 SPAKE2 + TLS，路径与 Android 11+ 无线调试一致
- **配对码在通知栏输入**（`RemoteInput`），和 Shizuku 的交互一致，不会把系统
  配对弹窗顶到后台
- 连接端口不手填：配对成功后用 mDNS 发现 `_adb-tls-connect._tcp`（端口每次开机
  都变，密钥不变）
- 一键流程：部署 `assets/timer` + 匹配的 conf → `am kill-all` → `nohup` 跑 fake
  → 轮询日志 → `su -c id`

exploit 二进制和 conf 一行没改，只换了 shell 提供者。Shizuku 模式完整保留。

### 8. PC 端推导工具

`tools/derive/`：设备能自己推导，但如果手上只有一个 boot.img / OTA 包、没有能
用的设备，这个脚本在 PC 上做同样的事。

```bash
pip install capstone numpy
python tools/derive/cve98260_auto.py boot.img --out profiles/
```

输出判定（`USABLE` / `INCOMPLETE` / `PATCHED` / `FAIL`）和
`<release>.timer.conf`，直接丢进 `app/src/main/assets/conf/` 就能用。

字段来源见 `tools/derive/README.md`，换机型的完整流程见 `tools/derive/PORTING.md`。

---

## 行为差异对照

| 场景 | 上游 | 本分支 |
|---|---|---|
| 6.6 / 6.12 内核 | 正常 | 完全相同（不读新字段） |
| 6.1 内核，无对应 conf | 跑不起来 | 启动前就拒绝，不写内存 |
| 6.1 内核，有 conf | 跑不起来 | 正常 |
| 没装 Shizuku | 不可用 | 可用（ADB 直连模式） |
| vivo / iQOO | 提权后可能被杀 | 自动加收尾动作 |
| `panic_on_warn=1` 的设备 | 提权到 cred 阶段崩溃 | 先清零再继续（见 GhostKey 同一修法） |

---

## 内置的 5 份 conf

装好即用，按 `uname -r` **精确匹配**选一份；匹配不上就拒绝启动。

| release | 设备 | 状态 | md5 |
|---|---|---|---|
| `6.1.157-android14-11-o-ga43993466696` | realme Neo7 | 实机跑通 | `a56caf2536534002c0304074859aef30` |
| `6.1.141-android14-11-o-g7598c3221214` | realme GT6 | conf 已核对，未上机 | `5f2af76f2f7f4ea6a9c049856f0eaede` |
| `6.1.141-android14-11-o-gffc54a6d2287` | OPPO K12s | 实机跑通（纯 OTA 推导） | `9899848234c8c0ff8e56ce4d036d3fb5` |
| `6.1.141-android14-11-o-g6ed3e67335d5` | realme GT5 Pro | conf 已推导，未上机 | `5524be65f454a10c72ea8efe73ba12c2` |
| `6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k` | OPPO Ace6 | conf 已推导，未上机 | `fa4feeec40599b61e439b0f93119a870` |

没有你的机型？用第 3 条（设备端）或第 8 条（PC 端）自己生成一份。

---

## 最短使用路径

**ADB 模式（不装 Shizuku）**

```
装 APK → 开发者选项开「无线调试」
→ App 里点「配对并连接」→ 通知栏输入 6 位配对码
→ 点「一键 root + KernelSU」
→ 打开管理器授权 → 用完重启
```

**Shizuku 模式**

```
装 Shizuku 并启动 → 打开 App（自动连接 + 自动准备）
→ 点「一键 root + KernelSU」→ 管理器授权 → 用完重启
```

重启是唯一干净的清理方式：park 着的进程和 KernelSU 都随之消失。

---

## 发布

| 版本 | versionCode | APK | 大小 | md5 |
|---|---|---|---|---|
| `0.71-ace6` | 72 | `TimerRoot-0.71-ace6.apk` | 3,951,854 B | `bd64af1e273b766701d6fb10e7dc182f` |
| `0.70-paircode` | 71 | `TimerRoot-0.70-paircode.apk` | 3,951,738 B | `f96cd302e16dbe994735b03101293c9b` |

版本推进（0.63 起）：

| 版本 | 要点 |
|---|---|
| 0.63-suverify | KSU 判定改为真跑 su |
| 0.64-onetap | 两次漏洞合并成一次 |
| 0.65 | 去掉机型专属命名，按角色命名 |
| 0.66-vivo | vivo 自动识别 + 收尾 |
| 0.67 | OTA 输入框不再回填旧链接 |
| 0.68 | 内置 GT5 Pro conf |
| 0.69-adb | 内置 ADB 客户端 |
| 0.70-paircode | 配对码移到通知栏 |
| 0.71-ace6 | 内置 Ace6（6.6.118）的 conf；修 derive 在 6.6 上的误判 |

---

## 已知限制

- **配对/连接依赖 mDNS**。个别 ROM 屏蔽 NSD 会发现不了无线调试服务，
  LibADB 没有暴露「指定 host:port 走 TLS」的接口，这条路绕不过去。
- 每次开机要重新打开无线调试（配对密钥会保留，一般直接连即可）。
- 6.1.141 这条线上 **同版本号也必须单独一份 conf**：GT6 与 GT5 Pro 的 20 个字段
  里 19 个相同，但 `timer_site` 不同，混用会写错内存。
- 只有四份 conf 经过静态核对，其中 Neo7 与 K12s 上过真机；GT6 与 GT5 Pro
  尚未实机验证，第一次跑之前建议先确认手头能重启。

---

## 许可

上游 MIT，见 [LICENSE](LICENSE)。`native/timer.c` 来自 rikumi/TimerRoot，同样 MIT，
文件头保留了出处。
