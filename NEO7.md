# TimerRoot — Neo7 / 6.1 fork

本 fork 在 [kpgc10kai/TimerRoot](https://github.com/kpgc10kai/TimerRoot) 的基础上，
把「写死 6.12.69」换成了 **conf 驱动 + 6.1 适配**，并在一台 realme Neo7 上
把 KernelSU 路线完整跑通。

上游是 app 外壳（Shizuku + AIDL + UI），二进制本身来自
[rikumi/TimerRoot](https://github.com/rikumi/TimerRoot) 的 conf 驱动版本。
本仓库把那份源码也收进来了：`native/timer.c`。

## 实测状态

设备：realme Neo7（ossi），`6.1.157-android14-11-o-ga43993466696`，SELinux Enforcing。

| 路线 | 结果 |
|---|---|
| root shell（真 cred 零写） | ✅ 三次复现，`uid=0` / `u:r:shell:s0`，但 `CapEff=0`（只有 bset 那三位） |
| KernelSU（fake cred + late-load） | ✅ 一次点击 7 秒完成，`KSU_LOADED`，`su` 在 `u:r:ksu:s0`，`CapEff=000001ffffffffff` |

一次成功运行的日志：

```
[+] plant1 probe off=0x6a8 (slide calibration)
[+] slide=0x287be00000 (probe)
[+] panic_on_warn zero-written (value unreadable)
[+] plant1 fake cred node=0x9c0 blob=0x1f00 layout=6.1
[+] plant1 reaped status=0x9
[+] selinux after write: enforce=0
[fake] worker setresgid=0 setresuid=0 uid=0 euid=0
[rootd] listening /data/local/tmp/rootd.sock uid=0 euid=0
[ksu] try: late-load --kmi android14-6.1 --allow-shell --package-name me.weishu.kernelsu
[ksu] rc=0
KSU_LOADED
```

## 相对上游改了什么

**原生（`native/timer.c`）**

- 6.1 的 `cred.usage` 是 4 字节 → `cred_uid_off=4` 时按 0xa0 布局构造 fake cred；
  6.6/6.12 仍走原来的 0xb8。
- fake cred **故意叠在 rb_node 上**（`pc == node`）。`rb_erase_cached()` 会做
  `leftmost = rb_next(node)`，只有 `pc == node` 时 `rb_next()` 因 `RB_EMPTY_NODE`
  返回 NULL，清理循环才自然结束；把 cred 挪开会让它返回 cred 地址，
  循环再删一次 → panic。
- 因此先打一发无害的 **probe**（零写到自己那页）只为拿 KASLR slide，
  再把 `panic_on_warn` 清零，最后才写 fake cred —— 那条 `WARN_ON_ONCE` 就不会致命。
- 抢页 miss 不再整次报废：旧受害者按「持有僵尸」隔离，换新受害者重试（3 次）。
- 新增 **rootd**：`commit_creds()` 之后 fork 一个常驻进程监听
  `/data/local/tmp/rootd.sock`（0600，owner shell），ksud 失败也不丢本次开机的 root。
- `ksu_stage.sh` 先试 `/data/local/tmp/kernelsu.ko`（自编模块入口），
  再走 ksud late-load 的 KMI 阶梯，失败打 dmesg 尾部。
- ksud 通过 `pm list packages -f` 定位 —— `/data/app` 对 shell 是 0771，`find` 永远空。

**Android 侧**

- `assets/conf/*.conf`：按 `uname -r` 精确匹配，匹配不上直接拒绝启动（不拿别的机型偏移硬跑）。
- 界面/提示中文化；`服务版本` 标记 + `UserServiceArgs.version` 递增，
  避免 Shizuku 复用旧用户服务进程（否则"装了新包还在跑旧代码"）。
- 「自检」查 CapEff / SELinux 域 / `/data` 访问；「root 命令」走 rootd；
  「上次日志」读 `/sdcard/Android/data/<pkg>/files/last-run.log`（重启后也能看）。
- 每次跑之前自动 `am kill-all; sync`，降低抢页时的系统分配噪声。
- KSU 成功判定从「看到 KSU_LOADED」升级为端到端 `su -c id` 是否落在 `u:r:ksu:s0`。

## 构建

```bash
git clone https://github.com/RikkaApps/Shizuku-API
pwsh scripts/build.ps1 -Sdk "$env:LOCALAPPDATA\Android\Sdk" -ShizukuApi ..\Shizuku-API \
     -VersionCode 56 -VersionName "0.55-neo7"
# → build/TimerRoot.apk
```

`scripts/build.ps1` 会自动挑本机最高的 `build-tools` 和带 `framework.aidl` 的
`platform`（也可以用 `-BuildTools` / `-Platform` 指定），签名密钥在
`keystore/debug.jks`，缺失时自动 `keytool` 生成 —— 所以同一个工作区反复构建
始终可以覆盖安装。

> 密钥不进仓库（`*.jks` 被忽略）。**全新克隆会生成一把新密钥**，签出来的 APK
> 无法覆盖安装旧的那份（`INSTALL_FAILED_UPDATE_INCOMPATIBLE`）。
> 想升级安装就把原来的 `keystore/debug.jks` 一起带过来，或者先卸载旧版。

重新编 native（改了 `native/timer.c` 才需要）：

```bash
NDK=/opt/android-ndk sh native/build.sh    # 覆盖 app/src/main/assets/timer
```

## 使用

1. Shizuku 用**无线调试**启动（uid 2000 / `u:r:shell:s0`；root 启动是 `ksu` 域，权限不同）；
2. 打开 App → 确认日志出现「用户服务版本：0.55」；
3. 点 **准备**（`已安装 316608 字节` + ksud 的 `ver=`）；
4. 点 **加载 KernelSU**，一次即可。失败会 park，**不要 kill，重启**。

本次开机内 `su` 与 rootd 都可用；重启全清空 —— 这是临时 root 的固有代价。

## 保持与上游同步

`main` 永远保持和上游一致（不动它），所有改动都在 `neo7` 分支上。
这样 GitHub 的 **Sync fork** 按钮可以直接用，或者在本地：

```bash
git fetch upstream
git checkout main && git merge --ff-only upstream/main && git push origin main   # 镜像上游
git checkout neo7 && git merge main                                             # 把上游更新合进来
```

`neo7` 上的提交按「原生 / Android / 构建 / 文档」分开，冲突面很小：
上游改 `MainActivity` / `UserService` 时，冲突集中在这两个文件，
`native/` 与 `assets/conf/` 不受影响。

## 换到别的机型

链路本身与机型无关，差异全在 conf 的 20 个数值里，可以从 boot.img 自动推：

```bash
python cve98260_auto.py boot.img --out profiles/
#  → profiles/<release>.timer.conf   ← 丢进 app/src/main/assets/conf/ 即可
```

一个 APK 可以同时带多份 conf（按 `uname -r` 选）。推导脚本与踩坑清单见
`cve98260-autoport/`（`PORTING.md`）。

必要条件：漏洞未修补（没有 `posixtimer_exec`）、shell 域能写 tracefs、
4 KiB 页。KSU 路线额外要求内核允许加载模块（`CONFIG_MODULES=y`、
未开 `MODULE_SIG_FORCE`）。

## 声明

仅用于自有设备的兼容性研究与恢复用途。所有常量来自公开的内核镜像分析，
不含任何厂商私有代码。原始漏洞研究归 `woshigenm` / `YuKongA` / `rikumi` 等作者，
遵循 MIT。
