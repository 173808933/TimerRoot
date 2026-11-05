# TimerRoot

Android front end for **CVE-2026-98260** (POSIX CPU timer use-after-free), the
same class of bug as CVE-2026-64560. One tap gives you a root shell and then
late-loads **KernelSU** (`u:r:ksu:s0`).

The exploit itself is *not* included here. This repository is the app shell
around it: UI, state detection and the Shizuku plumbing needed to run a
shell-domain exploit from an ordinary app.

## What this branch (`conf-driven`) changes

Cut from `main` (upstream mirror `b97535b`). Everything is additive — upstream
code paths stay untouched for devices that don't use these features.

### 1. Exploit built from source, driven by a conf (`4562388`, `bce859b`)

- `native/timer.c` (2.6k lines) and `native/build.sh`: a 6.1 port of the
  POSIX-timer exploit, driven entirely by a text profile instead of hard-coded
  offsets.
- Ships four profiles under `app/src/main/assets/conf/`, one per kernel
  release (6.1.157 and three 6.1.141 builds). The file name *is* the release;
  the app picks the one that matches `uname -r` exactly and refuses to start
  on a kernel it has no profile for.
- `UserService.java` gains `rootdExec()` / `suCheck()` / `exportLog()` so one
  race attempt can leave a resident `rootd` alive for the rest of the boot
  instead of gambling again.
- Chinese UI, plus a guard against starting the flow twice.

### 2. Import a conf at runtime (`bed3d95`, `cda31a3`)

A new device used to mean rebuilding the APK. Now a conf can be pushed to
`/data/local/tmp/conf.d` or imported through the UI, validated against
`uname -r` before use.

`IUserService.aidl` grew four methods, so `UserServiceArgs.version` had to go
7 → 8. Shizuku caches the user-service process keyed on that number; an old
process would deserialise the new AIDL incorrectly.

### 3. Derive a profile on the device (`7573859`)

- `ota/BootImageParser.kt` (646 lines): unpacks boot v2–v4, decompresses the
  gzip / lz4 / lz4-legacy kernel and locates the arm64 `Image`.
- `ota/KallsymsExtractor.kt` (747 lines): recovers the compressed kallsyms
  (token table, markers, names, offsets, relative base) straight from the image.
- `ota/Deriver.kt`: turns those symbols plus BTF into a complete conf.

Validated by generating profiles from two real boot images and diffing all 20
fields against the hand-written confs — identical.

### 4. Manager picker (`0.59`)

Auto-detection was already content-based: any installed package that ships
`lib/arm64/libksud.so` is accepted, so renamed forks (SukiSU, ReSukiSU,
KSU-Next, Bakasu, SuperManager) work without a list. The known-name array only
orders the candidates, so an unrelated app that happens to bundle `libksud.so`
cannot win by being earlier in `pm` output.

What was missing was an escape hatch. If two managers are installed, or the
wrong package gets picked, there was no way to override it short of
uninstalling. Now:

- `ksuManagers()` lists every package that carries `libksud.so` (plus names
  that look like a manager, whose lib may live inside the APK).
- `setKsuManager(pkg)` writes `/data/local/tmp/ksud.pkg.override`; the prepare
  path consults it first and falls back to auto if that package has no ksud.
  `setKsuManager("auto")` deletes the file.
- The details card grew a "管理器" row showing `自动 · <pkg>` or
  `手动 · <pkg>`; tapping it opens the picker.

`IUserService.aidl` grew two methods, so `UserServiceArgs.version` goes
8 → 9.

### 5. KernelSU state is judged by running su (`0.63`)

`suCheck()` used to open with `new File("/system/bin/su").exists()` and bail out
with "su 不存在" when the file was missing. That check is wrong for every
KernelSU that ships built-in su: `su_compat` rewrites `execve("/system/bin/su")`
to a memfd-backed blob inside the kernel (the module carries the
`install su session fd failed` path), so **the file never exists on disk**. The
same test was used by `info()`, which is why the UI kept reporting KernelSU as
"not loaded" even when `kernelsu` was sitting in `/proc/modules`.

The check is now an actual execution: `su`, `/system/bin/su`,
`/data/adb/ksu/bin/su` are tried in order, and success means `id` reports
`uid=0` (the user service itself runs as shell/2000, so nothing else can produce
it). On failure the first real error is printed instead of a guess. `info()`
uses the same helper, and tapping "加载 KernelSU" once KSU is active re-runs the
verification instead of re-running the exploit, which would only park another
zombie. `UserServiceArgs.version` goes 9 → 10.

### 6. vivo tail work, opt-in per device (`0.66`)

OriginOS kills a process on `sys_exit` if its cred was just changed, and keeps a
`riskdetect` watchdog around; both break `su` right after it starts working.
The fix is a tail stage, but it must never fire on a ColorOS/other device, so it
is gated three times:

1. the app sends `TIMER_VIVO=0` unless the device is vivo (or the user forces it
   on in **vivo 适配** on the details card);
2. the conf must carry `vivo_disarm = 1`;
3. the conf must also carry a plausible `sys_exit_tp` (kernel address).

When all three pass, the fake stage zeroes `__tracepoint_sys_exit.funcs`
(`+0x48`, derived from `vr.ko` relocations) before the worker execs `ksud`, and
the ksud script runs `stop riskdetect` first. The `funcs` pointer is what the
tracepoint iterator walks, so a NULL there disables every vendor callback on
that tracepoint without touching their bookkeeping.

Confs for non-vivo kernels simply do not have those two keys, which is why the
same binary stays a no-op there.

### 7. ADB mode: no Shizuku (`0.69`)

Shizuku was never a permission source; it is just one way to get a shell-domain
process. The app can also act as an ADB client itself:

- **连接方式** on the details card switches between *Shizuku* and *ADB 直连*.
- In ADB mode you enter the pairing port and the 6-digit code from
  *Developer options → Wireless debugging → Pair device with pairing code*.
  Pairing is SPAKE2 + TLS; the RSA key and self-signed cert live in the app's
  private directory (`0600`, generated on first use).
- The connect port is **not** entered: after pairing, the client discovers
  `_adb-tls-connect._tcp` over mDNS. Ports change per boot, the pairing key does
  not.
- One tap then deploys `assets/timer` + the matching conf to
  `/data/local/tmp`, runs `timer --conf timer.conf fake`, polls `timer.log`
  and finally runs `su -c id`.

The exploit binary and conf are untouched — only the shell provider changed.

Built with [LibADB](https://github.com/MuntashirAkon/libadb-android) 3.1.1
(pure Java), bcprov/bcpkix 1.81 and spake2-android. This adds ~2 MB to the APK.

Limits: Android 11+ only (wireless debugging is TLS), mDNS must work on the
ROM (there is no manual host:port TLS path in LibADB), and wireless debugging
has to be re-enabled after every reboot.

### Behaviour differences

| Scenario | Upstream | This branch |
|---|---|---|
| Device with a built-in conf | works | works, same code path |
| Device without one | rebuild the APK | import a conf, or derive it from `boot.img` on the phone |
| Second attempt in the same boot | — | blocked by `.lock2`; reboot first |

---

## Why the app needs Shizuku

An app runs as `untrusted_app` and cannot read `/sys/kernel/tracing`, which the
exploit needs for its leak and trigger. TimerRoot therefore starts a **Shizuku
user service**, which Shizuku runs as the shell user (`uid 2000`,
`u:r:shell:s0`). The exploit binary executes inside that process, so it gets
the same environment it would have from `adb shell`.

```
MainActivity (untrusted_app)
  └─ Shizuku user service (uid 2000, u:r:shell:s0)
       ├─ extracts assets/timer to /data/local/tmp/timer
       └─ runs it; on success keeps /system/bin/sh alive
```

## Requirements

- Android 12+ (`minSdk 30`), arm64
- [Shizuku](https://shizuku.rikka.app/) running (start it from the Shizuku app
  via wireless debugging, or over ADB)
- [KernelSU](https://github.com/tiann/KernelSU) manager installed, for the
  `Load KernelSU` path
- A kernel build the exploit was ported to. The upstream binary targets
  `6.12.69-android16-6-g242e1a07f878-ab15865446-4k`; see below.

## Getting the exploit binary

TimerRoot expects the compiled exploit at `app/src/main/assets/timer`:

```bash
git clone https://github.com/YuKongA/CVE-2026-98260
cp CVE-2026-98260/timer/timer app/src/main/assets/timer
```

or

```powershell
scripts/fetch-timer.ps1
```

The binary is MIT licensed by its authors; only use it on hardware you own, and
only when your kernel matches the build it was ported to.

## Build

### Android Studio / Gradle

Open the project and build, or:

```bash
./gradlew assembleDebug
```

The project needs the Android SDK with platform 36 and build-tools 36. The
Shizuku API is pulled from Maven (`dev.rikka.shizuku:api`).

### Without Gradle

`scripts/build.ps1` builds and signs an APK with just the SDK, `javac`, `d8`,
`aapt2` and `apksigner`. It vendors nothing: it compiles the app together with
the Shizuku API sources, so clone those first:

```powershell
git clone https://github.com/RikkaApps/Shizuku-API
scripts/build.ps1 -Sdk "C:\Users\<you>\AppData\Local\Android\Sdk"
```

## Usage

### 1. Start Shizuku

Shizuku has to be running before TimerRoot can do anything: it is the process
that provides the shell user the exploit needs. Shizuku stops on every reboot,
so this is the first step each time.

**Wireless debugging (no PC after the first pairing)**

1. Enable developer options: Settings -> About device -> tap *Build number* 7x.
2. Settings -> System -> Developer options -> **Wireless debugging** -> on.
3. Open the Shizuku app -> **Start** -> *Start via wireless debugging*.
4. Allow the notification, then in *Pair device with pairing code* enter the
   6-digit code shown on the phone.
5. Shizuku reports "Shizuku is running" (the notification says the server is up).

**Over USB**

With the phone connected and USB debugging authorised:

```bash
adb shell sh /sdcard/Android/data/moe.shizuku.privileged.api/start.sh
```

Newer Shizuku releases may not ship that script any more; if it is missing, use
the wireless debugging route above.

Check that the server is up:

```bash
adb shell ps -A | grep shizuku_server
# shell  12345  1  ...  shizuku_server
```

`ps` showing only `moe.shizuku.privileged.api` means the manager app is open but
the server is **not** running; the exploit cannot start until it is.

### 2. First launch

1. Open TimerRoot.
2. When Shizuku asks *Allow TimerRoot to access Shizuku?*, choose
   **Allow all the time**.
3. The card turns **Ready** (Shizuku connected, no root yet). If it still says
   `Not connected`, press `Shizuku` in the tools row to request again.

### 3. Prepare (automatic)

Nothing to press. As soon as Shizuku grants access the app extracts
`assets/timer` to `/data/local/tmp/timer`, picks the conf whose `release`
matches `uname -r` exactly, locates `ksud`, and runs `am kill-all; sync`.
The `准备` pill in Tools only repeats it.

If the card says `conf=none`, this build has no profile for that kernel: import
one, or derive it from the OTA link (see above).

### 4. One tap: root + KernelSU

Press **一键 root + KernelSU**. A single exploit run does the whole job:

```
[+] slide=0x1988600000 (probe)
[+] panic_on_warn zero-written (value unreadable)
[+] fake cred armed: task=... cred=... mode=fake
[+] selinux after write: enforce=0
[fake] worker setresgid=0 setresuid=0 uid=0 euid=0
[rootd] listening /data/local/tmp/rootd.sock uid=0 euid=0
[ksu] try: late-load --kmi android14-6.1 --allow-shell --package-name ...
[ksu] rc=0
KSU_LOADED
—— 验证 su ——
module: kernelsu ...
via: su
id: uid=0(root) ... context=u:r:ksu:s0
```

The success sheet offers **打开管理器** (grant apps / load modules) and
**重启设备**.

Why one run instead of two: the fake-cred stage is the only one that ends with
full capabilities and SELinux permissive, which is exactly what `ksud
late-load` needs. The old shell-only run is still there as **只获取 root
Shell** for troubleshooting, but it is no longer a prerequisite — pressing it
first just parks a second process for nothing.

### 5. Reboot

Use the `重启设备` button in the success sheet, or the same action when a run
fails. Rebooting is the only clean way to remove parked processes and unload
KernelSU.

After rebooting, start again from step 1: Shizuku is stopped and KernelSU is
gone.

The status card reflects what is actually live, detected by running
`su -c id` and checking for `u:r:ksu:s0`:

| card | meaning |
|---|---|
| Not connected | Shizuku is not running / not bound |
| Ready | Shizuku connected, no root yet |
| Root shell | `uid=0`, `u:r:shell:s0` |
| Jailbreak mode | KernelSU loaded, `su` works in `u:r:ksu:s0` |


## Safety

This is a kernel exploit. Read this before pressing anything.

- **Do not kill a parked process.** The exploit keeps a process alive with the
  fake credential page pinned in socket buffers. Reaping it can panic the
  kernel. Reboot is the only clean way to remove it.
- **A reboot clears everything**: KernelSU, the root shell and the parked
  processes. That is the intended way to stop.
- **SELinux is left permissive** until the next reboot.
- A failed attempt leaves a stale timerqueue node; other apps may crash until
  you reboot.
- Only use this on a device you own or are explicitly allowed to modify.

## Layout

```
app/src/main/java/com/kpgc/timerroot/MainActivity.java   UI and state
app/src/main/java/com/kpgc/timerroot/UserService.java    runs as the shell user
app/src/main/aidl/com/kpgc/timerroot/IUserService.aidl   service interface
app/src/main/assets/timer                                exploit binary (not in git)
scripts/build.ps1                                        Gradle-free build
```

## Credits

- Exploit: [YuKongA/CVE-2026-98260](https://github.com/YuKongA/CVE-2026-98260)
  (MIT), based on work by woshigenm and the other 98260 ports.
- [Shizuku](https://github.com/RikkaApps/Shizuku) and
  [Shizuku-API](https://github.com/RikkaApps/Shizuku-API) (Apache-2.0) by Rikka.
- KernelSU (GPL-2.0) for the late-load path.

## License

MIT for the app code in this repository. The exploit binary and the Shizuku API
keep their own licenses.
