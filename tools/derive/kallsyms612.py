#!/usr/bin/env python3
"""kallsyms612.py — Linux 6.12 GKI Image 符号表提取器（无需 ELF、无需符号）。

用法：
    python3 kallsyms612.py <Image> [out.json]

相对旧的 extract_symbols_auto.py，6.12 有三处必须改的地方，本文件全部覆盖：

  1. `kallsyms_names` 每条记录的长度是 **1 或 2 字节**：长度字节最高位为 1 时，
     真实长度 = (b0 & 0x7f) | (b1 << 7)。只按单字节读会把长名字跳过头，
     128943 条会数成 128922 条，整张表从此错位、数据符号全错。
  2. `kallsyms_offsets` 的起点不是紧跟 token_index，而是**再对齐 8 字节**
     （token_index 之后有 4~8 字节 padding）。偏移 1 项就会让所有数据符号错位。
  3. 三者长度关系：offsets 项数 == names 条数 == kallsyms_num_syms；
     relative_base 紧跟在 offsets 数组之后（8 字节、页对齐）。

定位锚点（靠结构特征，不靠扫描猜测）：
    token_index : 256 个严格递增 u16，首项 0，末项 < 0x2000
    token_table : token_index 之前、256 个 \\0 结尾的字符串
    markers     : token_table 之前、首项 0 的递增 u32 数组（每项 256 条）
    names_start : 走 256 条正好落在 start + markers[1]
    offsets     : relative_base_pos - 4 * names_count，且必须单调不减

自检锚点（解析完可人工核对）：
    _text          应为 MZ 头（ARM64 .head.text）
    _stext         paciasp
    linux_banner   "Linux version x.y.z-..."
    panic_on_oops / panic_timeout / panic_on_warn 三者地址相邻
"""
import json
import struct
import sys
from pathlib import Path


def find_token_index(d, lo=0, hi=None):
    """返回 (idx_pos, table_pos)。"""
    n = len(d)
    hi = n - 512 if hi is None else hi
    p = lo
    while p < hi:
        if d[p] != 0 or d[p + 1] != 0:
            p += 2
            continue
        idx = struct.unpack_from("<256H", d, p)
        if idx[0] != 0 or idx[255] >= 0x2000:
            p += 2
            continue
        ok = True
        for i in range(1, 256):
            if idx[i] <= idx[i - 1]:
                ok = False
                break
        if not ok:
            p += 2
            continue
        # token_table 起点：p 之前 0x2000 内找让 7 个抽样 token 都成立的位置
        for t in range(max(0, p - 0x2000), p):
            good = 0
            for i in (0, 1, 2, 3, 128, 254, 255):
                q = t + idx[i]
                if q >= p:
                    break
                if (q == t or d[q - 1] == 0) and 0x20 <= d[q] < 0x7F:
                    good += 1
            if good == 7:
                return p, t
        p += 2
    return None, None


def read_tokens(d, t, idx_pos):
    toks, q = [], t
    for _ in range(256):
        z = d.find(b"\x00", q, idx_pos + 512)
        if z < 0:
            return None
        toks.append(d[q:z].decode("latin1"))
        q = z + 1
    return toks


def parse_names(d, tokens, start, end):
    """6.12 规则：长度字节最高位为 1 表示两字节长度。"""
    names, p, big = [], start, 0
    while p < end:
        ln = d[p]
        p += 1
        if ln == 0:
            break
        if ln & 0x80:
            if p >= end:
                break
            ln = (ln & 0x7F) | (d[p] << 7)
            p += 1
            big += 1
        if p + ln > end:
            break
        s = []
        for _ in range(ln):
            s.append(tokens[d[p]])
            p += 1
        names.append("".join(s))
    return names, p, big


def main():
    img = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    d = img.read_bytes()

    idx_pos, table_pos = find_token_index(d)
    if idx_pos is None:
        sys.exit("token_index 未找到")
    tokens = read_tokens(d, table_pos, idx_pos)
    if not tokens:
        sys.exit("token_table 读取失败")
    print(f"[+] token_table @ {table_pos:#x}  token_index @ {idx_pos:#x}")

    # markers：token_table 之前、首项 0 的递增 u32
    m_start = None
    for off in range(table_pos - 4, max(0, table_pos - 0x4000), -4):
        if struct.unpack_from("<I", d, off)[0] != 0:
            continue
        vals = struct.unpack_from("<4I", d, off)
        if vals[0] == 0 and 0 < vals[1] < vals[2] < vals[3]:
            m_start = off
            break
    if m_start is None:
        sys.exit("markers 未找到")

    # names_start：两条约束
    #   (a) 走 256 条必须落在 start + markers[1]
    #   (b) kallsyms_num_syms 紧贴在 names 之前 8 字节（u32 + 4 字节 0），
    #       且走完全流到 markers 的条数正好等于它
    m1 = struct.unpack_from("<I", d, m_start + 4)[0]

    def walk(s, n, limit):
        q = s
        for _ in range(n):
            if q >= limit:
                return None
            ln = d[q]
            q += 1
            if ln == 0:
                return None
            if ln & 0x80:
                if q >= limit:
                    return None
                ln = (ln & 0x7F) | (d[q] << 7)
                q += 1
            q += ln
        return q

    ns = n_expected = None
    cands = []
    lo = max(0, m_start - 0x600000)
    for q in range(lo, m_start - 8, 4):
        v = struct.unpack_from("<I", d, q)[0]
        if not (20000 <= v <= 600000):
            continue
        if struct.unpack_from("<I", d, q + 4)[0] != 0:
            continue
        s = q + 8
        if walk(s, 256, m_start) == s + m1:
            cands.append((s, v))
    for s, v in cands:
        if walk(s, v, m_start) == m_start:
            ns, n_expected = s, v
            break
    if ns is None:
        sys.exit("names_start 未校准")
    print(f"[+] markers @ {m_start:#x}  names @ {ns:#x}  num_syms={n_expected}")

    names, endp, big = parse_names(d, tokens, ns, m_start)
    N = len(names)
    print(f"[+] names: {N} 条（两字节长度的 {big} 条），结束 {endp:#x} / markers {m_start:#x}")
    if endp != m_start:
        print(f"[!] 终点差 {m_start - endp} 字节")

    # relative_base：token_index 之后找页对齐高地址。
    # offsets 与 relative_base 之间可能有 0~8 字节对齐 padding，所以起点要试 ±4，
    # 再用「_text 处是 MZ 头、linux_banner 处是 "Linux version"」两条内容判据挑。
    idx_of = {}
    for i, s in enumerate(names):
        idx_of.setdefault(s[1:], i)

    def verify(v_base, o):
        try:
            offs_probe = struct.unpack_from(f"<{N}i", d, o)
        except struct.error:
            return False
        for nm, magic in (("linux_banner", b"Linux version"), ("_text", b"MZ")):
            i = idx_of.get(nm)
            if i is None or i >= N:
                continue
            off = offs_probe[i]
            if off < 0 or off + len(magic) > len(d):
                return False
            if d[off:off + len(magic)] != magic:
                return False
        return True

    base = base_pos = o_start = None
    for pos in range(idx_pos + 512, min(idx_pos + 512 + 0x400000, len(d) - 8), 8):
        v = struct.unpack_from("<Q", d, pos)[0]
        if not (0xFFFF000000000000 <= v < 0xFFFFFFFFFFFFFFFF) or v % 0x1000:
            continue
        for pad in (0, -4, 4, -8, 8):
            cand = pos - 4 * N + pad
            if cand < idx_pos + 512 or cand + 4 * N > pos + 16:
                continue
            if struct.unpack_from("<I", d, cand)[0] > 0x100000:
                continue
            if verify(v, cand):
                base, base_pos, o_start = v, pos, cand
                break
        if base is not None:
            break
    if base is None:
        sys.exit("relative_base / offsets 起点未解析")
    print(f"[+] offsets @ {o_start:#x}  relative_base = {base:#x} @ {base_pos:#x}")

    offs = struct.unpack_from(f"<{N}i", d, o_start)
    syms, dup = {}, 0
    for i, nm in enumerate(names):
        if i >= len(offs):
            break
        o = offs[i]
        addr = (base + o) if o >= 0 else (-o - 1)
        body = nm[1:]
        if body in syms:
            dup += 1
        syms[body] = addr

    print(f"[+] 符号 {len(syms)} 条（重名覆盖 {dup} 次）")
    for k in ("_text", "linux_banner", "init_cred", "selinux_state", "panic_on_warn"):
        if k in syms:
            print(f"      {k:16s} {syms[k]:#x}")

    if out:
        out.write_text(json.dumps({k: hex(v) for k, v in syms.items()}, indent=0))
        print(f"[+] 写出 -> {out}")


if __name__ == "__main__":
    main()
