"""
r2_tools.py — radare2 工具封装，供 ReAct agent 调用。

工具清单：
  1) r2_info(binary)               — 快速信息（arch / bits / 类型 / canary / PIE / nx）
  2) r2_strings(binary)            — 字符串列表
  3) r2_functions(binary)          — 函数列表（含地址 / size）
  4) r2_disasm(binary, addr, n)    — 指定地址反汇编 n 条指令
  5) r2_disasm_function(binary, fn) — 反汇编整个函数
  6) r2_cfg_summary(binary, fn)    — 函数的控制流基本信息
  7) r2_xrefs_to(binary, addr)     — 哪些地方引用了 addr
  8) r2_callgraph(binary)          — 简化版调用图（r2 ag-）

底层用 r2pipe（如可用）或 subprocess 调 r2。
"""

from __future__ import annotations
import json
import os
import re
import shutil
import subprocess
import time
from typing import Optional

# ---------------------------------------------------------------------------
# 底层 r2 调用
# ---------------------------------------------------------------------------
_R2_BIN = shutil.which("r2") or shutil.which("radare2")


def _r2_quick(binary: str, cmds: list[str], timeout: int = 60) -> str:
    """
    用 subprocess 调 r2，"-q" 关闭 banner，"-c" 后跟多个命令，命令用分号分隔。
    返回 r2 的 stdout (已 strip ANSI color)。
    """
    if not _R2_BIN:
        raise RuntimeError("r2 not installed (run `brew install radare2`)")
    if not os.path.isfile(binary):
        raise FileNotFoundError(f"binary not found: {binary}")
    cmd_str = ";".join(cmds)
    full = [_R2_BIN, "-q", "-2", "-c", cmd_str, binary]
    out = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    if out.returncode != 0 and not out.stdout:
        raise RuntimeError(f"r2 failed: {out.stderr}")
    # 去掉 ANSI 颜色码
    cleaned = re.sub(r"\x1b\[[0-9;]*m", "", out.stdout)
    return cleaned


def _r2_interactive(binary: str, commands: list[str], timeout: int = 90) -> str:
    """
    用 r2 -i (interactive pipe) 跑多个命令，更适合 aaa 这种带状态变化的。
    """
    if not _R2_BIN:
        raise RuntimeError("r2 not installed")
    if not os.path.isfile(binary):
        raise FileNotFoundError(f"binary not found: {binary}")
    pipe_cmd = "\n".join(commands) + "\n"
    full = [_R2_BIN, "-q", "-2", binary]
    out = subprocess.run(full, input=pipe_cmd, capture_output=True, text=True, timeout=timeout)
    cleaned = re.sub(r"\x1b\[[0-9;]*m", "", out.stdout)
    return cleaned


# ---------------------------------------------------------------------------
# 工具 1: r2_info
# ---------------------------------------------------------------------------
def r2_info(binary: str) -> dict:
    """基本信息：arch/bits/类型/安全特性"""
    t0 = time.time()
    try:
        text = _r2_quick(binary, ["iI"], timeout=30)
    except Exception as e:
        return {"ok": False, "error": str(e), "log_tail": f"[r2_info] {e}"}
    # 解析 (格式: key val, 一行一个)
    info: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            info[parts[0]] = parts[1]
        else:
            info.setdefault("_extra", []).append(line)
    out_text = "\n".join(f"  {k:12s} = {v}" for k, v in info.items() if k != "_extra")
    if "_extra" in info:
        out_text += "\n  (extra: " + ", ".join(info["_extra"][:6]) + ")"
    return {
        "ok": True,
        "info": info,
        "elapsed_secs": round(time.time() - t0, 3),
        "log_tail": f"[r2_info] {os.path.basename(binary)}\n{out_text}",
    }


# ---------------------------------------------------------------------------
# 工具 2: r2_strings
# ---------------------------------------------------------------------------
def r2_strings(binary: str, min_len: int = 4) -> dict:
    t0 = time.time()
    try:
        text = _r2_quick(binary, [f"iz"], timeout=30)
    except Exception as e:
        return {"ok": False, "error": str(e), "log_tail": f"[r2_strings] {e}"}
    rows: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        # 格式: nth paddr vaddr len size section type string
        m = re.match(r"(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.*)", line)
        if not m:
            continue
        nth, paddr, vaddr, slen, ssize, sec, stype, sval = m.groups()
        if int(slen) < min_len:
            continue
        rows.append({
            "n": int(nth),
            "vaddr": vaddr,
            "len":  int(slen),
            "section": sec,
            "type": stype,
            "value": sval,
        })
    pretty = "\n".join(
        f"  [{r['n']:3d}] {r['vaddr']:>12s}  ({r['type']:>6s}, {r['len']:3d}B)  {r['value'][:80]}"
        for r in rows
    ) or "  (no strings found)"
    return {
        "ok": True,
        "count": len(rows),
        "strings": rows,
        "elapsed_secs": round(time.time() - t0, 3),
        "log_tail": f"[r2_strings] {len(rows)} strings (min_len={min_len})\n{pretty}",
    }


# ---------------------------------------------------------------------------
# 工具 3: r2_functions
# ---------------------------------------------------------------------------
def r2_functions(binary: str) -> dict:
    t0 = time.time()
    try:
        # 用 afl，需要先 aaa
        text = _r2_interactive(
            binary,
            ["aaa", "afl"],
            timeout=120,
        )
    except Exception as e:
        return {"ok": False, "error": str(e), "log_tail": f"[r2_functions] {e}"}
    funcs: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"(0x[0-9a-fA-F]+)\s+(\d+)\s+(\d+)\s+(\S+)", line)
        if not m:
            continue
        addr, size, nargs, name = m.groups()
        funcs.append({
            "addr": addr,
            "size": int(size),
            "nargs": int(nargs),
            "name": name,
        })
    pretty = "\n".join(
        f"  {f['addr']}  size={f['size']:4d}  args={f['nargs']}  {f['name']}"
        for f in funcs
    ) or "  (no functions)"
    return {
        "ok": True,
        "count": len(funcs),
        "functions": funcs,
        "elapsed_secs": round(time.time() - t0, 3),
        "log_tail": f"[r2_functions] {len(funcs)} functions\n{pretty}",
    }


# ---------------------------------------------------------------------------
# 工具 4: r2_disasm (N 条指令)
# ---------------------------------------------------------------------------
def r2_disasm(binary: str, addr: str, n: int = 30) -> dict:
    t0 = time.time()
    try:
        # pd N @ addr
        text = _r2_quick(binary, [f"pd {n} @ {addr}"], timeout=30)
    except Exception as e:
        return {"ok": False, "error": str(e), "log_tail": f"[r2_disasm] {e}"}
    return {
        "ok": True,
        "addr": addr,
        "n": n,
        "elapsed_secs": round(time.time() - t0, 3),
        "log_tail": f"[r2_disasm] {n} instructions @ {addr}\n{text}",
    }


# ---------------------------------------------------------------------------
# 工具 5: r2_disasm_function
# ---------------------------------------------------------------------------
def r2_disasm_function(binary: str, function: str) -> dict:
    t0 = time.time()
    try:
        # 需要先 aaa 才会识别 main / entry 等函数边界
        text = _r2_interactive(
            binary,
            ["aaa", f"pdf @ {function}"],
            timeout=120,
        )
        # 过滤掉 r2 的 WARN/INFO 行
        lines = [
            l for l in text.splitlines()
            if l.strip() and not l.strip().startswith(("WARN:", "INFO:", "ERROR:"))
        ]
        if not lines:
            return {
                "ok": False, "function": function,
                "log_tail": f"[r2_disasm_function] {function} → no disassembly output. "
                            f"Is the function name/address correct? Try r2_functions to list all.",
            }
        body = "\n".join(lines)
    except Exception as e:
        return {"ok": False, "error": str(e), "log_tail": f"[r2_disasm_function] {e}"}
    return {
        "ok": True,
        "function": function,
        "elapsed_secs": round(time.time() - t0, 3),
        "log_tail": f"[r2_disasm_function] {function}\n{body}",
    }


# ---------------------------------------------------------------------------
# 工具 6: r2_cfg_summary (basic blocks / branches)
# ---------------------------------------------------------------------------
def r2_cfg_summary(binary: str, function: str) -> dict:
    t0 = time.time()
    try:
        text = _r2_interactive(
            binary,
            ["aaa", f"afi @ {function}"],
            timeout=120,
        )
        lines = [l for l in text.splitlines() if l.strip() and not l.strip().startswith(("WARN:", "INFO:", "ERROR:"))]
    except Exception as e:
        return {"ok": False, "error": str(e), "log_tail": f"[r2_cfg_summary] {e}"}
    return {
        "ok": True,
        "function": function,
        "elapsed_secs": round(time.time() - t0, 3),
        "log_tail": f"[r2_cfg_summary] {function}\n" + "\n".join(lines),
    }


# ---------------------------------------------------------------------------
# 工具 7: r2_xrefs_to
# ---------------------------------------------------------------------------
def r2_xrefs_to(binary: str, addr: str) -> dict:
    t0 = time.time()
    try:
        text = _r2_interactive(
            binary,
            ["aaa", f"axt {addr}"],
            timeout=120,
        )
        lines = [l for l in text.splitlines() if l.strip() and not l.strip().startswith(("WARN:", "INFO:", "ERROR:"))]
    except Exception as e:
        return {"ok": False, "error": str(e), "log_tail": f"[r2_xrefs_to] {e}"}
    return {
        "ok": True,
        "addr": addr,
        "elapsed_secs": round(time.time() - t0, 3),
        "log_tail": f"[r2_xrefs_to] {addr}\n" + ("\n".join(lines) or "  (no xrefs)"),
    }


# ---------------------------------------------------------------------------
# 工具 8: r2_callgraph
# ---------------------------------------------------------------------------
def r2_callgraph(binary: str) -> dict:
    t0 = time.time()
    try:
        text = _r2_quick(binary, ["ag-"], timeout=60)
    except Exception as e:
        return {"ok": False, "error": str(e), "log_tail": f"[r2_callgraph] {e}"}
    return {
        "ok": True,
        "elapsed_secs": round(time.time() - t0, 3),
        "log_tail": f"[r2_callgraph]\n{text[:2000]}{'...' if len(text) > 2000 else ''}",
    }


# ---------------------------------------------------------------------------
# dispatch 字典（agent 用）
# ---------------------------------------------------------------------------
R2_TOOL_DISPATCH = {
    "r2_info":              r2_info,
    "r2_strings":           r2_strings,
    "r2_functions":         r2_functions,
    "r2_disasm":            r2_disasm,
    "r2_disasm_function":   r2_disasm_function,
    "r2_cfg_summary":       r2_cfg_summary,
    "r2_xrefs_to":          r2_xrefs_to,
    "r2_callgraph":         r2_callgraph,
}
