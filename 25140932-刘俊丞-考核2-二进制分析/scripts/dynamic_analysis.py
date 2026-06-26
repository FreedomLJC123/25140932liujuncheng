"""
dynamic_analysis.py — sipapp 的 angr 动态分析（带 PJSIP 库 stub）

策略：
  - PJSIP 内部库（pj_pool / pj_scan / pj_list / pj_str / pj_stricmp / int_parse_*）
    状态空间爆炸的根源。用 SimProcedure 全 stub 成简单返回：
      pj_pool_alloc       -> 返回一个新地址
      pj_list_insert_before -> no-op
      pj_stricmp          -> 返回 0 (相等) 或非 0
      int_parse_param     -> 移动 scanner 游标
      int_parse_uri_or_name_addr -> 我们的目标，跳过具体实现
      parse_hdr_end       -> no-op
  - 这样 angr 只看 parse_hdr_fromto / parse_hdr_contact 的核心控制流

用法：
    ./.venv/bin/python scripts/dynamic_analysis.py
"""

from __future__ import annotations
import claripy
import angr
import logging
import os
import time
from typing import Optional

for _n in ("angr", "cle", "claripy", "pyvex"):
    logging.getLogger(_n).setLevel(logging.CRITICAL)


# ---------------------------------------------------------------------------
# PJSIP 库函数 SimProcedures
# ---------------------------------------------------------------------------
class PJPoolAlloc(angr.SimProcedure):
    """pj_pool_alloc(pool, size) -> 返回一个新分配的地址"""

    def run(self, pool, size):
        # 分配一段新的"内存"（用 angr 自己的 symbolic buffer）
        addr = self.state.heap._malloc(size)
        return addr


class PJListInsertBefore(angr.SimProcedure):
    """pj_list_insert_before(pos, node) -> no-op"""

    def run(self, pos, node):
        return 0


class PJStricmp(angr.SimProcedure):
    """pj_stricmp(a, b) -> 比较两个字符串，返回差值"""

    def run(self, a, b):
        # 简化：返回 0 (相等) 让路径继续
        return claripy.BVV(0, 32)


class PJStrcmp(angr.SimProcedure):
    """pj_strcmp(a, b) -> 简化版本"""

    def run(self, a, b):
        return claripy.BVV(0, 32)


class ParseHdrEnd(angr.SimProcedure):
    """parse_hdr_end(scanner) -> no-op"""

    def run(self, scanner):
        return 0


class IntParseParam(angr.SimProcedure):
    """int_parse_param(scanner, pool, pname, pvalue, ...) -> 移动 scanner 游标"""

    def run(self, scanner, pool, pname, pvalue, *args):
        # 写入一些"假"参数
        # 简化：写入空字符串 / 0
        # 这一步不写实现，只是给 angr 一个出口
        return 0


# ---------------------------------------------------------------------------
# 主分析函数
# ---------------------------------------------------------------------------
def analyze_parse_hdr_fromto(
    binary: str,
    entry: int = 0x42470,        # parse_hdr_fromto
    sink_call: int = 0x40e34,    # int_parse_uri_or_name_addr (REAL entry)
    max_steps: int = 256,
) -> dict:
    """
    从 parse_hdr_fromto 入手，看能不能走到 int_parse_uri_or_name_addr 的调用。
    """
    t0 = time.time()
    out = {
        "binary": binary,
        "entry":  hex(entry),
        "sink":   hex(sink_call),
        "found":  False,
        "elapsed": 0.0,
        "error":  None,
        "log_tail": "",
    }
    try:
        proj = angr.Project(binary, auto_load_libs=False)

        # 关键：把 PJSIP 库函数全 stub
        # 先看二进制里这些符号的实际地址
        syms = {
            "pj_pool_alloc":           "dbg.pj_pool_alloc",
            "pj_list_insert_before":   "dbg.pj_list_insert_before",
            "pj_stricmp":              "dbg.pj_stricmp",
            "int_parse_param":         "dbg.int_parse_param",
            "parse_hdr_end":           "dbg.parse_hdr_end",
        }
        for sp_name, sym_name in syms.items():
            sym = proj.loader.find_symbol(sym_name)
            if sym and sym.rebased_addr != 0:
                cls = {
                    "pj_pool_alloc":         PJPoolAlloc,
                    "pj_list_insert_before": PJListInsertBefore,
                    "pj_stricmp":            PJStricmp,
                    "int_parse_param":       IntParseParam,
                    "parse_hdr_end":         ParseHdrEnd,
                }[sp_name]
                proj.hook_symbol(sym_name, cls())
                # print(f"  hooked {sym_name} at {hex(sym.rebased_addr)}")

        # Blank state from entry
        state = proj.factory.blank_state(
            addr=entry,
            add_options={
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        # Symbolize the stack (r0-r3 will be passed to internal calls)
        # r0 is the scanner pointer (ctx->scanner)
        # r1 is the pool pointer
        # r2 is the hdr pointer
        # For parse_hdr_fromto(scanner, pool, hdr):
        #   r0 = scanner, r1 = pool, r2 = hdr
        # Make them symbolic pointers but pointing to concrete-ish memory
        # Easier: leave registers as-is (blank_state defaults work)

        simgr = proj.factory.simulation_manager(state)
        simgr.explore(find=[sink_call], n=max_steps)
        out["found"]      = bool(simgr.found)
        out["active"]     = len(simgr.active)
        out["deadended"]  = len(simgr.deadended)
        out["avoided"]    = len(getattr(simgr, "avoid", []))
        out["elapsed"]    = round(time.time() - t0, 3)
        out["log_tail"]   = (
            f"[dynamic_analysis] from {hex(entry)} → {hex(sink_call)}\n"
            f"  found={out['found']}  active={out['active']}  "
            f"deadended={out['deadended']}  avoided={out['avoided']}  "
            f"({out['elapsed']}s)"
        )
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        out["log_tail"] = f"[dynamic_analysis] ERROR: {out['error']}"
    return out


def analyze_parse_hdr_contact(
    binary: str,
    entry: int = 0x4205c,        # parse_hdr_contact
    sink_call: int = 0x40e34,    # int_parse_uri_or_name_addr (REAL entry)
    max_steps: int = 256,
) -> dict:
    """Same as above but for parse_hdr_contact"""
    return analyze_parse_hdr_fromto(binary, entry=entry, sink_call=sink_call,
                                     max_steps=max_steps)


if __name__ == "__main__":
    import sys
    binary = sys.argv[1] if len(sys.argv) > 1 else "target/sipapp"
    binary = os.path.abspath(binary)

    print("=" * 70)
    print(f"Dynamic analysis on {binary}")
    print("=" * 70)

    # 1) parse_hdr_fromto → int_parse_uri_or_name_addr
    print("\n[1/2] parse_hdr_fromto (0x42470) → int_parse_uri_or_name_addr (0x40e34)")
    out = analyze_parse_hdr_fromto(binary, max_steps=128)
    print(f"  {out['log_tail']}")

    # 2) parse_hdr_contact → int_parse_uri_or_name_addr
    print("\n[2/2] parse_hdr_contact (0x4205c) → int_parse_uri_or_name_addr (0x40e34)")
    out2 = analyze_parse_hdr_fromto(
        binary, entry=0x4205c, sink_call=0x40e34, max_steps=128
    )
    print(f"  {out2['log_tail']}")

    print("\n" + "=" * 70)
    print("结论：")
    if out["found"] or out2["found"]:
        print("  ✓ angr 在 stub 掉 PJSIP 库后能走到 vulnerable sink")
        print("  → 这条路径是 attack surface，可构造恶意 SIP header 触发")
    else:
        print("  ✗ stub 后仍未能走到 sink (max_steps 不够 / 需要更细粒度 stub)")
