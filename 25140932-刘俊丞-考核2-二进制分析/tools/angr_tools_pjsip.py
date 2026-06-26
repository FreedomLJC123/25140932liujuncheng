"""
angr_tools_pjsip.py — 针对 sipapp 的 angr 工具（简化版）

sipapp 是网络服务（recv/send），完整符号执行需要模拟 socket —— 太重。
这里用 angr 跑 **reachability**：
  - 从某个函数入口起步
  - 入口参数做符号化
  - 找能不能走到已知的 vulnerable sink（vuln_addr）
  - 输出：能 / 不能 + 触发路径

工具：
  1) reachability_test(binary, target_func, vuln_addr, max_steps)
       - 标 target_func 为入口（state 起始地址）
       - 把函数的栈空间当符号 BVS（默认 256B）
       - 跑 angr.explore(find=vuln_addr, avoid=PLT)
       - 返回 found / not-found / 异常
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


def _make_blank_state(binary: str, func_addr: int, stack_size: int = 256):
    """
    从 func_addr 入口建一个空 state（绕过 entry point，避免 libc 初始化），
    栈帧是符号 BVS。返回 (state, bvs)。
    """
    proj = angr.Project(binary, auto_load_libs=False)
    # 在 func_addr 启一个空白 state
    state = proj.factory.blank_state(
        addr=func_addr,
        add_options={
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    # 造一段符号栈
    bvs = claripy.BVS("input", 8 * stack_size)
    state.memory.store(state.regs.sp, bvs)
    # 给前 16 字节加 printable-ASCII 约束（让解出更"合理"）
    for off in range(min(16, stack_size)):
        byte_bv = bvs.chop(8)[off]
        state.solver.add(claripy.Or(
            byte_bv == 0x00,
            claripy.And(byte_bv >= 0x20, byte_bv <= 0x7e),
        ))
    return proj, state, bvs


def reachability_test(
    binary: str,
    target_func: int,
    vuln_addr: int,
    max_steps: int = 1024,
    stack_size: int = 256,
) -> dict:
    """
    测试能不能从 target_func 走到 vuln_addr。

    target_func: 入口函数地址（如 parse_hdr_fromto = 0x42470）
    vuln_addr: sink 地址（如 int_parse_uri_or_name_addr 内某个危险 BB）
    max_steps: 探索步数上限
    """
    t0 = time.time()
    out: dict = {
        "binary": binary,
        "target_func": hex(target_func),
        "vuln_addr":  hex(vuln_addr),
        "max_steps":  max_steps,
        "found":      False,
        "elapsed":    0.0,
        "error":      None,
        "log_tail":   "",
    }
    try:
        proj, state, bvs = _make_blank_state(binary, target_func, stack_size)
        simgr = proj.factory.simulation_manager(state)
        simgr.explore(find=[vuln_addr], n=max_steps)
        out["found"] = bool(simgr.found)
        out["active"]    = len(simgr.active)
        out["deadended"] = len(simgr.deadended)
        out["avoided"]   = len(getattr(simgr, "avoid", []))
        out["elapsed"]   = round(time.time() - t0, 3)
        out["log_tail"]  = (
            f"[reachability_test] from {hex(target_func)} → {hex(vuln_addr)}\n"
            f"  found={out['found']}  active={out['active']}  "
            f"deadended={out['deadended']}  avoided={out['avoided']}  "
            f"({out['elapsed']}s)"
        )
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        out["log_tail"] = f"[reachability_test] ERROR: {out['error']}"
    return out


# ---------------------------------------------------------------------------
# 工具：针对 sipapp 的预置 sink 地址
# ---------------------------------------------------------------------------
# 这些地址是 Ghidra / r2 看出来的，是 sipapp 内可能 vulnerable 的 sink
# （不是 exploit 地址，只是"如果能走到这里就说明有路径"）
KNOWN_SINKS = {
    # int_parse_uri_or_name_addr 入口 (PJSIP URI 解析) — 主要 sink
    "int_parse_uri_or_name_addr":  0x00041038,
    # parse_hdr_fromto 内部对 int_parse_param 的调用
    "int_parse_param_in_fromto":   0x000424c8,  # 估算
    # pj_pool_alloc（内存分配，可作为"成功解析完"标志）
    "pj_pool_alloc_in_parser":     0x0003e2b0,
}


# ---------------------------------------------------------------------------
# 工具：尝试从某函数走到 sink，可携带任意外部状态
# ---------------------------------------------------------------------------
def explore_to(
    binary: str,
    target_func: int,
    find: list[int] | int,
    avoid: Optional[list[int]] = None,
    max_steps: int = 1024,
    stack_size: int = 256,
    timeout: int = 60,
) -> dict:
    """更通用的 explore，可指定 find/avoid 列表"""
    import time
    t0 = time.time()
    if isinstance(find, int):
        find = [find]
    avoid = avoid or []
    out = {
        "binary":  binary,
        "from":    hex(target_func),
        "find":    [hex(a) for a in find],
        "avoid":   [hex(a) for a in avoid],
        "found":   False,
        "elapsed": 0.0,
        "error":   None,
        "log_tail": "",
    }
    try:
        proj, state, bvs = _make_blank_state(binary, target_func, stack_size)
        simgr = proj.factory.simulation_manager(state)
        simgr.explore(find=find, avoid=avoid, n=max_steps)
        out["found"]       = bool(simgr.found)
        out["active"]      = len(simgr.active)
        out["deadended"]   = len(simgr.deadended)
        out["avoided"]     = len(getattr(simgr, "avoid", []))
        out["elapsed"]     = round(time.time() - t0, 3)
        out["log_tail"]    = (
            f"[explore_to] from {out['from']} → {out['find']}\n"
            f"  found={out['found']}  active={out['active']}  "
            f"deadended={out['deadended']}  avoided={out['avoided']}  "
            f"({out['elapsed']}s)"
        )
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        out["log_tail"] = f"[explore_to] ERROR: {out['error']}"
    return out
