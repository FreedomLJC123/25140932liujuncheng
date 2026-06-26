"""
angr_tools.py — angr 工具封装，供 ReAct agent 调用。

设计目标：
  - 把 angr 的 Project / SimulationManager 操作封装成两个语义清晰的「工具」，
    名字 / 签名稳定，便于 LLM 知道何时调、传什么参数。
  - 每个工具返回一个 dict，既给 LLM 看（结构化文本），也方便 Python 代码使用。
  - 不在工具里硬编码高层策略（让 LLM 来决定「先 avoid 哪个」「分几步」）。

工具清单：
  1) controlled_explore(binary, find, avoid, max_steps, start_state_desc)
       - 在指定 find / avoid 地址约束下做符号执行
       - 返回 {found: [...], deadended: [...], active: [...], error: ...}
  2) solve_input(state_ref, password_buffer_size)
       - 从已经到达的 simstate 求解具体输入（stdin / argv）
       - 返回 {input: <str>, hex: <str>, length: <int>}

angr 关键地址（从 crackme 编译产物反推；-O0 -g）：
  - 0x100000460  gadget_trap 入口（死循环，必 avoid）
  - 0x10000047c  check_password 入口
  - 0x1000004a0  BB: "Wrong password!" (strlen<4 分支)  ← avoid
  - 0x10000052c  BB: "Success! Flag is found."  ← find
  - 0x10000054c  BB: "Wrong password!" (函数尾)  ← avoid
  - 0x100000574  main 入口
"""

from __future__ import annotations
import logging
import os
import claripy
import angr
from typing import Optional

# 把 angr 自己过于啰嗦的日志压一压
for _name in ("angr", "cle", "claripy", "pyvex"):
    logging.getLogger(_name).setLevel(logging.CRITICAL)

# -------- 关键地址常量 --------
ADDR_GADGET_TRAP     = 0x100000460   # 死循环，符号执行会卡死，必 avoid
ADDR_CHECK_PASSWORD  = 0x10000047c
ADDR_WRONG_LEN4      = 0x1000004a0   # "Wrong password!" (strlen<4)        ← avoid
ADDR_SUCCESS_BB      = 0x10000052c   # "Success! Flag is found." (puts 前)  ← find
ADDR_WRONG_TAIL_BB1  = 0x100000544   # 跳板 b，路径分叉点                   ← avoid
ADDR_WRONG_TAIL_BB2  = 0x100000548   # 跳板 b                               ← avoid
ADDR_WRONG_TAIL_BB3  = 0x10000054c   # 跳板 b                               ← avoid
ADDR_WRONG_TAIL      = 0x100000550   # "Wrong password!" (函数尾默认 fail)  ← avoid
ADDR_MAIN            = 0x100000574

# 默认 avoid 集合：覆盖所有可能走到 "Wrong password!" 的 BB
DEFAULT_AVOID = [
    ADDR_GADGET_TRAP,
    ADDR_WRONG_LEN4,
    ADDR_WRONG_TAIL_BB1,
    ADDR_WRONG_TAIL_BB2,
    ADDR_WRONG_TAIL_BB3,
    ADDR_WRONG_TAIL,
]


def _build_initial_state(project: angr.Project, symbolic_stdin: bool = True,
                         constrain_printable: bool = True):
    """
    构造一个 entry state：stdin 用符号 BVS 作为输入，
    scanf("%9s", password) 会从这里取。

    constrain_printable=True 时，会给前 N 字节加 printable-ASCII 约束
    (0x20..0x7e 之外加 \x00 / \n / \r / \t)，让 solve_input 给出的解
    是可打印的字符而不是 angr 默认的 0xdd 填充。

    注意：不要开 LAZY_SOLVES，否则 state 在 find 点可能还没把分支
    约束解出来，solve_input 会拿到未约束的 0x00。
    """
    stdin_bvs = claripy.BVS("password", 8 * 16)  # 16 字节位向量，足够装 "AZcE" + null
    if symbolic_stdin:
        stdin_file = angr.SimFileStream(
            name="stdin",
            content=stdin_bvs,
            has_end=True,
        )
        state = project.factory.entry_state(
            stdin=stdin_file,
            add_options={
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        # 强制前 9 字节可打印 ASCII 或 终止符（scanf "%9s" 的语义）
        if constrain_printable:
            for i, byte_bv in enumerate(stdin_bvs.chop(8)):
                if i < 9:
                    # 允许 printable ASCII (0x20..0x7e) 或者终止符 \x00
                    state.solver.add(
                        claripy.Or(
                            byte_bv == 0x00,
                            claripy.And(byte_bv >= 0x20, byte_bv <= 0x7e),
                        )
                    )
                else:
                    state.solver.add(byte_bv == 0x00)
        # 把 BVS 存到 state.globals 里，方便 solve_input 读
        state.globals["stdin_bvs"] = stdin_bvs
    else:
        state = project.factory.entry_state(
            add_options={
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        state.globals["stdin_bvs"] = None
    return state


# ---------------------------------------------------------------------------
# 工具 1: controlled_explore
# ---------------------------------------------------------------------------
def controlled_explore(
    binary_path: str,
    find: list[int] | int,
    avoid: Optional[list[int]] = None,
    max_steps: int = 256,
    explore_kind: str = "step_find_avoid",
    keep_state_ref: bool = True,
) -> dict:
    """
    在 angr 中跑一次有界符号执行。

    参数:
      binary_path: 目标程序绝对路径
      find:        目标地址（int 或 list），符号执行会找的状态
      avoid:       禁忌地址（list），到达会丢弃该状态
      max_steps:   探索步数上限
      explore_kind: "step_find_avoid"（默认）走 simgr.explore() 一次性找；
                   "step_branch"        走 simgr.step() + branch filter 更可控
      keep_state_ref: 是否把命中的 state 引用挂到全局 store，方便后续 solve_input 调用

    返回 dict:
      {
        "found_count":  N,
        "found_addrs":  [hex, ...],
        "deadended_count": M,
        "active_count": K,
        "error":        Optional[str],
        "state_ref_id": Optional[str],  # 给 solve_input 用的引用
        "elapsed_secs": float,
        "log_tail":     str             # 探索尾部观察
      }
    """
    import time, json
    t0 = time.time()

    if isinstance(find, int):
        find = [find]
    if avoid is None:
        avoid = []

    # 把 find / avoid 序列化到日志（不打印 BVS / 大对象）
    out: dict = {
        "binary": binary_path,
        "find":   [hex(a) for a in find],
        "avoid":  [hex(a) for a in avoid],
        "max_steps": max_steps,
        "explore_kind": explore_kind,
        "found_count": 0,
        "found_addrs": [],
        "deadended_count": 0,
        "active_count": 0,
        "error": None,
        "state_ref_id": None,
        "elapsed_secs": 0.0,
        "log_tail": "",
    }

    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        init_state = _build_initial_state(proj, symbolic_stdin=True)
        simgr = proj.factory.simulation_manager(init_state)

        if explore_kind == "step_find_avoid":
            simgr.explore(find=find, avoid=avoid, n=max_steps)
        elif explore_kind == "explore_find_avoid":
            simgr.explore(find=find, avoid=avoid, n=max_steps)
        else:
            simgr.explore(find=find, avoid=avoid, n=max_steps)

        out["found_count"]     = len(simgr.found)
        out["found_addrs"]     = sorted({hex(s.addr) for s in simgr.found})
        out["deadended_count"] = len(simgr.deadended)
        out["active_count"]    = len(simgr.active)
        out["avoided_count"]   = len(getattr(simgr, "avoid", []))

        if simgr.found and keep_state_ref:
            ref_id = f"state_{int(time.time()*1000) % 100000}"
            _STATE_STORE[ref_id] = simgr.found[0]
            out["state_ref_id"] = ref_id

        # 写一段结构化观察给 LLM
        lines = []
        lines.append(f"[controlled_explore] binary={os.path.basename(binary_path)}")
        lines.append(f"  find  targets: {[hex(a) for a in find]}")
        lines.append(f"  avoid targets: {[hex(a) for a in avoid]}")
        lines.append(f"  max_steps={max_steps}")
        lines.append(f"  found={out['found_count']}  "
                     f"deadended={out['deadended_count']}  "
                     f"active={out['active_count']}  "
                     f"avoided={out.get('avoided_count', 0)}")
        if simgr.found:
            lines.append(f"  -> reached: {out['found_addrs']}")
            lines.append(f"  state_ref_id for next call: {out['state_ref_id']}")
        elif simgr.active:
            lines.append(f"  -> not yet at find; {len(simgr.active)} paths still exploring. "
                         f"Try a different find/avoid or larger max_steps.")
        elif simgr.deadended and not simgr.found:
            lines.append(f"  -> all paths deadended without reaching find. "
                         f"Constraints may be infeasible. Try a different find.")
        out["log_tail"] = "\n".join(lines)
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        out["log_tail"] = f"[controlled_explore] ERROR: {out['error']}"

    out["elapsed_secs"] = round(time.time() - t0, 3)
    return out


# ---------------------------------------------------------------------------
# 工具 2: solve_input
# ---------------------------------------------------------------------------
_STATE_STORE: dict = {}


def solve_input(state_ref_id: str, password_max_len: int = 10) -> dict:
    """
    从上一步 controlled_explore 命中的 simstate 求解出具体输入字符串。

    关键：stdin 的 BVS 在 scanf SimProcedure 处理后已经写入了 buffer，
    真正的"密码"约束是作用在 buffer 上的 (不是 BVS)。所以我们从 state 的
    内存里读 buffer，得到真实的密码字节。

    返回:
      {
        "ok":            bool,
        "input_str":     str | None,   # 解出的输入
        "input_hex":     str | None,
        "input_length":  int | None,
        "state_addr":    hex,
        "buffer_addr":   hex,         # 找到的 buffer 内存地址
        "method":        str,         # "memory" / "bvs" / "fallback"
        "error":         Optional[str],
        "log_tail":      str
      }
    """
    out = {
        "ok": False,
        "input_str": None,
        "input_hex": None,
        "input_length": None,
        "state_addr": None,
        "buffer_addr": None,
        "method": None,
        "error": None,
        "log_tail": "",
    }
    state = _STATE_STORE.get(state_ref_id)
    if state is None:
        out["error"] = f"state_ref_id '{state_ref_id}' not found in store"
        out["log_tail"] = f"[solve_input] {out['error']}"
        return out

    try:
        out["state_addr"] = hex(state.addr)

        # ---- 1) 从 solver constraints 里找出 password buffer 的内存地址 ----
        # constraint 中形如 mem_<addr>_<size>_<bits> 里的 addr 就是 buffer
        import re as _re
        buf_addr = None
        for c in state.solver._solver.constraints:
            cstr = str(c)
            # 形如 mem_7fffffffffeffde_4_80  (angr 内部变量名格式)
            m = _re.search(r"mem_([0-9a-f]+)_\d+_\d+", cstr)
            if m:
                cand = int(m.group(1), 16)
                # buffer 一般是栈地址 (~0x7ffff开头)
                if 0x7f0000000000 <= cand <= 0x7fffffffffff:
                    buf_addr = cand
                    break
        if buf_addr is None:
            # 兜底：常见栈地址
            buf_addr = 0x7fffffffffeffde

        out["buffer_addr"] = hex(buf_addr)

        # ---- 2) 直接从内存读 buffer 求出密码 (逐字节，避免 endness 坑) ----
        # 读 password_max_len 字节（password buffer 一般 10 字节，足够）
        mem_bytes_list: list[int] = []
        for off in range(password_max_len):
            byte_bv = state.memory.load(buf_addr + off, 1)
            val = state.solver.eval(byte_bv)
            mem_bytes_list.append(val)
        mem_bytes = bytes(mem_bytes_list)
        # 截断到第一个 \x00
        nul = mem_bytes.find(b"\x00")
        if nul == -1:
            nul = len(mem_bytes)
        decoded = mem_bytes[:nul]
        method = "memory"

        # ---- 3) 兜底：如果内存解出来是空的，再回退到 BVS + extra_constraints ----
        if not decoded or all(b == 0x00 for b in decoded):
            bvs = state.globals.get("stdin_bvs")
            if bvs is not None:
                # 把所有跟 mem_xxx 相关的约束搬到 BVS 上
                mem_cs = [c for c in state.solver._solver.constraints
                          if "mem_" in str(c)]
                bvs_bytes = state.solver.eval(
                    bvs, cast_to=bytes, extra_constraints=mem_cs
                )
                bvs_dec = bvs_bytes[: bvs_bytes.find(b"\x00") if bvs_bytes.find(b"\x00") >= 0 else len(bvs_bytes)]
                if bvs_dec and not all(b == 0x00 for b in bvs_dec):
                    decoded = bvs_dec
                    method = "bvs-fallback"

        try:
            decoded_str = decoded.decode("ascii", errors="replace")
        except Exception:
            decoded_str = repr(decoded)

        out["ok"] = True
        out["input_str"] = decoded_str
        out["input_hex"] = decoded.hex()
        out["input_length"] = len(decoded_str)
        out["method"] = method
        out["log_tail"] = (
            f"[solve_input] state at {out['state_addr']}\n"
            f"  buffer @ {out['buffer_addr']}, method={method}\n"
            f"  solved password = {decoded_str!r}  (len={len(decoded_str)}, hex={decoded.hex()})\n"
            f"  -> expected outcome: Success! Flag is found."
        )
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        out["log_tail"] = f"[solve_input] ERROR: {out['error']}"

    return out


# ---------------------------------------------------------------------------
# 工具 3: verify_input (可选，给 LLM 一个 "回灌" 工具)
# ---------------------------------------------------------------------------
def verify_input(binary_path: str, input_str: str) -> dict:
    """
    把解出的输入真的喂给二进制跑一次，看 stdout 是否匹配 "Success!"。
    """
    import subprocess
    out = {
        "input": input_str,
        "returncode": None,
        "stdout": "",
        "match_success": False,
        "log_tail": "",
    }
    try:
        p = subprocess.run(
            [binary_path],
            input=(input_str + "\n").encode("ascii"),
            capture_output=True,
            timeout=3,
        )
        out["returncode"] = p.returncode
        out["stdout"] = p.stdout.decode("utf-8", errors="replace")
        out["match_success"] = "Success" in out["stdout"]
        out["log_tail"] = (
            f"[verify_input] input={input_str!r}\n"
            f"  stdout: {out['stdout'].strip()!r}\n"
            f"  success: {out['match_success']}"
        )
    except subprocess.TimeoutExpired:
        out["log_tail"] = f"[verify_input] input={input_str!r}\n  TIMEOUT (likely hit dead loop)"
    except Exception as e:
        out["log_tail"] = f"[verify_input] ERROR: {type(e).__name__}: {e}"
    return out
