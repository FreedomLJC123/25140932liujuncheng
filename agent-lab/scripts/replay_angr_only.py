#!/usr/bin/env python3
"""
本脚本的输出和 ReAct agent 中 3 个 angr 工具的输出完全一致，
"""

import sys
from pathlib import Path

PROJ_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJ_ROOT))

from tools.angr_tools import (
    controlled_explore, solve_input, verify_input,
    ADDR_GADGET_TRAP, ADDR_SUCCESS_BB, ADDR_WRONG_LEN4, ADDR_WRONG_TAIL,
    DEFAULT_AVOID,
)

BINARY = str(PROJ_ROOT / "target" / "crackme")


def main() -> int:
    print("=== Step 1: controlled_explore ===")
    out = controlled_explore(
        binary_path=BINARY,
        find=[ADDR_SUCCESS_BB],
        avoid=list(DEFAULT_AVOID),
        max_steps=512,
    )
    print(out["log_tail"])
    if out["found_count"] == 0:
        print("FAILED: no path to success")
        return 1

    print("\n=== Step 2: solve_input ===")
    sol = solve_input(out["state_ref_id"])
    print(sol["log_tail"])
    if not sol["ok"]:
        print("FAILED: cannot solve input")
        return 1

    print("\n=== Step 3: verify_input ===")
    ver = verify_input(BINARY, sol["input_str"])
    print(ver["log_tail"])
    return 0 if ver["match_success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
