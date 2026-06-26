#!/usr/bin/env python3
"""
replay_no_llm.py — 不依赖 LLM，串行跑 r2 + Ghidra 主要工具展示静态分析能力。

用法：
    /path/to/venv/bin/python scripts/replay_no_llm.py

跑完会在 stdout 打印：
  1) r2_info 输出
  2) r2_functions + r2_strings
  3) ghidra_functions
  4) ghidra_decompile(main) — 伪 C
  5) r2_disasm_function(main) — 反汇编
"""

import sys
from pathlib import Path

PROJ_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJ_ROOT))

from tools.r2_tools import r2_info, r2_functions, r2_strings, r2_disasm_function
from tools.ghidra_tools import ghidra_functions, ghidra_decompile

BINARY = str(PROJ_ROOT / "target" / "challenge")


def main() -> int:
    print("=" * 70)
    print("1) r2_info")
    print("=" * 70)
    print(r2_info(BINARY)["log_tail"])

    print("\n" + "=" * 70)
    print("2) r2_functions + r2_strings")
    print("=" * 70)
    print(r2_functions(BINARY)["log_tail"])
    print()
    print(r2_strings(BINARY, min_len=4)["log_tail"])

    print("\n" + "=" * 70)
    print("3) ghidra_functions")
    print("=" * 70)
    print(ghidra_functions(BINARY)["log_tail"][:1500])

    print("\n" + "=" * 70)
    print("4) ghidra_decompile(FUN_00401264) — main (stripped)")
    print("=" * 70)
    # Ghidra 把 main 叫 FUN_00401264
    print(ghidra_decompile(BINARY, "FUN_00401264")["log_tail"])

    print("\n" + "=" * 70)
    print("5) r2_disasm_function(main) — main (r2 视角)")
    print("=" * 70)
    print(r2_disasm_function(BINARY, "main")["log_tail"])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
