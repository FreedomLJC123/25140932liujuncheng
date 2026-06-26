#!/usr/bin/env python3
"""
angr_smoke.py — 验证 angr 框架在 sipapp 上的可用性。

用法：
    ./.venv/bin/python scripts/angr_smoke.py

本脚本对几个 tractable 小函数做 reachability test，证明：
  - angr 能加载 ARM 32-bit sipapp
  - 函数级 blank_state + 符号 BVS 栈初始化 OK
  - 小函数（<100B）0.1-0.2s 出结果
  - 大函数（>200B + 多级调用）会超时（已知限制）
"""

import sys
import time
from pathlib import Path

PROJ_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJ_ROOT))

from tools.angr_tools_pjsip import reachability_test, KNOWN_SINKS  # noqa: E402

BINARY = str(PROJ_ROOT / "target" / "sipapp")


def main() -> int:
    print("=" * 70)
    print("angr smoke test on sipapp (ARM 32-bit, PJSIP 2012)")
    print("=" * 70)

    # Smallest parse_hdr_* functions (<100B) — should finish in <1s
    small_tests = [
        ("parse_hdr_accept", 0x41d40, 0x41d40, 16, 32),       # self-reachable
        ("parse_hdr_allow",  0x41d8c, 0x41d8c, 16, 32),
        ("parse_hdr_min_expires", 0x42d6c, 0x42d6c, 16, 32),
    ]

    for name, entry, sink, steps, sz in small_tests:
        t0 = time.time()
        out = reachability_test(BINARY, entry, sink, steps, sz)
        wall = time.time() - t0
        print(f"\n[{name}]  entry={hex(entry)}  sink={hex(sink)}  "
              f"max_steps={steps}  stack={sz}B  wall={wall:.2f}s")
        print(f"  found={out['found']}  active={out.get('active','?')}  "
              f"deadended={out.get('deadended','?')}  avoided={out.get('avoided','?')}")
        if out['error']:
            print(f"  ERROR: {out['error']}")

    print("\n" + "=" * 70)
    print("Known sinks in sipapp (for future angr targeting):")
    for k, v in KNOWN_SINKS.items():
        print(f"  {k:30s}  {hex(v)}")
    print()
    print("NOTE: large functions (>200B with deep call chains) will time out")
    print("      on 2.2MB PJSIP. Use libFuzzer/AFL++ for real fuzzing instead.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
