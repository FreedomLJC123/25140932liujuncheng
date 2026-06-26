# sipapp-lab · ReAct 静态 + angr 动态分析 (PJSIP 2012)

> 二进制：`/Users/ahs/.../xwechat_files/.../temp/drag/sipapp`
> ARM 32-bit Linux, Marvell GCC 4.6.3, uClibc, PJSIP 2012 软电话

## 状态

- ✅ **Pass 1 静态分析**：r2 + Ghidra 找到 PJSIP URI 解析栈溢出 → `output/vuln.json`
- ⚠️ **Pass 2 angr 动态分析**：框架搭好，但 2.2MB PJSIP 二进制对 angr 太慢（>90s timeout）
  - 小函数 (76B) 0.14s 出结果，框架可用
  - 大函数（>200B + 多级调用）超时

## 一键复现

```bash
cd sipapp-lab

# 装 angr（系统 Python 3.11+）
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt

# 配 key（不会进 git）
echo "DEEPSEEK_API_KEY=sk-xxx" > ~/.deepseek.env
chmod 600 ~/.deepseek.env

# 装系统工具
brew install radare2
brew install openjdk@21
# Ghidra 12.1.2 解压到 /tmp/ghidra_dl/ghidra_12.1.2_PUBLIC

# 跑静态分析 agent
./.venv/bin/python -m agent.react_agent \
    --binary target/sipapp \
    --max-steps 6 \
    --log logs/run.txt \
    --vuln-out output/vuln.json
```

## 工具栈（13 个工具）

### r2 (8) — 来自 static-lab
- `r2_info` / `r2_functions` / `r2_strings` / `r2_disasm` / `r2_disasm_function` / `r2_cfg_summary` / `r2_xrefs_to` / `r2_callgraph`

### Ghidra (4) — 来自 static-lab
- `ghidra_functions` / `ghidra_decompile` / `ghidra_strings` / `ghidra_xrefs`

### angr (3) — agent-lab 复用 + pjsip 简化版
- `angr_controlled_explore` / `angr_solve_input` / `angr_verify_input` (from agent-lab, 对小目标有用)
- `angr.reachability_test` / `angr.explore_to` (pjsip 简化版, 适合小函数)

## 漏洞（vuln.json）

| 字段 | 值 |
|---|---|
| `vuln_type` | **stack_buffer_overflow** |
| `location` | **int_parse_uri_or_name_addr @ 0x0041038** (called from `parse_hdr_fromto` @ 0x42470) |
| `cause` | PJSIP 2012 URI 解析，依赖 pj_scan_get_char 的 token 长度，无显式 length check。From/To 头从 `recv` 流入。匹配 CVE-2014-8363 / CVE-2016-10378 模式。 |

调用链：
```
recv (网络 SIP 消息)
  → pjsip_tsx_recv_msg
  → init_parser @ 0x3e238 (4148B, 主解析器)
  → parse_hdr_from / parse_hdr_to
  → parse_hdr_fromto @ 0x42470 (280B)
  → int_parse_uri_or_name_addr @ 0x41038 (1216B) ← SINK
```

## 文件清单

```
sipapp-lab/
├── README.md
├── report.md
├── requirements.txt
├── .gitignore
├── target/sipapp                   2.2MB ARM 32-bit PJSIP
├── tools/
│   ├── r2_tools.py
│   ├── ghidra_tools.py
│   ├── angr_tools.py               from agent-lab
│   └── angr_tools_pjsip.py         simplified for sipapp
├── agent/
│   └── react_agent.py              PJSIP-context patched
├── logs/run.txt                    10 轮 static ReAct 日志
├── output/vuln.json                Agent Final Answer
└── scripts/
    └── angr_smoke.py
```

## 已知限制 / 后续工作

- **angr 对 2.2MB 真实二进制不实用**——状态空间爆炸。要做真 fuzz：
  - libFuzzer + Ghidra 的 `fuzz.py` 模板
  - AFL++ with `qemu_mode` for ARM32
  - Boofuzz（针对 SIP 协议的 dumb fuzzer）
- **vuln.json 是基于 PJSIP 2012 已知 CVE 模式**，不是完全自主逆向发现
- **没做 exploit**（按要求"不要求 exploit"，但要 exploit 需要上述 fuzz 工具）
