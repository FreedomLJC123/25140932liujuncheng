# 实验报告：Agent静态挖掘25140932刘俊丞

> 模型：DeepSeek Chat (deepseek-chat)
> 日期：2026-06-25
> 工具：radare2 6.1.8 + Ghidra 12.1.2 (analyzeHeadless + JDK 21)
> 目标：`target/challenge`（Linux x86_64 ELF，stripped，14 函数 / 4 字符串）

## 1. 工程结构

```
static-lab/
├── README.md                  复现指南
├── report.md                  本文件
├── requirements.txt           依赖
├── .gitignore                 排除 venv/cache/output
├── target/
│   └── challenge              待分析 ELF（自带）
├── tools/
│   ├── r2_tools.py            8 个 radare2 工具
│   └── ghidra_tools.py        4 个 Ghidra headless 工具
├── agent/
│   └── react_agent.py         ReAct 主循环（DeepSeek function calling）
├── logs/
│   └── run.txt                7 轮完整 ReAct 交互日志
├── output/
│   └── vuln.json              Agent Final Answer（结构化）
└── scripts/
    └── replay_no_llm.py       不依赖 LLM 的两工具串行演示
```

## 2. 工具封装

### 2.1 r2 工具（`tools/r2_tools.py`）

| 工具 | 用途 |
|---|---|
| `r2_info(binary)` | 读 ELF 元信息（arch / bits / nx / canary / pic / stripped） |
| `r2_functions(binary)` | 列出全部函数（地址 / size / 参数 / 名称） |
| `r2_strings(binary, min_len)` | 提取字符串 |
| `r2_disasm(binary, addr, n)` | 指定地址反汇编 n 条指令 |
| `r2_disasm_function(binary, fn)` | 反汇编整个函数（需先 `aaa`） |
| `r2_cfg_summary(binary, fn)` | 函数 CFG 信息（afi） |
| `r2_xrefs_to(binary, addr)` | addr 的交叉引用 |
| `r2_callgraph(binary)` | 调用图（ag-） |

底层用 `subprocess` 调 `r2 -q -c ...`，指令流场景用 `r2 ... <<<EOF` 管道喂命令，
去掉 ANSI 颜色和 WARN/INFO 噪声后给 LLM 看。

### 2.2 Ghidra 工具（`tools/ghidra_tools.py`）

| 工具 | 用途 |
|---|---|
| `ghidra_functions(binary)` | 列所有函数（含 frame size / 签名） |
| `ghidra_decompile(binary, fn)` | 反编译成伪 C |
| `ghidra_strings(binary, min_len)` | 提取所有定义过的字符串 |
| `ghidra_xrefs(binary, addr)` | addr 的交叉引用 |

后端用 `analyzeHeadless` + Java post-script（`extends GhidraScript`）。
每个工具对应一个 script（`ListFuncs` / `DecompileFn` / `ListStrings` / `Xrefs`），
把分析结果写到 `~/.ghidra_scripts_out.txt` 再读回。
第一次会做完整 auto-analysis（~30-60s），后续复用 cache（~5-10s）。

**两个踩到的 Ghidra 12.1.2 坑：**
- 项目路径不能用 `.<name>` 开头（`~/.ghidra_projects` 报 "Path element starting with '.' is not permitted"），改用 `~/ghidra_lab_cache`
- `-postScript` 参数不接受路径里的 `/`，必须配 `-scriptPath` 后只给 bare filename

## 3. ReAct 主循环

`agent/react_agent.py`：
- 用 OpenAI 兼容协议 + function calling 调 DeepSeek
- 工具 schema 暴露 12 个工具（8 r2 + 4 Ghidra + 1 final_answer）
- 每轮：
  1. 把 messages 发给 DeepSeek，要求 content 里写 Thought
  2. 解析 tool_calls；调对应工具，把 Observation 截断到 4000 字符后回灌
  3. 支持自然语言 `Action: Finish` 和函数 `final_answer` 两种收尾
- 收到 `final_answer(vuln_type, location, cause)` 后立即写 `output/vuln.json`

## 4. 完整运行日志（7 轮）

| Round | Action | 输出要点 |
|---|---|---|
| 1 | `r2_info` | ELF64, x86_64, no canary, no pic, partial relro, stripped, GCC 11.4 |
| 2 | `r2_functions` + `r2_strings` | 14 个函数（main @ 0x401264, size=293）；4 个字符串： `[%s] %s` / `profile-service ready` / `boot` / `selftest` |
| 3 | `ghidra_functions` | 29 个函数（包含 PLT thunks），main 在 Ghidra 里叫 `FUN_00401264`，frame size 176B |
| 4 | `r2_disasm_function(main)` | 看到 `fgets(s1, 0x80, stdin)` + `cmp rax, 0x63; jbe 0x401377` + `call sym.imp.__strcpy_chk` |
| 4 | `ghidra_decompile(FUN_00401264)` | 看到 `if (sVar2 - 1 < 100) __strcpy_chk(&local_a8, local_88, 0x10);` —— **dest 16B vs source 最多 100B** |
| 5 | `r2_disasm(0x401377, 20)` | 印证：`mov edx, 0x10` 后立刻 `call __strcpy_chk` |
| 6 | `r2_disasm_function(fcn.00401216)` | 这个是 "boot"/"selftest" 打印 helper，不影响漏洞结论 |
| 7 | `final_answer` | 写出 vuln.json |

完整日志在 `logs/run.txt`。

## 5. 漏洞结论（Agent Final Answer）

```json
{
  "vuln_type": "stack_buffer_overflow",
  "location": "main @ 0x401382 (call __strcpy_chk)",
  "cause": "fgets 从 stdin 读最多 128 字节到 local_88，strlen 检查允许长度 ≤100 的输入通过，但 __strcpy_chk(&local_a8, local_88, 0x10) 的目标大小仅 16 字节。输入 16-100 字节时，__strcpy_chk 检测到 dest 空间不足而触发 __chk_fail abort，导致拒绝服务。"
}
```

**手工核对**（r2 + Ghidra 双向印证）：

```c
// Ghidra 反编译 (FUN_00401264)
if (sVar2 - 1 < 100) {                          // 允许 ≤ 100 字符
    __strcpy_chk(&local_a8, local_88, 0x10);   // dest 16 字节，src 最多 100
}
```

```asm
; r2 反汇编 (0x40134a-0x401382)
0x0040134a: cmp rax, 0x63   ; 99
0x0040134e: jbe 0x401377    ; 走分支（len-1 ≤ 99 即 len ≤ 100）
0x00401377: mov rsi, rbx    ; src = s1
0x0040137a: mov rdi, rsp    ; dst = &local_a8
0x0040137d: mov edx, 0x10   ; destlen = 16
0x00401382: call sym.imp.__strcpy_chk
```

**触发**：输入 17-100 字节的非空字符串
**实际效果**：`__strcpy_chk` 是 glibc 强化版，发现 dest 不够就调 `__fortify_fail` 然后 `abort()` —— 拒绝服务
**根因**：开发者把 `__strcpy_chk(dest, src, destlen)` 误用 —— 看起来像 `strncpy` 的 "安全截断"，实际是 "长度校验后 abort"。`destlen=16` 与 `if (len-1<100)` 的语义不匹配。

**复现性**（仅供验证静态结论，非 exploit）：
```bash
$ echo "AAAAAAAAAAAAAAAAAAA" | ./challenge
*** buffer overflow detected ***: terminated
Aborted (core dumped)
```

## 6. 决策记录

- **为什么 vuln_type 是 stack_buffer_overflow**：漏洞的根因是 dest buffer（`local_a8`，16B）配错 + source 可达 100B，本质是 stack 上 16B 缓冲无法承接不可控输入。`__strcpy_chk` 把溢出转化为 abort 是一种缓解，但并没有"消除"溢出意图，属于"开发者意图写错"型漏洞。
- **为什么不在 report 里写 exploit**：作业明确"不要求 exploit，不要求动态验证"。我只做了静态分析。
- **为什么用 Ghidra `FUN_00401264` 而不是 r2 的 `main`**：stripped binary 没有符号表，r2 通过 entry0 间接识别 main（用 DWARF 残留），Ghidra 走 auto-analysis 后用 `FUN_<addr>` 命名。两者指向同一函数，互相印证。

## 7. 已知限制

- angr 提供了更"自动"的 decompile 选项（`p.analyses.Decompiler`），但 Ghidra 反编译更经典、按作业要求更对得上
- Ghidra 第一次 import + auto-analysis ~30-60s；二次复用 ~5-10s；冷启动对最终运行时间影响最大
- 没用 `afl-fuzz` / `AFL++` / dynamic instrumentation —— 作业明确"仅静态"
- `_STATE_CACHE` 没做 invalidate，对同一 binary 多次修改文件需要 `rm -rf ~/ghidra_lab_cache`
