"""
react_agent.py — ReAct 静态分析 agent (r2 + Ghidra)

工作流（每轮）：
   1. 把当前 messages 发给 DeepSeek (OpenAI 兼容 + function calling)
   2. 解析响应：
      - 有 tool_calls：执行对应工具，把结果作为 Observation 回灌
      - 没 tool_calls 且 finish_reason=stop：把 content 当 final answer
   3. 写日志 (Thought/Action/Observation)
   4. 达到 max_steps 或 agent 调用 final_answer → 退出
"""

from __future__ import annotations
import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

PROJ_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJ_ROOT))

from openai import OpenAI  # noqa: E402

from tools.r2_tools import R2_TOOL_DISPATCH  # noqa: E402
from tools.ghidra_tools import GHIDRA_TOOL_DISPATCH  # noqa: E402


def load_api_key() -> tuple[str, str]:
    env_path = Path.home() / ".deepseek.env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())
    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    base_url = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    if not api_key:
        raise SystemExit(
            "ERROR: DEEPSEEK_API_KEY not found in ~/.deepseek.env or env vars."
        )
    return api_key, base_url


# ---------------------------------------------------------------------------
# 工具 schema
# ---------------------------------------------------------------------------
TOOL_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "r2_info",
            "description": "读目标二进制的元信息（arch / bits / 安全特性 / 编译选项）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary": {"type": "string", "description": "二进制绝对路径。"},
                },
                "required": ["binary"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "r2_strings",
            "description": "提取所有 ≥ min_len 长度的字符串（地址 + 长度 + 内容）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary":   {"type": "string"},
                    "min_len":  {"type": "integer", "default": 4},
                },
                "required": ["binary"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "r2_functions",
            "description": "列出所有函数（地址 / size / 参数数 / 名称）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary": {"type": "string"},
                },
                "required": ["binary"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "r2_disasm",
            "description": "在指定地址反汇编 n 条指令（n 缺省 30）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary": {"type": "string"},
                    "addr":   {"type": "string", "description": "十六进制地址（带或不带 0x 都可）"},
                    "n":      {"type": "integer", "default": 30},
                },
                "required": ["binary", "addr"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "r2_disasm_function",
            "description": "反汇编整个函数（按函数名或地址）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary":   {"type": "string"},
                    "function": {"type": "string"},
                },
                "required": ["binary", "function"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "r2_xrefs_to",
            "description": "查 addr 的所有交叉引用（哪些地方引用了这个地址）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary": {"type": "string"},
                    "addr":   {"type": "string"},
                },
                "required": ["binary", "addr"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ghidra_functions",
            "description": "用 Ghidra headless 列所有函数（含 frame size / 调用约定 / 签名）。",
            "parameters": {
                "type": "object",
                "properties": {"binary": {"type": "string"}},
                "required": ["binary"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ghidra_decompile",
            "description": "用 Ghidra decompiler 把指定函数反编译成伪 C 代码。",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary":   {"type": "string"},
                    "function": {"type": "string", "description": "函数名（如 main、entry.init0）或地址（0x401264）"},
                },
                "required": ["binary", "function"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ghidra_strings",
            "description": "用 Ghidra headless 列所有字符串（从 .rodata / DefinedData 提取）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary":  {"type": "string"},
                    "min_len": {"type": "integer", "default": 4},
                },
                "required": ["binary"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ghidra_xrefs",
            "description": "用 Ghidra headless 查指定地址的所有交叉引用。",
            "parameters": {
                "type": "object",
                "properties": {
                    "binary": {"type": "string"},
                    "addr":   {"type": "string"},
                },
                "required": ["binary", "addr"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "final_answer",
            "description": "当你已经判定漏洞后调用。参数 vuln_type / location / cause 必须是结构化结果。",
            "parameters": {
                "type": "object",
                "properties": {
                    "vuln_type": {"type": "string", "description": "漏洞类型，如 stack_buffer_overflow / format_string / use_after_free 等。"},
                    "location":  {"type": "string", "description": "Sink 所在函数或地址（必须与 log 里的工具返回一致）。"},
                    "cause":     {"type": "string", "description": "一句话：不可信输入如何到达危险操作。"},
                },
                "required": ["vuln_type", "location", "cause"],
            },
        },
    },
]

TOOL_DISPATCH: dict[str, Any] = {**R2_TOOL_DISPATCH, **GHIDRA_TOOL_DISPATCH}


def _tool_final_answer(vuln_type: str, location: str, cause: str) -> dict:
    return {
        "vuln_type": vuln_type,
        "location":  location,
        "cause":     cause,
        "ok":        True,
        "log_tail":  f"[final_answer] vuln_type={vuln_type!r} location={location!r} cause={cause!r}",
    }


TOOL_DISPATCH["final_answer"] = _tool_final_answer


# ---------------------------------------------------------------------------
# 系统提示
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """\
你是一个 **ReAct 静态分析智能体**。任务：对一个 Linux x86_64 ELF 黑盒二进制做纯静态分析，
判断它是否存在漏洞，并给出 **vuln_type / location / cause** 三段式结论。

## 工具（只读静态）
- **r2 (radare2)**：`r2_info` / `r2_strings` / `r2_functions` / `r2_disasm` / `r2_disasm_function` / `r2_xrefs_to`
- **Ghidra (headless)**：`ghidra_functions` / `ghidra_decompile` / `ghidra_strings` / `ghidra_xrefs`

调用建议：
- 开头先用 `r2_info` 摸底（arch / 安全特性 / nx / pic / canary）
- 然后 `r2_functions` + `ghidra_functions` 找入口点和可疑函数（main / 处理用户输入的）
- 对可疑函数用 `r2_disasm_function` + `ghidra_decompile` 双向印证（r2 给你指令流，Ghidra 给你伪 C 高级逻辑）
- 对可疑 sink（如 `__strcpy_chk` / `__snprintf_chk` / `printf` / `fgets` / `read`）用 `r2_xrefs_to` / `ghidra_xrefs` 找调用上下文

## 漏洞判定要点
- 看 **不可信输入**（stdin / argv / 网络 / 文件读）流向哪里
- 看 **buffer 长度**和 copy 函数（strcpy / strncpy / sprintf / memcpy / fgets）的 `size` 参数是否匹配
- 关注 **fortified 函数的误用**（如 `__strcpy_chk(dest, src, 16)` 但 `src` 实际可达 100 字节）
- 不要分析 main 以外用不到的 dead code（如 `fcn.00401170` / `entry.fini0` / `entry.init0`）



## 目标上下文（这是 PJSIP 嵌入式软电话）
- 平台：ARM 32-bit Linux, Marvell GCC 4.6.3 (2012 时代), uClibc, 多线程
- 包含 PJSIP 库 (~2MB，符号未 strip) + 自定义 sipapp 业务代码
- 关键候选漏洞函数（已知 CVE 模式）：
  - `dbg.init_parser` (0x3e238, 4148B) — PJSIP 主入口
  - `parse_hdr_*` 系列 (parse_hdr_contact/from/via/...) — 头解析（历史 CVE 集中地）
  - `int_parse_sip_url` (0x41038, 1216B) — SIP URL 解析（CVE-2014-8363 等）
  - `dbg.sipapp_read_commandline` (0x12538) — 命令行解析（format string 风险）
  - `dbg.sipapp_config_parse` (0x15dac, 1600B) — 配置文件解析
- 关注栈/堆溢出、off-by-one、format string、整数符号/截断

## 输出格式
**每一轮都先在 content 字段写一行 Thought** 简述你的判断 / 下一步计划，
然后调对应工具。

收尾：调 `final_answer(vuln_type, location, cause)`，三个字段都要和工具返回对得上，
**不能凭空写**。例如：
```
Thought: 工具返回 main 0x401377 有 `__strcpy_chk(rsp, user_input, 16)`，
         但前面检查只允许 strlen <= 100，17-100 字符输入会触发 __chk_fail abort。
         这是开发者把 __strcpy_chk 当 strncpy 用的 bug。漏洞类型 stack_buffer_overflow。
Action (function-call): final_answer({
  "vuln_type": "stack_buffer_overflow",
  "location": "main @ 0x401382 (call __strcpy_chk)",
  "cause": "用户 stdin 最多 100 字节，__strcpy_chk 目标 16 字节，17-100 字符输入会触发 __chk_fail abort"
})
```
"""


# ---------------------------------------------------------------------------
# ReAct 文本格式回退解析
# ---------------------------------------------------------------------------
RE_THOUGHT = re.compile(r"Thought\s*:\s*(.+?)(?=\n\s*Action\s*:|$)", re.DOTALL | re.IGNORECASE)
RE_ACTION  = re.compile(r"Action\s*:\s*([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
RE_AINPUT  = re.compile(r"Action\s*Input\s*:\s*(\{.*?\})", re.DOTALL | re.IGNORECASE)


def parse_react_text(content: str) -> dict:
    thought = RE_THOUGHT.search(content).group(1).strip() if RE_THOUGHT.search(content) else ""
    action  = RE_ACTION.search(content).group(1).strip() if RE_ACTION.search(content) else ""
    ainput  = RE_AINPUT.search(content).group(1).strip() if RE_AINPUT.search(content) else ""
    parsed: dict = {}
    if ainput:
        try:
            parsed = json.loads(ainput)
        except Exception:
            try:
                parsed = json.loads(ainput.replace("'", '"'))
            except Exception:
                parsed = {}
    return {"thought": thought, "action": action, "action_input": parsed}


# ---------------------------------------------------------------------------
# 主循环
# ---------------------------------------------------------------------------
def run_agent(
    binary_path: str,
    model: str = "deepseek-chat",
    max_steps: int = 10,
    temperature: float = 0.2,
    log_path: str | None = None,
    vuln_json_path: str = "output/vuln.json",
) -> dict:
    api_key, base_url = load_api_key()
    client = OpenAI(api_key=api_key, base_url=base_url)

    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": f"开始分析。binary={binary_path}"},
    ]

    log_lines: list[str] = []
    def log(s: str) -> None:
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] {s}"
        print(line, flush=True)
        log_lines.append(line)
        if log_path:
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    log(f"=== ReAct static-analysis agent start === binary={binary_path} model={model} max_steps={max_steps}")
    final_answer: dict | None = None
    rounds = 0
    for step in range(1, max_steps + 1):
        rounds = step
        log(f"\n--- Round {step} ---")
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                tools=TOOL_SCHEMAS,
                tool_choice="auto",
                temperature=temperature,
                max_tokens=2500,
            )
        except Exception as e:
            log(f"LLM call FAILED: {type(e).__name__}: {e}")
            break

        msg = resp.choices[0].message
        content = msg.content or ""
        tool_calls = msg.tool_calls or []

        parsed = parse_react_text(content)
        if parsed["thought"]:
            log(f"Thought: {parsed['thought']}")

        if tool_calls:
            for tc in tool_calls:
                fn_name = tc.function.name
                try:
                    fn_args = json.loads(tc.function.arguments or "{}")
                except Exception:
                    fn_args = {}

                log(f"Action (function-call): {fn_name}({json.dumps(fn_args, ensure_ascii=False)})")

                # 默认 binary 路径
                if fn_name in R2_TOOL_DISPATCH or fn_name in GHIDRA_TOOL_DISPATCH:
                    fn_args.setdefault("binary", binary_path)

                tool = TOOL_DISPATCH.get(fn_name)
                if tool is None:
                    observation = f"ERROR: unknown tool '{fn_name}'"
                else:
                    try:
                        result = tool(**fn_args)
                    except Exception as e:
                        result = {"error": f"{type(e).__name__}: {e}",
                                  "log_tail": f"[{fn_name}] raised {type(e).__name__}: {e}"}
                    observation = result.get("log_tail") or json.dumps(result, ensure_ascii=False, indent=2)

                # 截断过长的 observation（避免撑爆 LLM 上下文）
                if len(observation) > 4000:
                    observation = observation[:4000] + "\n... [truncated]"

                log(f"Observation:\n{observation}")

                messages.append({
                    "role": "assistant",
                    "content": content if tc == tool_calls[0] else "",
                    "tool_calls": [{
                        "id": tc.id, "type": "function",
                        "function": {"name": fn_name, "arguments": tc.function.arguments or "{}"},
                    }],
                })
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": observation,
                })

                if fn_name == "final_answer":
                    final_answer = fn_args
                    log(f"Agent finished. Final answer: {final_answer}")
                    break
                if parsed["action"].lower() == "finish":
                    final_answer = parsed.get("action_input", {})
                    log(f"Agent finished (natural-language Finish). Final answer: {final_answer}")
                    break

            if final_answer is not None:
                break
            continue

        # 自然语言 Finish 路径
        if parsed["action"].lower() == "finish":
            final_answer = parsed.get("action_input", {})
            log(f"Agent finished (no tool call). Final answer: {final_answer}")
            break

        if not parsed["action"]:
            log("(no action / no tool call, prompting again)")
            messages.append({
                "role": "user",
                "content": "请按 Thought → Action → Action Input 格式继续；判定完成请调 final_answer(...,...)。",
            })
            continue

    log(f"=== ReAct end. rounds={rounds} ===")

    # 写 vuln.json
    if final_answer:
        vuln = {
            "vuln_type": final_answer.get("vuln_type", "unknown"),
            "location":  final_answer.get("location", "unknown"),
            "cause":     final_answer.get("cause", "unknown"),
        }
        Path(vuln_json_path).parent.mkdir(parents=True, exist_ok=True)
        Path(vuln_json_path).write_text(json.dumps(vuln, indent=2, ensure_ascii=False), encoding="utf-8")
        log(f"vuln.json written to {vuln_json_path}")
        log(f"vuln.json content: {json.dumps(vuln, ensure_ascii=False)}")
    else:
        log("WARNING: no final_answer received, vuln.json NOT written")

    return {
        "rounds": rounds,
        "final_answer": final_answer,
        "log_lines": log_lines,
        "vuln_json_path": vuln_json_path if final_answer else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--model", default="deepseek-chat")
    parser.add_argument("--max-steps", type=int, default=10)
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--log", default=None)
    parser.add_argument("--vuln-out", default="output/vuln.json")
    args = parser.parse_args()

    binary = str(Path(args.binary).resolve())
    log_path = args.log or f"logs/run.txt"
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    if Path(log_path).exists():
        Path(log_path).unlink()

    result = run_agent(
        binary_path=binary,
        model=args.model,
        max_steps=args.max_steps,
        temperature=args.temperature,
        log_path=log_path,
        vuln_json_path=args.vuln_out,
    )

    print(f"\n>>> rounds={result['rounds']}")
    print(f">>> final_answer: {result['final_answer']}")
    print(f">>> log:          {log_path}")
    print(f">>> vuln.json:    {result['vuln_json_path']}")
    return 0 if result["final_answer"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
