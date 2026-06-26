from __future__ import annotations
import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

# --- 让脚本能 import tools/angr_tools.py ---
PROJ_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJ_ROOT))

from openai import OpenAI  # noqa: E402

from tools.angr_tools import (  # noqa: E402
    controlled_explore,
    solve_input,
    verify_input,
    ADDR_GADGET_TRAP,
    ADDR_CHECK_PASSWORD,
    ADDR_WRONG_LEN4,
    ADDR_SUCCESS_BB,
    ADDR_WRONG_TAIL,
    ADDR_WRONG_TAIL_BB1,
    ADDR_WRONG_TAIL_BB2,
    ADDR_WRONG_TAIL_BB3,
    ADDR_MAIN,
    DEFAULT_AVOID,
)


# ---------------------------------------------------------------------------
# LLM 客户端
# ---------------------------------------------------------------------------
def load_api_key() -> tuple[str, str]:
    """
    优先 ~/.deepseek.env，其次系统环境变量。
    返回 (api_key, base_url)。
    """
    env_path = Path.home() / ".deepseek.env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    base_url = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    if not api_key:
        raise SystemExit(
            "ERROR: DEEPSEEK_API_KEY not found. Put it in ~/.deepseek.env (chmod 600) "
            "or export it in the shell."
        )
    return api_key, base_url


# ---------------------------------------------------------------------------
# 工具 schema — 喂给 OpenAI 兼容 function calling
# ---------------------------------------------------------------------------
TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "controlled_explore",
            "description": (
                "在 angr 中跑一次有界符号执行。"
                "返回 found / deadended / active 状态计数、命中地址、命中的 simstate 引用 (state_ref_id)。"
                "可以指定 find（希望到达的地址）和 avoid（要绕开的地址）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "binary_path": {
                        "type": "string",
                        "description": "目标二进制绝对路径。",
                    },
                    "find": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "希望到达的地址列表（int）。例如想看 puts('Success!') 就传 [12582956] (0x10000052c)。",
                    },
                    "avoid": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "要绕开的地址列表。强烈建议把 gadget_trap (0x100000460) 和 'Wrong password!' BB 传进来。",
                    },
                    "max_steps": {
                        "type": "integer",
                        "description": "探索步数上限。",
                        "default": 256,
                    },
                },
                "required": ["binary_path", "find"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "solve_input",
            "description": (
                "从上一步 controlled_explore 命中状态 (state_ref_id) 求解出具体输入字符串。"
                "返回 input_str / input_hex / length。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "state_ref_id": {
                        "type": "string",
                        "description": "controlled_explore 返回的 state_ref_id。",
                    },
                    "password_max_len": {
                        "type": "integer",
                        "default": 10,
                    },
                },
                "required": ["state_ref_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_input",
            "description": (
                "把解出的输入真的喂给二进制跑一次，看 stdout 是否含 'Success'。"
                "用于 LLM 自我校验求解结果。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string"},
                    "input_str":   {"type": "string"},
                },
                "required": ["binary_path", "input_str"],
            },
        },
    },
]

TOOL_DISPATCH = {
    "controlled_explore": controlled_explore,
    "solve_input":        solve_input,
    "verify_input":       verify_input,
}


def _tool_final_answer(answer: str) -> dict:
    """final_answer 是 no-op；agent 框架识别到这次调用就 break。"""
    return {
        "answer":  answer,
        "ok":      True,
        "log_tail": f"[final_answer] 任务结束。最终答案 = {answer!r}",
    }


# 把 final_answer 注入 dispatch
TOOL_DISPATCH["final_answer"] = _tool_final_answer


# ---------------------------------------------------------------------------
# 系统提示
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = f"""\
你是一个 ReAct (Reasoning + Acting) 智能体，专门做**自动化逆向分析**。

## 目标
对 `target/crackme` 这个 crackme 程序，找到能让它输出 `Success! Flag is found.` 的 4 字节密码输入。

## 已知信息
- 程序从 stdin 读 4 字节密码（实际是 4 个字符 + \\0 终止）
- 密码判定逻辑里有 `gadget_trap()` 死循环陷阱，路径 `ABxx` 会进死循环 → angr 会卡死，**必须 avoid**
- 关键地址：
    - `0x100000460`  gadget_trap 入口（**必 avoid**）
    - `0x10000052c`  puts("Success! Flag is found.") 前的 BB（**find**）
    - `0x1000004a0`  puts("Wrong password!") (strlen<4) — avoid
    - `0x100000550`  puts("Wrong password!") (函数尾) — avoid
- 二进制路径：传入 `binary_path` 参数

## 你的工作方式（ReAct 循环）
每轮必须按照下面顺序输出（写到 content 字段）：

    Thought:  <你这一轮打算做什么、为什么>
    Action:   <你要调的工具名，名字必须完全匹配>
    Action Input: <JSON 对象，参数>
                （如果是结束而不是调工具，Action 写成 "Finish"，Action Input 是你的最终答案）

收到工具结果后，你会拿到一个结构化 Observation。在 Observation 之后，**继续 Thought**，再决定下一步。

## 工具列表
- `controlled_explore(binary_path, find, avoid, max_steps)`：跑一次 angr 符号执行
- `solve_input(state_ref_id)`：从上一步命中的状态求具体输入
- `verify_input(binary_path, input_str)`：真跑一次二进制确认

## 建议策略
1. 第一轮：调 controlled_explore，find=[{ADDR_SUCCESS_BB}]，avoid=DEFAULT_AVOID（已包含 gadget_trap 和所有 "Wrong password!" BB），max_steps=512
2. 如果找到 (found_count>0)，调 solve_input 求出密码
3. 调 verify_input 真跑一次确认
4. 失败就把 observation 看完，调整参数再 explore

## 输出格式严格要求
**每一轮你都必须在 content 字段先写一行 Thought**（你的推理 / 计划），
然后用 function calling 调对应工具，或者用自然语言 `Action: Finish` 收尾。

正确格式示例（注意 Thought 一定在 content 里）：

  Thought: 第一步先用 controlled_explore 找 success 路径，避免 gadget_trap。
  [然后调函数 controlled_explore(find=..., avoid=..., max_steps=512)]

如果你认为已经完成任务：
  Thought: 任务完成，密码已求出并验证。
  Action: Finish
  Action Input: {{"answer": "AZcE"}}

或者调工具 `final_answer(answer="AZcE")` 收尾（推荐）。
"""


# ---------------------------------------------------------------------------
# 工具 schema — 喂给 OpenAI 兼容 function calling
# ---------------------------------------------------------------------------
TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "controlled_explore",
            "description": (
                "在 angr 中跑一次有界符号执行。"
                "返回 found / deadended / active 状态计数、命中地址、命中的 simstate 引用 (state_ref_id)。"
                "可以指定 find（希望到达的地址）和 avoid（要绕开的地址）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "binary_path": {
                        "type": "string",
                        "description": "目标二进制绝对路径。",
                    },
                    "find": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "希望到达的地址列表（int）。例如想看 puts('Success!') 就传 [12582956] (0x10000052c)。",
                    },
                    "avoid": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "要绕开的地址列表。强烈建议把 gadget_trap (0x100000460) 和 'Wrong password!' BB 传进来。",
                    },
                    "max_steps": {
                        "type": "integer",
                        "description": "探索步数上限。",
                        "default": 256,
                    },
                },
                "required": ["binary_path", "find"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "solve_input",
            "description": (
                "从上一步 controlled_explore 命中状态 (state_ref_id) 求解出具体输入字符串。"
                "返回 input_str / input_hex / length。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "state_ref_id": {
                        "type": "string",
                        "description": "controlled_explore 返回的 state_ref_id。",
                    },
                    "password_max_len": {
                        "type": "integer",
                        "default": 10,
                    },
                },
                "required": ["state_ref_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_input",
            "description": (
                "把解出的输入真的喂给二进制跑一次，看 stdout 是否含 'Success'。"
                "用于 LLM 自我校验求解结果。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string"},
                    "input_str":   {"type": "string"},
                },
                "required": ["binary_path", "input_str"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "final_answer",
            "description": (
                "当你已经完成求解并验证后，调用本工具给出最终答案。"
                "调用后整个 ReAct 循环就会结束。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "answer": {
                        "type": "string",
                        "description": "求出的密码输入。",
                    },
                },
                "required": ["answer"],
            },
        },
    },
]
# 解析 LLM 自然语言输出 (Thought / Action / Action Input)
# ---------------------------------------------------------------------------
RE_THOUGHT  = re.compile(r"Thought\s*:\s*(.+?)(?=\n\s*Action\s*:|$)", re.DOTALL | re.IGNORECASE)
RE_ACTION   = re.compile(r"Action\s*:\s*([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
RE_AINPUT   = re.compile(r"Action\s*Input\s*:\s*(\{.*?\})", re.DOTALL | re.IGNORECASE)


def parse_react_text(content: str) -> dict:
    """从 LLM content 里抠出 Thought / Action / Action Input。"""
    thought = (RE_THOUGHT.search(content).group(1).strip()
               if RE_THOUGHT.search(content) else "")
    action  = (RE_ACTION.search(content).group(1).strip()
               if RE_ACTION.search(content) else "")
    ainput_raw = (RE_AINPUT.search(content).group(1).strip()
                  if RE_AINPUT.search(content) else "")
    parsed: dict = {}
    if ainput_raw:
        try:
            parsed = json.loads(ainput_raw)
        except json.JSONDecodeError:
            # 容错：把单引号换成双引号再试
            try:
                parsed = json.loads(ainput_raw.replace("'", '"'))
            except Exception:
                parsed = {}
    return {"thought": thought, "action": action, "action_input": parsed}


# ---------------------------------------------------------------------------
# 主循环
# ---------------------------------------------------------------------------
def run_agent(
    binary_path: str,
    model: str = "deepseek-chat",
    max_steps: int = 8,
    temperature: float = 0.2,
    log_path: str | None = None,
) -> dict:
    api_key, base_url = load_api_key()
    client = OpenAI(api_key=api_key, base_url=base_url)

    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": f"开始任务。binary_path={binary_path}"},
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

    log(f"=== ReAct agent start === binary={binary_path} model={model} max_steps={max_steps}")

    final_answer: str | None = None
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
                max_tokens=2000,
            )
        except Exception as e:
            log(f"LLM call FAILED: {type(e).__name__}: {e}")
            break

        msg = resp.choices[0].message
        content = msg.content or ""
        tool_calls = msg.tool_calls or []

        # 记录本轮 Thought
        parsed = parse_react_text(content)
        if parsed["thought"]:
            log(f"Thought: {parsed['thought']}")

        # --- 分支 1: LLM 直接调了工具 (function calling) ---
        if tool_calls:
            tc = tool_calls[0]
            fn_name = tc.function.name
            try:
                fn_args = json.loads(tc.function.arguments or "{}")
            except Exception:
                fn_args = {}

            log(f"Action (function-call): {fn_name}({json.dumps(fn_args, ensure_ascii=False)})")

            # 强制给 binary_path 填上
            if fn_name in ("controlled_explore", "verify_input") and "binary_path" not in fn_args:
                fn_args["binary_path"] = binary_path
            # 给 find/avoid 填默认
            if fn_name == "controlled_explore":
                fn_args.setdefault("find", [ADDR_SUCCESS_BB])
                fn_args.setdefault("avoid", list(DEFAULT_AVOID))
                fn_args.setdefault("max_steps", 512)

            tool = TOOL_DISPATCH.get(fn_name)
            if tool is None:
                observation = f"ERROR: unknown tool '{fn_name}'"
            else:
                try:
                    result = tool(**fn_args)
                except Exception as e:
                    result = {"error": f"{type(e).__name__}: {e}",
                              "log_tail": f"[{fn_name}] raised {type(e).__name__}"}
                observation = result.get("log_tail") or json.dumps(result, ensure_ascii=False, indent=2)

            log(f"Observation:\n{observation}")

            # 把 assistant 的 tool_call + 我们的 tool result 都回灌
            messages.append({
                "role": "assistant",
                "content": content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": fn_name, "arguments": tc.function.arguments or "{}"},
                    }
                ],
            })
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": observation,
            })

            # 如果是 final_answer tool 或 Action: Finish，break
            if fn_name == "final_answer":
                final_answer = (fn_args or {}).get("answer")
                log(f"Agent finished via final_answer tool. Final answer = {final_answer!r}")
                break
            if parsed["action"].lower() == "finish":
                final_answer = (parsed["action_input"] or {}).get("answer")
                log(f"Agent finished (natural-language Finish). Final answer = {final_answer!r}")
                break
            continue

        # --- 分支 2: LLM 没调工具，依赖自然语言 Action ---
        if parsed["action"].lower() == "finish":
            final_answer = (parsed["action_input"] or {}).get("answer") or content
            log(f"Agent finished (no tool call). Final answer = {final_answer!r}")
            break

        # --- 分支 3: LLM 写了 Action 名字但没调 tool calling (回退路径) ---
        if parsed["action"] and parsed["action"].lower() != "finish":
            log(f"(fallback) ReAct-parsed Action: {parsed['action']}({parsed['action_input']})")
            tool = TOOL_DISPATCH.get(parsed["action"])
            if tool:
                try:
                    fn_args = dict(parsed["action_input"])
                    if parsed["action"] in ("controlled_explore", "verify_input") and "binary_path" not in fn_args:
                        fn_args["binary_path"] = binary_path
                    if parsed["action"] == "controlled_explore":
                        fn_args.setdefault("find", [ADDR_SUCCESS_BB])
                        fn_args.setdefault("avoid", list(DEFAULT_AVOID))
                        fn_args.setdefault("max_steps", 512)
                    result = tool(**fn_args)
                    observation = result.get("log_tail") or json.dumps(result, ensure_ascii=False, indent=2)
                except Exception as e:
                    observation = f"ERROR executing {parsed['action']}: {type(e).__name__}: {e}"
            else:
                observation = f"ERROR: unknown action '{parsed['action']}'"
            log(f"Observation:\n{observation}")
            messages.append({"role": "user", "content": f"Observation:\n{observation}"})
            continue

        # --- 分支 4: LLM 啥都没写（少见） ---
        log("(no action / no tool call, prompting again)")
        messages.append({"role": "user", "content": "请按 Thought → Action → Action Input 格式继续；如果你已经完成，用 Action: Finish + 答案。"})
        continue

    log(f"=== ReAct agent end. rounds={rounds} final_answer={final_answer!r} ===")
    return {
        "rounds": rounds,
        "final_answer": final_answer,
        "log_lines": log_lines,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--model", default="deepseek-chat")
    parser.add_argument("--max-steps", type=int, default=8)
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--log", default=None)
    args = parser.parse_args()

    binary = str(Path(args.binary).resolve())
    log_path = args.log or f"logs/run_{int(time.time())}.log"
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    if Path(log_path).exists():
        Path(log_path).unlink()  # 覆盖

    result = run_agent(
        binary_path=binary,
        model=args.model,
        max_steps=args.max_steps,
        temperature=args.temperature,
        log_path=log_path,
    )

    print(f"\n>>> rounds={result['rounds']} final_answer={result['final_answer']!r}")
    print(f">>> log written to: {log_path}")
    return 0 if result["final_answer"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
