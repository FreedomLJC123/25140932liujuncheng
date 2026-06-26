# 实验报告：基于 ReAct 智能体与 angr 的自动化逆向分析

> 提交人：[姓名]　学号：[学号]　课程：[课程名]
> 提交日期：2026-06-25

---

## 1. 实验目标

把 ReAct（Reasoning + Acting）架构应用到一个简单逆向场景：
以大语言模型（DeepSeek）为「决策与编排层」，以 angr 为可调用的「工具」，
通过「思考—行动—观察」闭环，引导符号执行探索目标路径，求解 crackme 程序的正确输入。

## 2. 求解对象

`target/crackme.c` —— 4 字节密码判定，含 `gadget_trap` 死循环陷阱。

判定逻辑（`check_password`）：
```c
if (input[0] == 'A') {
    if (input[1] == 'B') gadget_trap();   // 死循环分支
    if (input[1] == 'Z') {
        if ((input[2] ^ 0x12) == 'q') {
            if ((input[3] + 3) == 'H') {
                puts("Success! Flag is found."); return 1;
            }
        }
    }
}
```

预期答案（手算）：`A` + `Z` + `c`(0x71^0x12) + `E`(0x48−3) = **`AZcE`**。

## 3. 工程结构

```
agent-lab/
├── README.md                     本文件目录
├── requirements.txt              依赖清单
├── .gitignore                    忽略 .venv / logs / .env
├── target/
│   ├── crackme.c                 目标程序源码
│   └── crackme                   编译产物（gcc -O0 -g）
├── tools/
│   ├── __init__.py
│   └── angr_tools.py             angr 工具封装
│       ├── controlled_explore()  任务一·单步/受控探索
│       ├── solve_input()         任务一·输入求解
│       └── verify_input()        任务一·验证（回灌真跑）
├── agent/
│   ├── __init__.py
│   └── react_agent.py            任务二·ReAct 主循环
│       ├── 工具 schema（OpenAI function calling）
│       ├── 提示词（Thought/Action/Observation 格式）
│       ├── 主循环（带 fallback 自然语言 Action 解析）
│       └── 完整日志记录
├── logs/
│   └── run.log                   4 轮 ReAct 完整日志（≥3 轮要求）
└── scripts/
    └── replay_angr_only.py       不依赖 LLM 的 angr 复现脚本
```

## 4. 关键实现要点

### 4.1 angr 工具封装（任务一）

- **`controlled_explore(binary_path, find, avoid, max_steps)`**
  - 启动 angr entry state，给 stdin 装一个 16 字节符号 BVS
  - 给前 9 字节加 printable-ASCII 约束（避免 `0xdd` 默认填充）
  - 调 `simgr.explore(find, avoid, n=max_steps)` 一次性找/避
  - 把命中的 `simstate` 引用挂到 `_STATE_STORE` 里返回 `state_ref_id`
  - 失败时回传 `deadended` / `active` 数量 + 结构化建议

- **`solve_input(state_ref_id, password_max_len=10)`**
  - 关键技巧：stdin BVS 走过 scanf SimProcedure 后，**真正的密码约束在 buffer 内存上，不在 BVS 上**
  - 从 `solver._solver.constraints` 里 regex 找出 buffer 栈地址（`mem_<hex>_...`）
  - **逐字节** 读 buffer（避免 endness 转换坑），用 `solver.eval()` 求出具体值
  - 截断到第一个 `\x00`，转 ASCII

- **`verify_input(binary_path, input_str)`**
  - `subprocess.run` 真跑二进制，把 stdout 跟 "Success" 匹配
  - 给 LLM 一个「自我校验」回路

### 4.2 ReAct 主循环（任务二）

- **目标与约束的显式描述**：在 `SYSTEM_PROMPT` 里 hardcode
  - find = `0x10000052c`（"Success!" puts 前的 BB）
  - avoid = `{gadget_trap, "Wrong password!" BBs}` 的全集
  - 任务：「找到能让 crackme 输出 Success! 的 4 字节密码」

- **LLM 输出的解析与派发**：
  - 优先用 OpenAI function calling（DeepSeek 兼容）
  - Fallback：content 里匹配 `Action: <name>` / `Action Input: <json>` 文本格式
  - `final_answer` 工具作为"收尾"出口，避免自然语言 Finish 解析歧义

- **Observation 构造**：
  - 每个工具的 `log_tail` 字段是给 LLM 看的人话摘要
  - 包括：find/avoid 地址、found/deadended 计数、命中 state 地址、密码 buffer 读到的字节、verify 实际 stdout

### 4.3 关键地址一览（crackme -O0 -g 编译产物反推）

| 地址 | 含义 |
|---|---|
| `0x100000460` | `gadget_trap` 入口（**必 avoid**） |
| `0x10000047c` | `check_password` 入口 |
| `0x1000004a0` | BB：puts "Wrong password!"（strlen<4 分支）|
| `0x100000544`/`0x48`/`0x4c` | 跳板 `b` 指令（trampoline）|
| `0x100000550` | BB：puts "Wrong password!"（函数尾默认 fail）|
| `0x10000052c` | BB：puts "Success! Flag is found." ← **find** |
| `0x100000574` | `main` 入口 |

## 5. 完整运行日志

参见 [`logs/run.log`](logs/run.log)。下面是 4 轮 Thought → Action → Observation 的摘录（完整版含函数参数、时间戳、工具 Observation 完整文本）：

### Round 1 — 受控探索
```
Thought: 第一步先用 controlled_explore 找 success 路径，
         避免 gadget_trap 和所有 "Wrong password!" 的 BB。
         已知 find 地址是 0x10000052c（Success），
         avoid 地址包括 gadget_trap (0x100000460)、
         strlen<4 的 wrong (0x1000004a0) 和函数尾 wrong (0x100000550)。
Action (function-call): controlled_explore({
  "binary_path": ".../target/crackme",
  "find": [4294968620],
  "avoid": [4294968416, 4294968480, 4294968656],
  "max_steps": 512
})
Observation: [controlled_explore] binary=crackme
  find  targets: ['0x10000052c']
  avoid targets: ['0x100000460', '0x1000004a0', '0x100000550']
  max_steps=512
  found=1  deadended=0  active=1  avoided=5
  -> reached: ['0x10000052c']
  state_ref_id for next call: state_50845
```

### Round 2 — 求解输入
```
Thought: 成功找到了一个到达 Success 地址的状态，state_ref_id 是 state_50845。
         现在调用 solve_input 来求解具体的 4 字节密码输入。
Action (function-call): solve_input({
  "state_ref_id": "state_50845",
  "password_max_len": 10
})
Observation: [solve_input] state at 0x10000052c
  buffer @ 0x7fffffffffeffde, method=memory
  solved password = 'AZcE'  (len=4, hex=415a6345)
  -> expected outcome: Success! Flag is found.
```

### Round 3 — 验证
```
Thought: 解出的密码是 "AZcE"，现在用 verify_input 真跑二进制
         确认输出是否包含 "Success"。
Action (function-call): verify_input({
  "binary_path": ".../target/crackme",
  "input_str": "AZcE"
})
Observation: [verify_input] input='AZcE'
  stdout: 'Enter password: Success! Flag is found.'
  success: True
```

### Round 4 — 收尾
```
Thought: 验证通过，密码 "AZcE" 确实能让程序输出 "Success! Flag is found."。
         任务完成。
Action (function-call): final_answer({ "answer": "AZcE" })
Observation: [final_answer] 任务结束。最终答案 = 'AZcE'
```

> 闭环成立的三个证据：
> 1. `controlled_explore` 返回 `found=1`，state 真的在 `0x10000052c`；
> 2. `solve_input` 从 state 内存 buffer 读到的字节是 `0x41 0x5a 0x63 0x45` = `AZcE`；
> 3. `verify_input` 把 `AZcE` 真喂给 crackme，stdout 出现 `Success! Flag is found.`，与预期完全一致。

## 6. 思考题

### 在本实验中，LLM 主要承担什么角色？它如何借助语义与常识，缓解纯符号执行在搜索空间上的困难？

**LLM 的角色：高层决策与编排者（strategic orchestrator），不是求解器。**

它不做"找到满足约束的具体字节"这种活——那是 angr + Z3 的工作；
它做的是 **"知道下一步该看哪里、该避哪里、用什么工具"** 这种 *高层导航* 的活。

具体在四个层面发挥作用：

**1. 任务语义解析**
纯符号执行看到的是字节级 AST，没有"密码"概念。LLM 拿到任务描述后，
能立刻把"`Success! Flag is found.`"映射到 `puts("Success!")` 的 BB 地址（0x10000052c），
把"`gadget_trap` 死循环"映射到要 avoid 的入口地址（0x100000460）。
这种 **"自然语言意图 → 关键地址集合"** 的转换是人类分析师的强项，
但纯 angr API 完全不做这件事，需要人/脚本提前把地址硬编码进 find/avoid。

**2. 搜索空间剪枝 (pruning)**
纯符号执行遇到 gadget_trap 这种含 `while(1){}` 的死循环，
会沿着入口一直符号步进，**每一步都要进栈展开**，直到 Z3 报不可满足才回溯——
本质上是把"死循环 BB"重复展开无数次，浪费大量时间。
LLM 拿到任务描述的瞬间就识别出"这是陷阱"，直接告诉 angr "avoid 这个入口"，
相当于把"BB 内的循环展开"提前干掉了。

**3. 失败后的策略调整**
当 `controlled_explore` 返回 `found=0, active>0`，LLM 看 Observation 后能诊断：
- "active 还在跑，是不是 max_steps 给小了？" → 调大 max_steps 重跑
- "active=0 但 deadended>0，是不是 find/avoid 选错了？" → 改地址再试
- "solver 不可满足，是不是约束加得太严？" → 去掉 printable 约束
这种 **读 Observation → 反思 → 调参数** 的循环，没有 LLM 就要靠人手反复试。

**4. 多步证据合成**
一次 explore 不一定够：可能需要先找 strlen 检查、确认长度约束可达，
再调整 find 到 puts 之前的 BB。LLM 能把多次 explore 的 Observation 拼起来，
推理出"接下来 solve 哪个 state_ref_id"，并最终用 verify_input 真跑一次自检。

**总结一句话**：angr 是引擎，LLM 是司机。
没有 LLM，angr 的"自动"只是"自动符号执行"，需要人喂每个 find/avoid；
有了 LLM，"自动"才升级成"自动判断该往哪跑、跑完再决定下一步"。

## 7. 复现方式

```bash
# 1. 装环境（一次性，angr 依赖较重）
python3.11 -m venv .venv       # 任意 3.10+ Python
./.venv/bin/pip install -r requirements.txt

# 2. 配 key（不能提交进 git）
echo "DEEPSEEK_API_KEY=sk-xxx" > ~/.deepseek.env
echo "DEEPSEEK_BASE_URL=https://api.deepseek.com" >> ~/.deepseek.env
chmod 600 ~/.deepseek.env

# 3. 编译 crackme
cd target && gcc -O0 -g -o crackme crackme.c && cd ..

# 4. 跑 ReAct agent
./.venv/bin/python -m agent.react_agent \
    --binary target/crackme \
    --model deepseek-chat \
    --max-steps 6 \
    --log logs/run.log
```

## 8. 已知限制

- 当前 angr 工具的 buffer 地址 regex 假设栈地址落在 `0x7f0000000000-0x7fffffffffff` 区间；
  未来换架构或 PIE 二进制时需要适配
- `verify_input` 用 `subprocess.run` 跑二进制，3 秒超时（避开 AB 路径死循环导致整个 agent 挂掉）
- ReAct 主循环的 max_steps 缺省 6；本题正常 3-4 步就够

## 9. 文件清单

| 文件 | 用途 |
|---|---|
| `target/crackme.c` | 目标程序源码 |
| `target/crackme` | 编译产物 |
| `tools/angr_tools.py` | 三个 angr 工具 |
| `agent/react_agent.py` | ReAct 主循环 |
| `logs/run.log` | 4 轮 ReAct 完整日志 |
| `scripts/replay_angr_only.py` | 不依赖 LLM 的 angr 复现脚本（调试用）|
| `requirements.txt` | 依赖 |
| `README.md` | 复现指南 |
| `.gitignore` | 排除 .venv / logs / .env |
