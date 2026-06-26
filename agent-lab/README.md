# agent-lab · ReAct + angr 自动化逆向

基于 ReAct 智能体与 angr 的自动化逆向分析

## 快速开始

```bash
# 1. 装环境（一次性）
python3.11 -m venv .venv
./.venv/bin/pip install -r requirements.txt

# 2. 配 API key（不会进 git）
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

## 项目结构

```
agent-lab/
├── README.md            # 本文件
├── report.md            # 实验报告
├── requirements.txt     # 依赖
├── .gitignore
├── target/
│   ├── crackme.c        # 目标程序源码
│   └── crackme          # 编译产物
├── tools/
│   └── angr_tools.py    # angr 工具封装
├── agent/
│   └── react_agent.py   # ReAct 主循环
├── logs/
│   └── run.log          # 4 轮 ReAct 完整日志
└── scripts/
    └── replay_angr_only.py  # 不依赖 LLM 的 angr 复现（调试用）
```

## 工具清单

| 工具 | 用途 |
|---|---|
| `controlled_explore(binary, find, avoid, max_steps)` | 跑一次 angr 符号执行 |
| `solve_input(state_ref_id)` | 从命中的 simstate 求解具体输入 |
| `verify_input(binary, input_str)` | 真跑二进制确认 stdout 是否含 "Success" |
| `final_answer(answer)` | ReAct 收尾出口 |

## 预期结果

LLM 经过 3-4 轮 Thought → Action → Observation，求出密码 `AZcE`，
调用 `verify_input` 看到 stdout 含 `Success! Flag is found.`，任务完成。

完整日志在 `logs/run.log`。
