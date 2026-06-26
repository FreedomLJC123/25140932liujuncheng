

主题：[作业提交] ReAct + angr 自动化逆向分析

正文：

张强老师您好，

这是本学期基于 ReAct 智能体与 angr 的自动化逆向分析实验报告。

## 1. 仓库
- 仓库地址：https://github.com/FreedomLJC123/25140932liujuncheng
- 本次 commit hash：见仓库 log

## 2. 实验结果
- 目标程序：target/crackme（4 字节密码，含 gadget_trap 死循环陷阱）
- ReAct agent 经过 **4 轮** Thought → Action → Observation 闭环求解
- 求出密码：**AZcE**（验证二进制 stdout 含 "Success! Flag is found."）

## 3. 关键交付物
- `tools/angr_tools.py`：angr 工具封装（controlled_explore / solve_input / verify_input）
- `agent/react_agent.py`：ReAct 主循环（DeepSeek function calling）
- `logs/run.log`：4 轮完整 ReAct 交互日志
- `report.md`：完整实验报告（含思考题：LLM 在本实验中的角色）
- `README.md`：复现简介（个人理解）

## 4. 复现命令
```bash
python3.11 -m venv .venv
./.venv/bin/pip install -r requirements.txt
echo "DEEPSEEK_API_KEY=sk-xxx" > ~/.deepseek.env
chmod 600 ~/.deepseek.env
cd target && gcc -O0 -g -o crackme crackme.c && cd ..
./.venv/bin/python -m agent.react_agent --binary target/crackme --model deepseek-chat --max-steps 6 --log logs/run.log
```

联系方式：18222214365 刘俊丞
```
