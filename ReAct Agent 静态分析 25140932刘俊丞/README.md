# static-lab · 基于 ReAct 智能体的的二进制静态分析 25140932 刘俊丞

> 基于 ReAct 智能体的的二进制静态分析 25140932 刘俊丞

## 复现

```bash
cd static-lab
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt

echo "DEEPSEEK_API_KEY=sk-xxx" > ~/.deepseek.env
echo "DEEPSEEK_BASE_URL=https://api.deepseek.com" >> ~/.deepseek.env
chmod 600 ~/.deepseek.env

./.venv/bin/python -m agent.react_agent \
    --binary target/challenge \
    --max-steps 8 \
    --log logs/run.txt \
    --vuln-out output/vuln.json
```

跑完会得到：
- `logs/run.txt` —— 完整 ReAct 交互日志（≥3 轮）
- `output/vuln.json` —— Agent Final Answer（vuln_type / location / cause）

## 工具依赖

| 工具 | 安装 | 备注 |
|---|---|---|
| `r2` (radare2 6.1.8) | `brew install radare2` | macOS 自带；Linux `apt install radare2` |
| Ghidra 12.1.2 | 解压到 `$GHIDRA_HOME` | 不需要 GUI；用 `support/analyzeHeadless` |
| JDK 21 | `brew install openjdk@21` | **必须 JDK 21**，JDK 26 与 Ghidra 12.1.2 不兼容（`setRunScriptsNoImport` 报错） |
| Python 3.10+ | - | |
| angr 9.2.x | `pip install angr` | 间接被 capstone / pyelftools 拉入，r2 也吃 capstone |

环境变量（脚本会自动 fallback）：

```bash
export GHIDRA_HOME=/path/to/ghidra_12.1.2_PUBLIC       # 默认 /tmp/ghidra_dl/ghidra_12.1.2_PUBLIC
export JAVA_HOME=/opt/homebrew/opt/openjdk@21         # brew install openjdk@21
export DEEPSEEK_API_KEY=sk-xxx
export DEEPSEEK_BASE_URL=https://api.deepseek.com
```

## 项目结构

```
static-lab/
├── README.md
├── report.md
├── requirements.txt
├── .gitignore
├── target/challenge                # 待分析 ELF
├── tools/
│   ├── r2_tools.py                 # 8 个 radare2 工具
│   └── ghidra_tools.py             # 4 个 Ghidra headless 工具
├── agent/
│   └── react_agent.py              # ReAct 主循环
├── logs/run.txt                    # 7 轮完整 ReAct 日志
├── output/vuln.json                # Agent Final Answer
└── scripts/
    └── replay_no_llm.py            # 不依赖 LLM 的两工具串行演示
```

## 工具清单（13 个）

### r2（8）
- `r2_info` / `r2_functions` / `r2_strings` / `r2_disasm` / `r2_disasm_function`
- `r2_cfg_summary` / `r2_xrefs_to` / `r2_callgraph`

### Ghidra（4）
- `ghidra_functions` / `ghidra_decompile` / `ghidra_strings` / `ghidra_xrefs`

### 收尾（1）
- `final_answer(vuln_type, location, cause)` → 写 `output/vuln.json`

## 怎么判定漏洞（Agent 决策路径）

1. `r2_info` 摸底：x86_64 / no canary / no pic / partial relro / stripped / GCC 11.4
2. `r2_functions` + `r2_strings` 找入口点和可疑字符串（"boot" / "selftest" / "[%s] %s"）
3. `ghidra_functions` 找 main（stripped，Ghidra 叫 `FUN_00401264`）
4. `r2_disasm_function(main)` 看到 `fgets(s1, 0x80, stdin)` + `cmp rax, 0x63; jbe 0x401377` + `call __strcpy_chk`
5. `ghidra_decompile(FUN_00401264)` 看到 `__strcpy_chk(&local_a8, local_88, 0x10)` —— dest 16B vs source 可达 100B
6. `r2_disasm(0x401377, 20)` 印证：`mov edx, 0x10; call __strcpy_chk`
7. `final_answer` → vuln.json

## 实验发现中的问题（已解决）

- **Ghidra 项目路径不能用 `.<name>` 开头**（`GhidraURL.checkLocalAbsolutePath` 拒绝），脚本已用 `~/ghidra_lab_cache` 而非 `~/.ghidra_projects`
- **`-postScript` 参数不接受路径**，必须 `-scriptPath <dir>` 后只给 bare filename
- **JDK 版本**：Ghidra 12.1.2 跟 JDK 26 不兼容（`setRunScriptsNoImport` 抛 `IllegalArgumentException`），用 JDK 21
- **r2 函数名匹配**：要 `aaa` 之后才能 `pdf @ main`；脚本里所有 r2 反汇编类工具都先跑 `aaa`
- **Ghidra FunctionIterator 不是 List**：要用 `it.hasNext()` 迭代，不能转成 `List<Function>`
- **Ghidra `DataIterator`** 在 `ghidra.program.model.listing`，不是 `.data`
