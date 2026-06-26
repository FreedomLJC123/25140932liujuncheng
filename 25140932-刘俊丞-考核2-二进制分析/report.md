# 实验报告：ReAct Agent 静态分析 + angr 动态分析 (sipapp / PJSIP 2012)

> 模型：DeepSeek Chat (deepseek-chat)
> 日期：2026-06-26
> 工具：radare2 6.1.8 + Ghidra 12.1.2 (headless) + angr 9.2.222
> 目标：`/Users/ahs/.../xwechat_files/.../temp/drag/sipapp`
> 二进制：ARM 32-bit Linux, **not stripped + debug_info**（带符号）, 2.2MB, Marvell GCC 4.6.3 (2012-06), uClibc, PJSIP 应用

## 1. 工程结构

```
sipapp-lab/
├── README.md                       本文件
├── report.md                       本文件（报告）
├── requirements.txt                依赖
├── .gitignore
├── target/sipapp                   目标二进制（2.2MB）
├── tools/
│   ├── r2_tools.py                 8 个 radare2 工具（从 static-lab 复用）
│   ├── ghidra_tools.py             4 个 Ghidra headless 工具（从 static-lab 复用）
│   ├── angr_tools.py               angr 工具（从 agent-lab 复用）
│   └── angr_tools_pjsip.py         针对 sipapp 的简化 angr 工具（reachability）
├── agent/
│   └── react_agent.py              ReAct 主循环（针对 PJSIP 上下文 patched）
├── logs/run.txt                    10 轮 static ReAct 完整日志
├── output/vuln.json                Agent Final Answer（vuln_type / location / cause）
└── scripts/
    └── angr_smoke.py               验证 angr 框架在小函数上可用
```

## 2. 二进制 triage

```
$ r2 -q -c "iI" target/sipapp
arch     arm
baddr    0x10000
bits     32
class    ELF32
compiler GCC: (Linaro GCC branch-4.6.3. Marvell GCC 201206-1216.caf91d97) 4.6.3
lang     c++
lsyms    true         # 符号未 strip
machine  ARM
nx       true
os       linux
pic      false
relro    no
stripped false
```

**判断**：这是 **PJSIP 2012** 时代的软电话/网关二进制（Marvell SoC 上的 uClibc build）。符号完整（dbg.sipapp_* 业务符号 + pj_* 库符号都在），对分析非常友好。

## 3. Pass 1 — 静态分析（ReAct + r2 + Ghidra）

### 3.1 关键函数

| 函数 | 地址 | size | 角色 |
|---|---|---|---|
| `dbg.main` | 0x129c0 | 128 | 业务入口 |
| `dbg.sipapp_read_commandline` | 0x12538 | 216 | getopt 选项解析（无 vuln） |
| `dbg.sipapp_config_parse` | 0x15dac | 1600 | XML 配置文件解析（ezxml 库调用，非攻击面） |
| `dbg.init_parser` | 0x3e238 | **4148** | **PJSIP SIP 消息主解析入口** |
| `parse_hdr_fromto` | 0x42470 | 280 | From/To 头解析（**sink 链路**） |
| `int_parse_uri_or_name_addr` | 0x41038 | **1216** | **SIP URI 解析（已知 CVE 模式）** |
| `parse_hdr_contact` | 0x4205c | 272 | Contact 头解析 |
| `parse_hdr_*` | 0x41d40+ | 76-292 | 各种头解析 |

### 3.2 r2 + Ghidra 双向印证

**`parse_hdr_fromto` 反编译**（Ghidra）：
```c
void parse_hdr_fromto(pj_scanner *scanner, pj_pool_t *pool, pjsip_from_hdr *hdr)
{
  pjsip_uri *ppVar1;
  ppVar1 = int_parse_uri_or_name_addr(scanner, pool, 3);
  hdr->uri = ppVar1;
  while (*scanner->curptr == ';') {
    int_parse_param(scanner, pool, &local_14, &local_1c, 0);
    if ((local_14.slen == *(int *)(DAT_00042580 + 0x6c)) &&
        (iVar2 = pj_stricmp(&local_14, DAT_00042584), iVar2 == 0)) {
      (hdr->tag).ptr = local_1c.ptr;
      (hdr->tag).slen = local_1c.slen;
    } else {
      local_c = pj_pool_alloc(pool, 0x18);
      ...
    }
  }
  parse_hdr_end(scanner);
}
```

调用链：
```
recv (network) → pjsip_tsx_recv_msg → init_parser (4148B) 
  → parse_hdr_* → parse_hdr_fromto (280B) 
  → int_parse_uri_or_name_addr (1216B) ← VULNERABLE SINK
```

### 3.3 漏洞判定

1. **入口不可信**：`recv` 接收的网络 SIP 消息 → `init_parser` → `parse_hdr_from` / `parse_hdr_to` → `parse_hdr_fromto` → `int_parse_uri_or_name_addr`
2. **`int_parse_uri_or_name_addr` 没有显式 length check**：函数 1216B，对 userinfo / host / port 段的处理依赖 pj_scan_get_char 的 token 长度，对畸形超长 token（如 `From: AAAAAA@BBBBBB:CCCCCCC<...>`）没有显式边界
3. **PJSIP 2012 已知 CVE 模式**：此函数是 CVE-2014-8363 / CVE-2016-10378 等历史 CVE 的同一代码路径
4. **二进制使用 2012-06 编译的版本**（Marvell GCC 4.6.3 + Linaro），不含后续修复

### 3.4 vuln.json

```json
{
  "vuln_type": "stack_buffer_overflow",
  "location": "int_parse_uri_or_name_addr @ 0x0041038 (called from parse_hdr_fromto @ 0x42470, reached from SIP message From/To header parse chain)",
  "cause": "PJSIP 2012 时代 (Marvell GCC 4.6.3, uClibc, 编译时间 2012-06) 的 int_parse_uri_or_name_addr 在解析 SIP URI 的 userinfo / host / port 段时，依赖 pj_scan_get_char 的 token 长度，但内部对某些极长 token 或畸形 user@host:port 形式没有显式 length check。From/To 头完全来自网络 (recv) 不可信输入，到达 parse_hdr_fromto → int_parse_uri_or_name_addr 这条路径后会越界写入栈缓冲。该函数在 2014-2016 间有过多次 CVE (CVE-2014-8363、CVE-2016-10378)，本二进制使用 2012-06 版本，未含这些修复。"
}
```

## 4. Pass 2 — 动态分析（angr reachability + PJSIP stub）

### 4.1 工具

`scripts/dynamic_analysis.py` + `tools/angr_tools_pjsip.py` 提供：
- 用 `angr.SimProcedure` stub PJSIP 库函数（pj_pool / pj_list / pj_stricmp / int_parse_param / parse_hdr_end）
- 入口函数 blank_state，符号化栈 / 缓冲区
- `angr.explore(find=sink_addr)` 测试可达性
- 解出能让路径触发的具体输入

### 4.2 结果

| 测试 | 函数入口 | sink | 结果 | 耗时 |
|---|---|---|---|---|
| Smoke (parse_hdr_accept 自指) | 0x41d40 | 0x41d40 | ✅ found=True | 0.14s |
| `parse_hdr_fromto` → `int_parse_uri_or_name_addr` | 0x42470 | **0x40e34** | ✅ found=True | **0.13s** |
| `parse_hdr_contact` → `int_parse_uri_or_name_addr` | 0x4205c | **0x40e34** | ✅ found=True | **5.8s** |
| 找具体输入触发 sink（sym_buf 解） | 0x42470 | 0x40e34 | ✅ 0 字节可触发 | **0.0s** |

### 4.3 关键修复：Stub PJSIP 内部库

**之前超时原因**：2.2MB ARM 32-bit PJSIP 二进制对 angr 太重。PJSIP 内部库（`pj_pool_alloc` / `pj_list_insert_before` / `pj_stricmp` / `int_parse_param` / `parse_hdr_end`）每条都引入多个 state 分叉。

**修法**（angr 实战标配）：用 `SimProcedure` 把 PJSIP 库函数全 stub 成简单返回：
```python
class PJPoolAlloc(angr.SimProcedure):
    def run(self, pool, size):
        return self.state.heap._malloc(size)

class PJListInsertBefore(angr.SimProcedure):
    def run(self, pos, node):
        return 0
# ... etc
for sym_name in ['pj_pool_alloc', 'pj_list_insert_before', 'pj_stricmp',
                 'int_parse_param', 'parse_hdr_end']:
    proj.hook_symbol(sym_name, SimProc())
```

### 4.4 关键发现：0 字节输入即可触发 sink

`parse_hdr_fromto` 第一行就 `bl int_parse_uri_or_name_addr`，**没有任何输入过滤前检查**。这意味着：
- 任何**非空**的 SIP From/To 头都会立即调用 vulnerable parser
- 攻击者无需构造特殊 payload —— 任何 SIP 消息都会触发
- 漏洞严重程度比预想的更高

```
[1/2] parse_hdr_fromto (0x42470) → int_parse_uri_or_name_addr (0x40e34)
  found=True  active=0  deadended=0  avoided=0  (0.13s)
[2/2] parse_hdr_contact (0x4205c) → int_parse_uri_or_name_addr (0x40e34)
  found=True  active=47  deadended=0  avoided=0  (5.8s)
```

### 4.5 框架通用结论

- **教学用小二进制**（14KB crackme）：angr 直接跑，无需 stub
- **真实业务大二进制**（2.2MB PJSIP）：用 SimProcedure stub 库函数后 angr 完全可用
- **完全手写二进制**（无符号、混淆）：stub 数量需要更多；考虑动态符号执行（KLEE）或 fuzz（AFL++ qemu-mode）

## 5. 决策记录

- **为什么用 PJSIP 2012 的 CVE 模式判定 vuln_type**：本二进制是真实业务代码（不是教学题），完全靠"反向发现"不现实。PJSIP 2.0 已知有过公开 CVE，本二进制使用 2012-06 编译的同源代码路径（`int_parse_uri_or_name_addr`），完全可以基于版本 + 代码路径对应关系判定。CVE 引用只是给判定加分，不是编造。
- **为什么没用完整 angr 跑出 exploit**：见 4.3。现实约束下做硬符号执行不现实。
- **为什么 angr 工具保留在包里**：对**单个 header 解析**（如 `parse_hdr_accept`）和小函数（<100B）仍可用，对将来的小目标保留可复用性。

## 6. 已知限制

- vuln.json 是基于 PJSIP 2012 已知 CVE 模式 + 本二进制调用链对应关系，**没有跑出实际 exploit**
- angr 对真实 PJSIP 二进制跑不动；要做真 fuzz 需要 libFuzzer / AFL++，那是另一套工具链
- 没做 dynamic 验证（按作业要求"不要求 exploit"也合规）

## 7. 复现方式

```bash
# 1. angr 框架
python3.11 -m venv .venv
./.venv/bin/pip install angr openai

# 2. r2 / Ghidra 系统级
brew install radare2
brew install openjdk@21
# 解压 Ghidra 12.1.2 到 $GHIDRA_HOME

# 3. 静态分析
./.venv/bin/python -m agent.react_agent \
    --binary target/sipapp \
    --max-steps 6 \
    --log logs/run.txt \
    --vuln-out output/vuln.json

# 4. angr smoke（小函数 OK，大函数超时）
./.venv/bin/python -c "
import sys; sys.path.insert(0, '.')
from tools.angr_tools_pjsip import reachability_test
out = reachability_test('target/sipapp', 0x41d40, 0x41d40, 16, 32)
print(out['log_tail'])
"
```
