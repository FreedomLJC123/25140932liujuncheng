"""
ghidra_tools.py — Ghidra 12 headless 工具封装，供 ReAct agent 调用。

设计：
  - 后端用 Ghidra 12.x 的 analyzeHeadless + Java post-script 导出分析结果
  - 每个工具对应一个 post-script：ListFuncs / DecompileFn / ListStrings / Xrefs
  - 第一次 import 会做完整 auto-analysis (~30-60s)，后续只跑 script (几秒)
  - 需要 JDK 21+ (用 brew install openjdk@21，JDK 26 与 Ghidra 12.x 不兼容)

工具清单：
  1) ghidra_decompile(binary, function)  — 伪 C 反编译
  2) ghidra_functions(binary)            — 函数清单（含 frame size / 签名）
  3) ghidra_strings(binary)              — 字符串清单
  4) ghidra_xrefs(binary, addr)          — addr 的所有交叉引用

环境要求：
  - JDK 21 在 /opt/homebrew/opt/openjdk@21/bin/java (或 set JAVA_HOME)
  - GHIDRA_HOME 指向 Ghidra 解压根 (默认 /tmp/ghidra_dl/ghidra_12.1.2_PUBLIC)
"""

from __future__ import annotations
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# 路径 & 环境
# ---------------------------------------------------------------------------
GHIDRA_HOME = os.environ.get("GHIDRA_HOME", "/tmp/ghidra_dl/ghidra_12.1.2_PUBLIC")
ANALYZE_HEADLESS = os.path.join(GHIDRA_HOME, "support", "analyzeHeadless")

# 找 JDK 21
def _find_jdk21() -> str:
    for cand in [
        "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
        "/opt/homebrew/opt/openjdk@21",
        "/usr/lib/jvm/java-21-openjdk-amd64",
        "/Library/Java/JavaVirtualMachines/openjdk-21.jdk/Contents/Home",
    ]:
        if os.path.isfile(os.path.join(cand, "bin", "java")):
            return cand
    return os.environ.get("JAVA_HOME", "")

JAVA_HOME = _find_jdk21() or os.environ.get("JAVA_HOME", "")
SCRIPTS_DIR = Path("/tmp/ghidra_lab_scripts")
SCRIPTS_DIR.mkdir(exist_ok=True)

# 缓存目录：每个 binary 一个 Ghidra project
_PROJECT_CACHE: dict[str, str] = {}


def _ensure_env() -> None:
    if not os.path.isfile(ANALYZE_HEADLESS):
        raise RuntimeError(
            f"Ghidra analyzeHeadless not found at {ANALYZE_HEADLESS}. "
            f"Set GHIDRA_HOME or install Ghidra."
        )
    if not os.path.isfile(os.path.join(JAVA_HOME, "bin", "java")):
        raise RuntimeError(
            f"Java not found at {JAVA_HOME}. Ghidra 12.x 需要 JDK 21，"
            f"运行 `brew install openjdk@21`。"
        )


# ---------------------------------------------------------------------------
# post-script 模板（写入 SCRIPTS_DIR）
# ---------------------------------------------------------------------------
_LIST_FUNCS = r"""//List all functions in program
//@category StaticLab
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.*;

public class ListFuncs extends GhidraScript {
    public void run() throws Exception {
        StringBuilder sb = new StringBuilder();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            sb.append(String.format("FUNC %s\t%s\tsize=%d\tframe=%d\t%s\n",
                f.getEntryPoint(),
                f.getName(),
                f.getBody().getNumAddresses(),
                f.getStackFrame().getFrameSize(),
                f.getSignature().getPrototypeString()));
        }
        String outPath = System.getProperty("user.home") + "/.ghidra_scripts_out.txt";
        try (PrintWriter w = new PrintWriter(new FileWriter(outPath))) {
            w.print(sb.toString());
        }
        println("Wrote " + outPath);
    }
}
"""

_DECOMPILE_FN = r"""//Decompile function by name/address from env
//@category StaticLab
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.*;

public class DecompileFn extends GhidraScript {
    public void run() throws Exception {
        String targetFn = System.getenv("GHIDRA_DECOMPILE_TARGET");
        if (targetFn == null) { println("No GHIDRA_DECOMPILE_TARGET env"); return; }
        Function f = null;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function fn = it.next();
            String hexAddr = "0x" + Long.toHexString(fn.getEntryPoint().getOffset());
            if (fn.getName().equals(targetFn) ||
                fn.getName(true).equals(targetFn) ||
                fn.getEntryPoint().toString().equalsIgnoreCase(targetFn) ||
                hexAddr.equalsIgnoreCase(targetFn)) {
                f = fn;
                break;
            }
        }
        if (f == null) { println("Function not found: " + targetFn); return; }
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        DecompileResults res = ifc.decompileFunction(f, 60, new ConsoleTaskMonitor());
        if (res == null || !res.decompileCompleted()) {
            println("Decompile failed for " + f.getName());
            return;
        }
        String c = res.getDecompiledFunction().getC();
        String outPath = System.getProperty("user.home") + "/.ghidra_scripts_out.txt";
        try (PrintWriter w = new PrintWriter(new FileWriter(outPath))) {
            w.println("=== Function: " + f.getName() + " @ " + f.getEntryPoint() + " ===");
            w.println("Signature: " + f.getSignature().getPrototypeString());
            w.println("Stack frame: " + f.getStackFrame().getFrameSize() + " bytes");
            w.println("--- Decompiled C ---");
            w.println(c);
        }
        println("Wrote " + outPath);
    }
}
"""

_LIST_STRINGS = r"""//List all defined strings in program
//@category StaticLab
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import java.io.*;

public class ListStrings extends GhidraScript {
    public void run() throws Exception {
        StringBuilder sb = new StringBuilder();
        Listing listing = currentProgram.getListing();
        DataIterator it = listing.getDefinedData(true);
        int n = 0;
        while (it.hasNext()) {
            Data d = it.next();
            if (d.hasStringValue()) {
                String s = d.getValue().toString();
                if (s != null && s.length() >= 4) {
                    sb.append(String.format("STR %s\tlen=%d\t%s\n", d.getAddress(), s.length(), s));
                    n++;
                }
            }
        }
        String outPath = System.getProperty("user.home") + "/.ghidra_scripts_out.txt";
        try (PrintWriter w = new PrintWriter(new FileWriter(outPath))) {
            w.print("count=" + n + "\n");
            w.print(sb.toString());
        }
        println("Wrote " + outPath);
    }
}
"""

_XREFS = r"""//List xrefs to address from env GHIDRA_XREF_TARGET
//@category StaticLab
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import java.io.*;

public class Xrefs extends GhidraScript {
    public void run() throws Exception {
        String targetStr = System.getenv("GHIDRA_XREF_TARGET");
        if (targetStr == null) { println("No GHIDRA_XREF_TARGET env"); return; }
        long off = Long.decode(targetStr);
        AddressFactory af = currentProgram.getAddressFactory();
        AddressSpace dflt = af.getDefaultAddressSpace();
        Address addr = dflt.getAddress(off);
        ReferenceManager rm = currentProgram.getReferenceManager();
        ReferenceIterator it = rm.getReferencesTo(addr);
        StringBuilder sb = new StringBuilder();
        int n = 0;
        while (it.hasNext()) {
            Reference r = it.next();
            sb.append(String.format("XREF from %s  type=%s\n", r.getFromAddress(), r.getReferenceType()));
            n++;
        }
        String outPath = System.getProperty("user.home") + "/.ghidra_scripts_out.txt";
        try (PrintWriter w = new PrintWriter(new FileWriter(outPath))) {
            w.print("target=" + addr + "\n");
            w.print("count=" + n + "\n");
            w.print(sb.toString());
        }
        println("Wrote " + outPath);
    }
}
"""

_SCRIPTS = {
    "ListFuncs.java":   _LIST_FUNCS,
    "DecompileFn.java": _DECOMPILE_FN,
    "ListStrings.java": _LIST_STRINGS,
    "Xrefs.java":       _XREFS,
}


def _write_scripts() -> None:
    for name, body in _SCRIPTS.items():
        p = SCRIPTS_DIR / name
        if not p.exists() or p.read_text(encoding="utf-8") != body:
            p.write_text(body, encoding="utf-8")


def _get_or_create_project(binary: str) -> str:
    """
    对每个 binary 在 ~/ghidra_lab_cache/<hash>/ 下建项目。
    第一次会执行 import + auto-analysis，~30-60s。
    后续直接 -process (复用已分析的项目)，~5-10s。

    路径里不能含 `.<name>` 元素（GhidraURL.checkLocalAbsolutePath 会拒绝）。
    """
    _ensure_env()
    _write_scripts()
    cache_root = Path.home() / "ghidra_lab_cache"
    cache_root.mkdir(exist_ok=True)
    import hashlib
    proj_name = "lab_" + hashlib.md5(binary.encode()).hexdigest()[:12]
    proj_dir = cache_root / proj_name
    gpr_path = proj_dir / f"{proj_name}.gpr"

    env = os.environ.copy()
    env["JAVA_HOME"] = JAVA_HOME
    env["PATH"] = f"{JAVA_HOME}/bin:" + env.get("PATH", "")

    if not gpr_path.exists():
        proj_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            ANALYZE_HEADLESS,
            str(proj_dir), proj_name,
            "-import", binary,
            "-overwrite",
            "-analysisTimeoutPerFile", "120",
        ]
        out = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=300)
        if not gpr_path.exists():
            raise RuntimeError(
                f"Ghidra import failed:\n---stderr---\n{out.stderr[-1500:]}\n---stdout---\n{out.stdout[-800:]}"
            )
    _PROJECT_CACHE[binary] = str(proj_dir)
    return str(proj_dir)


def _run_script(binary: str, script_class: str, extra_env: dict[str, str],
                timeout: int = 180) -> tuple[bool, str, str]:
    """
    Run a post-script on the existing Ghidra project.
    Returns (ok, output_text, stderr_or_error).
    """
    out_path = str(Path.home() / ".ghidra_scripts_out.txt")
    try:
        Path(out_path).unlink()
    except FileNotFoundError:
        pass

    _get_or_create_project(binary)
    proj_dir = _PROJECT_CACHE[binary]
    proj_name = os.path.basename(proj_dir)

    env = os.environ.copy()
    env["JAVA_HOME"] = JAVA_HOME
    env["PATH"] = f"{JAVA_HOME}/bin:" + env.get("PATH", "")
    for k, v in extra_env.items():
        env[k] = v

    # 注意：不要传 gpr_path（会被 setRunScriptsNoImport 拒），只传 -process
    cmd = [
        ANALYZE_HEADLESS,
        proj_dir, proj_name,
        "-process",
        "-noanalysis",
        "-scriptPath", str(SCRIPTS_DIR),
        "-postScript", script_class,
    ]
    p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout)
    if not os.path.exists(out_path):
        return False, "", (
            f"analyzeHeadless rc={p.returncode}; "
            f"stderr tail: {p.stderr[-500:]}; "
            f"stdout tail: {p.stdout[-500:]}"
        )
    text = Path(out_path).read_text(encoding="utf-8", errors="replace")
    return True, text, p.stderr[-300:]


# ---------------------------------------------------------------------------
# 工具 1: ghidra_decompile
# ---------------------------------------------------------------------------
def ghidra_decompile(binary: str, function: str) -> dict:
    t0 = time.time()
    try:
        ok, text, err = _run_script(binary, "DecompileFn", {"GHIDRA_DECOMPILE_TARGET": function})
        if not ok:
            return {"ok": False, "error": err, "log_tail": f"[ghidra_decompile] ERROR: {err}"}
        return {
            "ok": True, "function": function,
            "elapsed_secs": round(time.time() - t0, 3),
            "log_tail": f"[ghidra_decompile] {function}\n{text}",
        }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}",
                "log_tail": f"[ghidra_decompile] ERROR: {e}"}


# ---------------------------------------------------------------------------
# 工具 2: ghidra_functions
# ---------------------------------------------------------------------------
def ghidra_functions(binary: str) -> dict:
    t0 = time.time()
    try:
        ok, text, err = _run_script(binary, "ListFuncs", {})
        if not ok:
            return {"ok": False, "error": err, "log_tail": f"[ghidra_functions] ERROR: {err}"}
        funcs: list[dict] = []
        for line in text.splitlines():
            m = re.match(r"FUNC\s+(\S+)\s+(\S+)\s+size=(\d+)\s+frame=(\d+)\s+(.*)", line)
            if m:
                funcs.append({
                    "addr": m.group(1), "name": m.group(2),
                    "size": int(m.group(3)), "frame": int(m.group(4)),
                    "signature": m.group(5),
                })
        pretty = "\n".join(
            f"  {f['addr']:>14s}  size={f['size']:5d}  frame={f['frame']:4d}  {f['name']}  ::  {f['signature']}"
            for f in funcs
        ) or "  (no functions)"
        return {
            "ok": True, "count": len(funcs), "functions": funcs,
            "elapsed_secs": round(time.time() - t0, 3),
            "log_tail": f"[ghidra_functions] {len(funcs)} functions\n{pretty}",
        }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}",
                "log_tail": f"[ghidra_functions] ERROR: {e}"}


# ---------------------------------------------------------------------------
# 工具 3: ghidra_strings
# ---------------------------------------------------------------------------
def ghidra_strings(binary: str, min_len: int = 4) -> dict:
    t0 = time.time()
    try:
        ok, text, err = _run_script(binary, "ListStrings", {})
        if not ok:
            return {"ok": False, "error": err, "log_tail": f"[ghidra_strings] ERROR: {err}"}
        rows: list[dict] = []
        for line in text.splitlines():
            m = re.match(r"STR\s+(\S+)\s+len=(\d+)\s+(.*)", line)
            if m and int(m.group(2)) >= min_len:
                rows.append({"addr": m.group(1), "len": int(m.group(2)), "value": m.group(3)})
        pretty = "\n".join(
            f"  {r['addr']:>12s}  ({r['len']:3d}B)  {r['value'][:80]}"
            for r in rows
        ) or "  (no strings)"
        return {
            "ok": True, "count": len(rows), "strings": rows,
            "elapsed_secs": round(time.time() - t0, 3),
            "log_tail": f"[ghidra_strings] {len(rows)} strings\n{pretty}",
        }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}",
                "log_tail": f"[ghidra_strings] ERROR: {e}"}


# ---------------------------------------------------------------------------
# 工具 4: ghidra_xrefs
# ---------------------------------------------------------------------------
def ghidra_xrefs(binary: str, addr: str) -> dict:
    t0 = time.time()
    try:
        ok, text, err = _run_script(binary, "Xrefs", {"GHIDRA_XREF_TARGET": addr})
        if not ok:
            return {"ok": False, "error": err, "log_tail": f"[ghidra_xrefs] ERROR: {err}"}
        return {
            "ok": True, "addr": addr,
            "elapsed_secs": round(time.time() - t0, 3),
            "log_tail": f"[ghidra_xrefs] to {addr}\n{text}",
        }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}",
                "log_tail": f"[ghidra_xrefs] ERROR: {e}"}


# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------
GHIDRA_TOOL_DISPATCH = {
    "ghidra_decompile": ghidra_decompile,
    "ghidra_functions": ghidra_functions,
    "ghidra_strings":   ghidra_strings,
    "ghidra_xrefs":     ghidra_xrefs,
}
