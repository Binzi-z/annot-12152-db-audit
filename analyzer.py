#!/usr/bin/env python3
"""analyzer.py —— 跨包污点分析 + 按包缓存的增量引擎。

分析模型
--------
- 包 = 目录；缓存按包组织（<root>/.scancache/cache.json）。
- 每个函数算一个 summary：propagates（参数是否污染返回值）、sanitizes（是否净化）。
  包间只通过 summary 耦合，这是增量与全量逐条一致的关键：
  包 P 的 findings 只取决于「自己的文件内容」+「它引用的外部符号的 summary」。
- 失效规则：
  1. 同包文件变更         -> 重扫本包；
  2. 被调符号 summary 变更 -> 沿反向依赖边重扫调用方（跨包传播）；
  3. 接口定义变更          -> 重扫声明了同名方法的包（实现方）。
- 脏读防护：每轮先做 manifest 对账（磁盘 vs 缓存），已删除文件/包的
  缓存条目先作废再分析；缓存内容寻址 + 原子落盘 + 版本号。详见 README。
"""
import hashlib
import json
import os
import re
import tempfile

CACHE_VERSION = 3

# ---------------------------------------------------------------- 词法规则

SOURCE_RE = re.compile(r"\.URL\.Query\(\)|\.FormValue\(|\.PostFormValue\(")

# 标准库净化调用（限定名）
STDLIB_SANITIZERS = {"strings.ReplaceAll", "filepath.Clean", "path.Clean"}
# 项目内已知净化函数（按名引导；summary 会把净化性传播给包装函数）
KNOWN_SANITIZER_NAMES = {"onlyDigits", "allowlistHost"}

SINKS = [
    (re.compile(r"\bqueryStr\(|\bdb\.Query\(|\b\w+\.Query\("), "cwe-89"),
    (re.compile(r"\brunCmd\(|\bexec\.Command\("), "cwe-78"),
    (re.compile(r"\breadFile\(|\bos\.Open\(|\bos\.ReadFile\("), "cwe-22"),
    (re.compile(r"\bfetch\(|\bhttp\.Get\(|\bhttp\.Post\("), "cwe-918"),
]

RULE_META = {
    "cwe-89":  ("sql-injection",     "SQL 注入：未净化的用户输入进入 SQL 查询"),
    "cwe-78":  ("command-injection", "命令注入：未净化的用户输入进入命令执行"),
    "cwe-22":  ("path-traversal",    "路径穿越：未净化的用户输入进入文件路径"),
    "cwe-918": ("ssrf",              "SSRF：未净化的用户输入进入外发请求"),
}

FUNC_RE = re.compile(
    r"^func\s+(?:\(\s*(?:(\w+)\s+)?\*?(\w+)\s*\)\s+)?(\w+)\s*\(([^)]*)\)\s*[^{\n]*\{")
IMPORT_BLOCK_RE = re.compile(r'import\s*\(([^)]*)\)', re.S)
IMPORT_LINE_RE = re.compile(r'^\s*(?:(\w+)\s+)?"([^"]+)"', re.M)
IFACE_RE = re.compile(r"type\s+(\w+)\s+interface\s*\{(.*?)\}", re.S)
IDENT_RE = re.compile(r"[A-Za-z_]\w*")
CALL_RE = re.compile(r"(?:(\w+)\.)?(\w+)\(")


# ---------------------------------------------------------------- 解析

class Func:
    __slots__ = ("name", "recv", "params", "start", "body")

    def __init__(self, name, recv, params, start, body):
        self.name, self.recv, self.params = name, recv, params
        self.start, self.body = start, body  # body: [(lineno, text)]

    @property
    def is_entry(self):
        return "http.ResponseWriter" in self.params and "*http.Request" in self.params

    @property
    def param_names(self):
        names = []
        for part in self.params.split(","):
            toks = part.split()
            if len(toks) >= 2:
                names.extend(toks[:-1])
        return names


class GoFile:
    def __init__(self, path, text):
        self.path = path
        m = re.search(r"^package\s+(\w+)", text, re.M)
        self.pkg_name = m.group(1) if m else "main"
        self.imports = {}  # alias -> import path
        for block in IMPORT_BLOCK_RE.findall(text):
            for alias, ipath in IMPORT_LINE_RE.findall(block):
                self.imports[alias or ipath.rsplit("/", 1)[-1]] = ipath
        for m2 in re.finditer(r'^\s*import\s+(?:(\w+)\s+)?"([^"]+)"', text, re.M):
            alias, ipath = m2.group(1), m2.group(2)
            self.imports[alias or ipath.rsplit("/", 1)[-1]] = ipath
        self.funcs = self._parse_funcs(text)
        self.interfaces = {
            m.group(1): sorted(set(re.findall(r"(\w+)\s*\(", m.group(2))))
            for m in IFACE_RE.finditer(text)
        }

    def _parse_funcs(self, text):
        funcs, lines = [], text.splitlines()
        i = 0
        while i < len(lines):
            m = FUNC_RE.match(lines[i].strip())
            if not m:
                i += 1
                continue
            recv_t, name, params = m.group(2), m.group(3), m.group(4)
            depth, body, j = 0, [], i
            while j < len(lines):
                depth += lines[j].count("{") - lines[j].count("}")
                if j > i:
                    body.append((j + 1, lines[j]))
                j += 1
                if depth <= 0:
                    break
            funcs.append(Func(name, recv_t, params, i + 1, body))
            i = j
        return funcs


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def discover_packages(root):
    """walk root -> {rel_dir: {relpath: text}}；目录即包。"""
    pkgs = {}
    for dirpath, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".scancache", ".git")]
        gos = [n for n in names if n.endswith(".go")]
        if not gos:
            continue
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        pkgs[rel_dir] = {}
        for n in sorted(gos):
            rel = os.path.join(rel_dir, n).replace("\\", "/")
            with open(os.path.join(dirpath, n), encoding="utf-8") as fh:
                pkgs[rel_dir][rel] = fh.read()
    return pkgs


def module_name(root):
    try:
        with open(os.path.join(root, "go.mod"), encoding="utf-8") as fh:
            m = re.search(r"^module\s+(\S+)", fh.read(), re.M)
            return m.group(1) if m else ""
    except OSError:
        return ""


def pkg_path(module, rel_dir):
    return module if rel_dir == "." else module + "/" + rel_dir


# ---------------------------------------------------------------- 污点引擎

class Summary:
    def __init__(self, propagates=False, sanitizes=False):
        self.propagates, self.sanitizes = propagates, sanitizes

    @property
    def hash(self):
        # 只含语义，不含参数名/位置 —— 改参数名、加注释不会误触发失效
        return sha256(f"{int(self.propagates)}|{int(self.sanitizes)}")[:16]

    def to_json(self):
        return {"propagates": self.propagates, "sanitizes": self.sanitizes,
                "hash": self.hash}


class Engine:
    """summary 表驱动的过程间污点。所有包共用一张表，跨包调用按 import alias 解析。"""

    def __init__(self, summaries):
        self.summaries = summaries  # {pkg_path: {func_name: Summary}}

    def resolve(self, pkg, imports, alias, fname):
        if alias:
            ipath = imports.get(alias)
            if ipath and ipath in self.summaries:
                return self.summaries[ipath].get(fname)
            return None
        return self.summaries.get(pkg, {}).get(fname)

    def _calls(self, expr):
        return [(m.group(1), m.group(2)) for m in CALL_RE.finditer(expr)]

    def _is_sanitizing_expr(self, expr, pkg, imports):
        for alias, fname in self._calls(expr):
            if alias and f"{alias}.{fname}" in STDLIB_SANITIZERS:
                return True
            s = self.resolve(pkg, imports, alias, fname)
            if s is not None and s.sanitizes:
                return True
        return False

    def expr_taint(self, expr, tainted, pkg, imports):
        """expr 的求值结果是否带污点。"""
        if self._is_sanitizing_expr(expr, pkg, imports):
            return False
        if SOURCE_RE.search(expr):
            return True
        if not (set(IDENT_RE.findall(expr)) & tainted):
            return False
        calls = self._calls(expr)
        if not calls:
            return True  # 纯拼接/直传
        for alias, fname in calls:
            s = self.resolve(pkg, imports, alias, fname)
            if s is None:
                return True  # 未知函数：保守按传播处理（保召回）
            if s.propagates:
                return True
        return False

    def args_taint(self, args, tainted, pkg, imports):
        """sink 实参是否带污点（只看实参本身）。"""
        if self._is_sanitizing_expr(args, pkg, imports):
            return False
        if SOURCE_RE.search(args):
            return True
        return bool(set(IDENT_RE.findall(args)) & tainted)

    def run_body(self, func, pkg, imports, seed):
        """跑一个函数体，返回 (findings, returns_taint)。
        findings 仅入口函数的会被采用。"""
        tainted = set(seed)
        findings, returns_taint = [], False
        assign_re = re.compile(r"^\s*(\w+)\s*(?::=|=)\s*(.+?)\s*$")
        for lineno, line in func.body:
            code = line.split("//", 1)[0]
            if not code.strip():
                continue
            m = assign_re.match(code)
            if m and m.group(1) != "_":
                var, rhs = m.group(1), m.group(2)
                if self.expr_taint(rhs, tainted, pkg, imports):
                    tainted.add(var)
                else:
                    tainted.discard(var)
            for rx, rule in SINKS:
                sm = rx.search(code)
                if not sm:
                    continue
                depth, k = 1, sm.end()
                while k < len(code) and depth:
                    if code[k] == "(":
                        depth += 1
                    elif code[k] == ")":
                        depth -= 1
                    k += 1
                if self.args_taint(code[sm.end():k - 1], tainted, pkg, imports):
                    findings.append((lineno, rule))
            stripped = code.strip()
            if stripped.startswith("return") and \
                    self.expr_taint(stripped[6:], tainted, pkg, imports):
                returns_taint = True
        return findings, returns_taint


def compute_summaries(target_parsed, base_summaries):
    """在 base_summaries（干净包的既有 summary）语境下，重算 target 包的 summary。
    返回完整 summary 表。不动点迭代，语料浅，4 轮足够收敛。"""
    summaries = {p: dict(s) for p, s in base_summaries.items()}
    for p in target_parsed:
        summaries.setdefault(p, {})
    engine = Engine(summaries)
    for _ in range(4):
        changed = False
        for ppath, (imports, funcs) in target_parsed.items():
            for f in funcs:
                if f.recv or f.is_entry:
                    continue
                _, returns_taint = engine.run_body(f, ppath, imports,
                                                   set(f.param_names))
                sanitizes = f.name in KNOWN_SANITIZER_NAMES
                if not sanitizes:
                    for _, line in f.body:
                        code = line.split("//", 1)[0].strip()
                        if code.startswith("return") and engine._is_sanitizing_expr(
                                code[6:], ppath, imports):
                            sanitizes, returns_taint = True, False
                            break
                new = Summary(propagates=returns_taint and not sanitizes,
                              sanitizes=sanitizes)
                old = summaries[ppath].get(f.name)
                if old is None or (old.propagates, old.sanitizes) != \
                        (new.propagates, new.sanitizes):
                    summaries[ppath][f.name] = new
                    changed = True
        if not changed:
            break
    return summaries


def analyze_package(ppath, files, summaries):
    """对单个包求 findings。只依赖本包文件 + 全局 summary 表（一致性不变式）。"""
    engine = Engine(summaries)
    findings = []
    for path, text in files.items():
        gf = GoFile(path, text)
        for f in gf.funcs:
            if not f.is_entry:
                continue
            hits, _ = engine.run_body(f, ppath, gf.imports, set())
            for lineno, rule in hits:
                findings.append({"file": gf.path, "line": lineno, "ruleId": rule})
    return findings


# ---------------------------------------------------------------- 包解析辅助

class PkgInfo:
    def __init__(self, ppath, files):
        self.ppath = ppath
        self.files = files
        self.gfiles = [GoFile(p, t) for p, t in files.items()]
        self.imports = {}
        for gf in self.gfiles:
            self.imports.update(gf.imports)
        self.funcs = [f for gf in self.gfiles for f in gf.funcs]
        self.interfaces = {}
        self.methods = {}
        for gf in self.gfiles:
            self.interfaces.update(gf.interfaces)
            for f in gf.funcs:
                if f.recv:
                    self.methods.setdefault(f.recv, set()).add(f.name)
        self.methods = {k: sorted(v) for k, v in self.methods.items()}
        # 对外部符号的引用：{import_path: [symbol...]}
        deps = {}
        for gf in self.gfiles:
            for f in gf.funcs:
                for _, line in f.body:
                    for m in re.finditer(r"(\w+)\.(\w+)\(", line):
                        ipath = gf.imports.get(m.group(1))
                        if ipath and "/" in ipath:
                            deps.setdefault(ipath, set()).add(m.group(2))
        self.deps = {k: sorted(v) for k, v in deps.items()}


# ---------------------------------------------------------------- 缓存

def load_cache(root):
    path = os.path.join(root, ".scancache", "cache.json")
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        if doc.get("version") != CACHE_VERSION:
            return None  # 分析器升级 -> 整体失效，绝不读旧格式
        return doc
    except (OSError, ValueError):
        return None


def save_cache(root, doc):
    cache_dir = os.path.join(root, ".scancache", )
    os.makedirs(cache_dir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=cache_dir, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)
    os.replace(tmp, os.path.join(cache_dir, "cache.json"))  # 原子落盘


# ---------------------------------------------------------------- 扫描入口

def _sort(findings):
    uniq = {(f["file"], f["line"], f["ruleId"]): f for f in findings}
    return sorted(uniq.values(), key=lambda f: (f["file"], f["line"], f["ruleId"]))


def scan_full(root):
    """全量：不读不写缓存。"""
    module = module_name(root)
    disk = discover_packages(root)
    infos = {pkg_path(module, d): PkgInfo(pkg_path(module, d), files)
             for d, files in disk.items()}
    summaries = compute_summaries(
        {p: (i.imports, i.funcs) for p, i in infos.items()}, {})
    findings = []
    for ppath, info in infos.items():
        findings.extend(analyze_package(ppath, info.files, summaries))
    return _sort(findings), {"mode": "full",
                             "packages": sorted(infos),
                             "rescanned": sorted(infos)}


def scan_incremental(root):
    """增量：manifest 对账 -> 影响面传播 -> 只重扫脏包。"""
    module = module_name(root)
    disk = discover_packages(root)
    cache = load_cache(root) or {"version": CACHE_VERSION, "packages": {}}
    cached = cache["packages"]

    # ---- 1. manifest 对账（防脏读第一道闸）----------------------------
    on_disk = {pkg_path(module, d): {p: sha256(t) for p, t in files.items()}
               for d, files in disk.items()}
    dirty, changed_syms = set(), {}
    for ppath, hashes in on_disk.items():
        if cached.get(ppath, {}).get("files") != hashes:
            dirty.add(ppath)  # 新增/修改/删除文件 -> 本包重扫
    for ppath in list(cached):
        if ppath not in on_disk:
            # 整包被删：缓存条目作废，其符号记为已删除，触发调用方重扫
            changed_syms[ppath] = set(cached[ppath].get("summaries", {}))
            del cached[ppath]

    # ---- 2. 解析脏包，重算 summary，算符号级变化 -----------------------
    infos = {}
    for ppath in sorted(dirty):
        rel_dir = "." if ppath == module else ppath[len(module) + 1:]
        if rel_dir in disk:
            infos[ppath] = PkgInfo(ppath, disk[rel_dir])

    base = {p: {n: Summary(s["propagates"], s["sanitizes"])
                for n, s in e.get("summaries", {}).items()}
            for p, e in cached.items()}
    summaries = compute_summaries(
        {p: (i.imports, i.funcs) for p, i in infos.items()}, base)

    changed_ifaces = {}
    for ppath, info in infos.items():
        old = cached.get(ppath, {})
        old_sums = old.get("summaries", {})
        new_sums = summaries.get(ppath, {})
        for n in set(old_sums) | set(new_sums):
            o, nn = old_sums.get(n), new_sums.get(n)
            if (o["hash"] if o else None) != (nn.hash if nn else None):
                changed_syms.setdefault(ppath, set()).add(n)
        old_if = old.get("interfaces", {})
        if old_if != info.interfaces:
            changed_ifaces[ppath] = set(old_if) | set(info.interfaces)

    # ---- 3. 影响面传播（反向依赖 + 接口实现），到不动点 -----------------
    def iface_methods(ppath):
        names = changed_ifaces.get(ppath, set())
        old_if = cached.get(ppath, {}).get("interfaces", {})
        new_if = infos.get(ppath).interfaces if ppath in infos else {}
        out = set()
        for n in names:
            out |= set(old_if.get(n, [])) | set(new_if.get(n, []))
        return out

    propagated = True
    while propagated:
        propagated = False
        for ppath in sorted(cached):
            if ppath in dirty:
                continue
            entry = cached[ppath]
            hit = any(set(syms) & changed_syms.get(ipath, set())
                      for ipath, syms in entry.get("deps", {}).items())
            if not hit:
                my_methods = {m for ms in entry.get("methods", {}).values()
                              for m in ms}
                hit = any(iface_methods(d) & my_methods for d in changed_ifaces)
            if hit:
                dirty.add(ppath)
                rel_dir = "." if ppath == module else ppath[len(module) + 1:]
                infos[ppath] = PkgInfo(ppath, disk[rel_dir])
                propagated = True
        if propagated:
            summaries = compute_summaries(
                {p: (i.imports, i.funcs) for p, i in infos.items()}, base)
            for ppath, info in infos.items():
                if ppath in changed_syms or ppath not in cached:
                    continue
                old_sums = cached[ppath].get("summaries", {})
                new_sums = summaries.get(ppath, {})
                for n in set(old_sums) | set(new_sums):
                    o, nn = old_sums.get(n), new_sums.get(n)
                    if (o["hash"] if o else None) != (nn.hash if nn else None):
                        changed_syms.setdefault(ppath, set()).add(n)

    # ---- 4. 重扫脏包；干净包直接取缓存 findings ------------------------
    findings = []
    for ppath, entry in cached.items():
        if ppath not in dirty:
            findings.extend(entry.get("findings", []))
    for ppath in sorted(dirty):
        info = infos[ppath]
        fresh = analyze_package(ppath, info.files, summaries)
        findings.extend(fresh)
        cached[ppath] = {
            "files": on_disk[ppath],
            "summaries": {n: s.to_json()
                          for n, s in summaries.get(ppath, {}).items()},
            "interfaces": info.interfaces,
            "methods": info.methods,
            "deps": info.deps,
            "findings": fresh,
        }
    cache["packages"] = cached
    save_cache(root, cache)
    return _sort(findings), {"mode": "incremental",
                             "packages": sorted(on_disk),
                             "rescanned": sorted(dirty),
                             "changed_symbols": {p: sorted(s) for p, s in
                                                 changed_syms.items()}}


# ---------------------------------------------------------------- SARIF

def to_sarif(findings, tool_name="incr-taint"):
    rules = [{"id": rid, "name": name, "shortDescription": {"text": desc}}
             for rid, (name, desc) in RULE_META.items()]
    results = [{
        "ruleId": f["ruleId"],
        "level": "error",
        "message": {"text": RULE_META[f["ruleId"]][1]},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f["file"]},
            "region": {"startLine": f["line"]}}}],
    } for f in findings]
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": tool_name,
                                          "version": str(CACHE_VERSION),
                                          "rules": rules}},
                      "results": results}]}
