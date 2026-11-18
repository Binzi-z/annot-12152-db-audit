#!/usr/bin/env python3
"""eval_samples.py —— 45 条变更样本：验证增量==全量、统计召回/误报。

每条样本：在仓库副本上施加一次变更 -> 跑增量（带缓存）-> 跑全量（ fresh ）
-> 断言两者逐条一致 -> 用已知的真值 delta 累计 TP/FP/FN。
覆盖：同包变更、路由层变更、被调符号变更（同包/跨包）、接口实现变更、
     文件删除（脏读防护）、整包删除、净化器增删、符号重命名。

用法：python eval_samples.py
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analyzer

ROOT = os.path.dirname(os.path.abspath(__file__))
HANDLERS = "pkg/handlers/handlers.go"
EXTRA = "pkg/handlers/extra.go"
FILEUTIL = "pkg/fileutil/fileutil.go"
MAIN = "main.go"
P_HANDLERS = "annot/pkg/handlers"
P_FILEUTIL = "annot/pkg/fileutil"
P_MAIN = "annot"


# ---------------------------------------------------------------- 文件操作

def read(work, rel):
    with open(os.path.join(work, rel), encoding="utf-8") as fh:
        return fh.read()


def write(work, rel, text):
    path = os.path.join(work, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def append(work, rel, text):
    write(work, rel, read(work, rel) + text)


def replace(work, rel, old, new, count=1):
    text = read(work, rel)
    assert old in text, f"{rel}: 找不到待替换文本: {old[:50]!r}"
    write(work, rel, text.replace(old, new, count))


def delete(work, rel):
    path = os.path.join(work, rel)
    assert os.path.exists(path), f"{rel} 不存在"
    os.remove(path)
    # 空目录一并删（模拟整包删除）
    d = os.path.dirname(path)
    if d and not os.listdir(d):
        os.rmdir(d)


def find_line(work, rel, needle, last=False):
    hits = [i for i, line in enumerate(read(work, rel).splitlines(), 1)
            if needle in line]
    assert hits, f"{rel} 中找不到 {needle!r}"
    return hits[-1] if last else hits[0]


# ---------------------------------------------------------------- 样本定义
# 每个样本: (名称, 变更函数) -> {"add": [(file,line)], "del": [...],
#                               "rescan": [pkg...], "no_rescan": [pkg...]}

def _noop(work, rel, tag):
    append(work, rel, f"\n// {tag}: 无语义变更\n")
    return {}


def _mk(name, fn):
    return {"name": name, "fn": fn}


SAMPLES = []
S = lambda name, fn: SAMPLES.append(_mk(name, fn))

# ---- A. 同包无语义变更（1-5）-------------------------------------------
S("a1-noop-handlers", lambda w: {**_noop(w, HANDLERS, "a1"),
                                 "rescan": [P_HANDLERS],
                                 "no_rescan": [P_FILEUTIL, P_MAIN]})
S("a2-noop-handlers-2", lambda w: _noop(w, HANDLERS, "a2"))
S("a3-noop-extra", lambda w: _noop(w, EXTRA, "a3"))
S("a4-noop-fileutil", lambda w: {**_noop(w, FILEUTIL, "a4"),
                                 "no_rescan": [P_HANDLERS]})
S("a5-noop-main", lambda w: {**_noop(w, MAIN, "a5"),
                             "no_rescan": [P_HANDLERS]})

# ---- B. 路由层变更（6-9）：上次事故的反面 —— 只动路由不该漏也不该多扫 ----
S("b1-route-comment", lambda w: {**_noop(w, MAIN, "b1"),
                                 "no_rescan": [P_HANDLERS]})


def _b2(w):
    replace(w, MAIN, '\thttp.ListenAndServe(":8080", nil)',
            '\thttp.HandleFunc("/safe08b", handlers.SafeHandle08)\n'
            '\thttp.ListenAndServe(":8080", nil)')
    return {"no_rescan": [P_HANDLERS]}


S("b2-route-add-safe", _b2)
S("b3-route-comment-2", lambda w: _noop(w, MAIN, "b3"))
S("b4-route-comment-3", lambda w: _noop(w, MAIN, "b4"))

# ---- C. 同包被调符号变更（10-13）---------------------------------------
def _c1(w):
    replace(w, HANDLERS,
            "func forward00(v string) string {\n\treturn v\n}",
            "func forward00(v string) string {\n\treturn onlyDigits(v)\n}")
    return {"del": [(HANDLERS, 74)]}


S("c1-forward00-sanitize", _c1)
S("c2-forward00-revert", lambda w: (
    replace(w, HANDLERS,
            "func forward00(v string) string {\n\treturn onlyDigits(v)\n}",
            "func forward00(v string) string {\n\treturn v\n}"),
    {"add": [(HANDLERS, 74)]})[1])


def _c3(w):
    replace(w, HANDLERS,
            "func forward01(v string) string {\n\treturn v\n}",
            "func forward01(v string) string {\n\treturn onlyDigits(v)\n}")
    return {"del": [(HANDLERS, 86)]}


S("c3-forward01-sanitize", _c3)
S("c4-forward01-revert", lambda w: (
    replace(w, HANDLERS,
            "func forward01(v string) string {\n\treturn onlyDigits(v)\n}",
            "func forward01(v string) string {\n\treturn v\n}"),
    {"add": [(HANDLERS, 86)]})[1])

# ---- D. 跨包被调符号变更（14-17）：复刻事故场景 --------------------------
def _d1(w):
    replace(w, FILEUTIL, "return filepath.Join(base, name)",
            "return filepath.Clean(filepath.Join(base, name))")
    # 拼路径函数开始净化 -> 调用方 handlers 必须重扫，Handle14 不再是漏洞
    return {"del": [(EXTRA, 14)], "rescan": [P_FILEUTIL, P_HANDLERS]}


S("d1-join-sanitize-crosspkg", _d1)
S("d2-join-revert-crosspkg", lambda w: (
    replace(w, FILEUTIL, "return filepath.Clean(filepath.Join(base, name))",
            "return filepath.Join(base, name)"),
    {"add": [(EXTRA, 14)], "rescan": [P_FILEUTIL, P_HANDLERS]})[1])
S("d3-join-comment-only", lambda w: {**_noop(w, FILEUTIL, "d3"),
                                     "no_rescan": [P_HANDLERS]})


def _d4(w):
    replace(w, FILEUTIL,
            "func Join(base, name string) string {\n\treturn filepath.Join(base, name)\n}",
            "func Join(base, leaf string) string {\n\treturn filepath.Join(base, leaf)\n}")
    # 只改参数名，summary 不变 -> 调用方不应重扫
    return {"no_rescan": [P_HANDLERS]}


S("d4-join-rename-param", _d4)

# ---- E. 增删 handler（18-28）--------------------------------------------
_VULN_SQL = '''
func Handle15(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	_ = queryStr("SELECT * FROM t WHERE x = '" + raw + "'")
}
'''
_VULN_CMD = '''
func Handle16(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	_ = runCmd("ping -c 1 " + raw)
}
'''
_SAFE_CMD = '''
func SafeHandle17(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	clean := onlyDigits(raw)
	_ = runCmd("ping -c 1 " + clean)
}
'''
_VULN_SSRF = '''
func Handle18(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	_ = fetch(raw)
}
'''
_SAFE_SSRF = '''
func SafeHandle19(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	u := allowlistHost(raw)
	_ = fetch(u)
}
'''
_VULN_PATH = '''
func Handle20(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	v := fileutil.Join(baseDir, raw)
	_ = readFile(v)
}
'''


def _add_handler(snippet, needle):
    def fn(w):
        append(w, EXTRA, snippet)
        return {"add": [(EXTRA, find_line(w, EXTRA, needle))]}
    return fn


S("e1-add-vuln-sql", _add_handler(_VULN_SQL, "SELECT * FROM t"))
S("e2-add-vuln-cmd", _add_handler(_VULN_CMD, 'runCmd("ping -c 1 " + raw)'))
S("e3-add-safe-cmd", lambda w: (append(w, EXTRA, _SAFE_CMD), {})[1])
S("e4-add-vuln-ssrf", _add_handler(_VULN_SSRF, "_ = fetch(raw)"))
S("e5-add-safe-ssrf", lambda w: (append(w, EXTRA, _SAFE_SSRF), {})[1])
S("e6-add-vuln-path-crosspkg",
  lambda w: (append(w, EXTRA, _VULN_PATH),
             {"add": [(EXTRA, find_line(w, EXTRA, "_ = readFile(v)",
                                        last=True))]})[1])


def _e7(w):
    # 删掉整个 extra.go：缓存里它的 findings 必须全部消失（脏读防护）
    lines = read(w, EXTRA).splitlines()
    truth_del = []
    for i, l in enumerate(lines, 1):
        if ("_ = queryStr(" in l or '_ = runCmd("ping -c 1 " + raw)' in l
                or "_ = readFile(v)" in l or "_ = fetch(raw)" in l):
            truth_del.append((EXTRA, i))
    delete(w, EXTRA)
    return {"del": truth_del, "rescan": [P_HANDLERS]}


S("e7-delete-extra-file", _e7)

_EXTRA_ORIG = '''package handlers

import (
	"net/http"

	"annot/pkg/fileutil"
)

// Handle14 影像下载接口：文件名来自查询串，跨包拼路径后直接打开（CWE-22）。
func Handle14(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	v := fileutil.Join(baseDir, raw)
	_ = readFile(v)
}
'''
S("e8-recreate-extra", lambda w: (write(w, EXTRA, _EXTRA_ORIG),
                                  {"add": [(EXTRA, 14)]})[1])
S("e9-extra-comment", lambda w: _noop(w, EXTRA, "e9"))
S("e10-handle14-sanitize-at-sink", lambda w: (
    replace(w, EXTRA, "_ = readFile(v)", "_ = readFile(onlyDigits(v))"),
    {"del": [(EXTRA, 14)]})[1])
S("e11-handle14-revert", lambda w: (
    replace(w, EXTRA, "_ = readFile(onlyDigits(v))", "_ = readFile(v)"),
    {"add": [(EXTRA, 14)]})[1])

# ---- F. 接口与实现（29-32）----------------------------------------------
S("f1-add-interface", lambda w: (
    append(w, FILEUTIL, "\ntype Cleaner interface{ Clean(string) string }\n"),
    {"no_rescan": [P_HANDLERS]})[1])


def _f2(w):
    append(w, FILEUTIL, "\ntype Pass struct{}\n\n"
                        "func (Pass) Clean(s string) string { return s }\n")
    append(w, EXTRA, "\ntype passThrough struct{}\n\n"
                     "func (passThrough) Clean(s string) string { return s }\n")
    return {}


S("f2-add-implementations", _f2)


def _f3(w):
    replace(w, FILEUTIL,
            "type Cleaner interface{ Clean(string) string }",
            "type Cleaner interface{ Clean(string) string; Name() string }")
    # 接口方法集变了 -> 声明了 Clean 方法的 handlers 包（实现方）必须重扫
    return {"rescan": [P_FILEUTIL, P_HANDLERS]}


S("f3-interface-methodset-change", _f3)
S("f4-impl-body-change", lambda w: (
    replace(w, FILEUTIL,
            "func (Pass) Clean(s string) string { return s }",
            "func (Pass) Clean(s string) string { return \"\" }"),
    {"rescan": [P_FILEUTIL], "no_rescan": [P_HANDLERS]})[1])

# ---- G. 净化器增删（33-38）----------------------------------------------
def _g1(w):
    # SafeHandle08 去掉净化 -> 变成真漏洞（只替换第一处，SafeHandle12 不动）
    replace(w, HANDLERS, "clean := strings.ReplaceAll(raw, \"'\", \"\")",
            "clean := raw", count=1)
    return {"add": [(HANDLERS, 171)]}


S("g1-safe08-unsanitize", _g1)
S("g2-safe08-revert", lambda w: (
    replace(w, HANDLERS, "clean := raw",
            "clean := strings.ReplaceAll(raw, \"'\", \"\")", count=1),
    {"del": [(HANDLERS, 171)]})[1])
S("g3-handle02-sanitize", lambda w: (
    replace(w, HANDLERS, "v := forward02(raw)",
            "v := onlyDigits(forward02(raw))"),
    {"del": [(HANDLERS, 98)]})[1])
S("g4-handle02-revert", lambda w: (
    replace(w, HANDLERS, "v := onlyDigits(forward02(raw))",
            "v := forward02(raw)"),
    {"add": [(HANDLERS, 98)]})[1])
S("g5-safe10-unsanitize", lambda w: (
    replace(w, HANDLERS, "clean := filepath.Clean(raw)", "clean := raw"),
    {"add": [(HANDLERS, 197)]})[1])
S("g6-safe10-revert", lambda w: (
    replace(w, HANDLERS, "clean := raw", "clean := filepath.Clean(raw)",
            count=1),
    {"del": [(HANDLERS, 197)]})[1])

# ---- H. 文件/整包删除（39-42）：脏读防护 ---------------------------------
_STATE = {}


def _h1(w):
    _STATE["fileutil"] = read(w, FILEUTIL)
    delete(w, FILEUTIL)
    # fileutil.Join 解析不到 -> 保守按传播处理，Handle14 的 finding 保留
    return {"del": [], "rescan": [P_HANDLERS]}


S("h1-delete-fileutil-pkg", _h1)
S("h2-restore-fileutil", lambda w: (write(w, FILEUTIL, _STATE["fileutil"]),
                                    {})[1])


def _h3(w):
    _STATE["extra"] = read(w, EXTRA)
    delete(w, EXTRA)
    return {"del": [(EXTRA, 14)], "rescan": [P_HANDLERS]}


S("h3-delete-extra-again", _h3)
S("h4-restore-extra", lambda w: (write(w, EXTRA, _STATE["extra"]),
                                 {"add": [(EXTRA, 14)]})[1])

# ---- I. 重命名与新包（43-45）---------------------------------------------
def _i1(w):
    append(w, HANDLERS, "\nfunc onlyDigitsX(v string) string {\n"
                        "\treturn onlyDigits(v)\n}\n")
    replace(w, HANDLERS, "clean := onlyDigits(raw)",
            "clean := onlyDigitsX(raw)", count=2)
    return {}


S("i1-rename-sanitizer-wrapper", _i1)

_LEGACY = '''package legacy

import (
	"net/http"
	"os"
)

// HandleLegacy 遗留下载接口：未接路由也按签名识别为入口。
func HandleLegacy(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("f")
	f, _ := os.Open("/srv/data/" + raw)
	if f != nil {
		defer f.Close()
	}
}
'''
S("i2-add-legacy-pkg", lambda w: (
    write(w, "pkg/legacy/legacy.go", _LEGACY),
    {"add": [("pkg/legacy/legacy.go", 12)]})[1])
S("i3-delete-legacy-pkg", lambda w: (
    delete(w, "pkg/legacy/legacy.go"),
    {"del": [("pkg/legacy/legacy.go", 12)]})[1])

assert len(SAMPLES) == 45, f"样本数 {len(SAMPLES)} != 45"


# ---------------------------------------------------------------- 执行

def key(findings):
    return [(f["file"], f["line"], f["ruleId"]) for f in findings]


def main():
    work = tempfile.mkdtemp(prefix="incr_eval_")
    for item in os.listdir(ROOT):
        src = os.path.join(ROOT, item)
        if item.endswith(".go") or item in ("go.mod", "labels.json"):
            shutil.copy2(src, work)
    for d in ("pkg",):
        shutil.copytree(os.path.join(ROOT, d), os.path.join(work, d))

    labels = json.load(open(os.path.join(ROOT, "labels.json"),
                            encoding="utf-8"))["vulns"]
    truth = {(v["file"], v["line"]) for v in labels}

    # 冷启动：建立缓存
    base_findings, _ = analyzer.scan_incremental(work)
    assert {(f["file"], f["line"]) for f in base_findings} == truth, \
        "冷启动结果与 labels 不一致"

    tp = fp = fn = 0
    inconsistencies, stale, rows = [], [], []
    for idx, sample in enumerate(SAMPLES, 1):
        expect = sample["fn"](work) or {}
        for f, l in expect.get("del", []):
            truth.discard((f, l))
        for f, l in expect.get("add", []):
            truth.add((f, l))

        incr, stats = analyzer.scan_incremental(work)
        full, _ = analyzer.scan_full(work)

        ok = key(incr) == key(full)
        if not ok:
            inconsistencies.append(sample["name"])
        # 脏读检查：finding 不得指向磁盘上已不存在的文件
        for f in {f["file"] for f in incr}:
            if not os.path.exists(os.path.join(work, f)):
                stale.append((sample["name"], f))
        for p in expect.get("rescan", []):
            assert p in stats["rescanned"], \
                f"{sample['name']}: {p} 应重扫但未重扫 {stats['rescanned']}"
        for p in expect.get("no_rescan", []):
            assert p not in stats["rescanned"], \
                f"{sample['name']}: {p} 不应重扫 {stats['rescanned']}"

        got = {(f["file"], f["line"]) for f in incr}
        s_tp = len(truth & got)
        s_fp = len(got - truth)
        s_fn = len(truth - got)
        tp += s_tp; fp += s_fp; fn += s_fn
        rows.append((idx, sample["name"], ok, s_tp, s_fp, s_fn,
                     len(stats["rescanned"])))

    recall = tp / (tp + fn) if tp + fn else 0.0
    prec = tp / (tp + fp) if tp + fp else 0.0
    fpr = 1 - prec

    print(f"{'#':>2} {'sample':<34} {'一致':<4} TP  FP  FN  重扫包数")
    for idx, name, ok, a, b, c, n in rows:
        print(f"{idx:>2} {name:<34} {'OK' if ok else 'DIFF':<4} "
              f"{a:>2} {b:>2} {c:>2}  {n}")
    print("-" * 64)
    print(f"样本数={len(SAMPLES)}  增量==全量: "
          f"{len(SAMPLES) - len(inconsistencies)}/{len(SAMPLES)}")
    print(f"脏读(finding 指向已删文件): {len(stale)} 起")
    print(f"TP={tp} FP={fp} FN={fn}")
    print(f"recall={recall:.1%} (要求>=85%)  "
          f"false_positive_rate={fpr:.1%} (要求<=15%)")

    # 终态应回到 labels 基线
    final, _ = analyzer.scan_incremental(work)
    assert {(f["file"], f["line"]) for f in final} == \
           {(v["file"], v["line"]) for v in labels}, "终态未回到 labels 基线"

    shutil.rmtree(work, ignore_errors=True)
    if inconsistencies:
        print("不一致样本:", inconsistencies)
        return 1
    if stale:
        print("脏读样本:", stale)
        return 1
    if recall < 0.85 or fpr > 0.15:
        print("指标不达标")
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
