"""增量引擎的骨架测试：一致性、跨包传播、脏读防护。"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import analyzer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def make_work():
    work = tempfile.mkdtemp(prefix="incr_test_")
    for item in os.listdir(ROOT):
        if item.endswith(".go") or item == "go.mod":
            shutil.copy2(os.path.join(ROOT, item), work)
    shutil.copytree(os.path.join(ROOT, "pkg"), os.path.join(work, "pkg"))
    return work


def test_full_scan_matches_labels():
    findings, _ = analyzer.scan_full(ROOT)
    got = {(f["file"], f["line"]) for f in findings}
    truth = {(v["file"], v["line"]) for v in
             json.load(open(os.path.join(ROOT, "labels.json"),
                            encoding="utf-8"))["vulns"]}
    assert got == truth  # 全量：9/9，零误报


def test_incremental_equals_full_on_noop_change():
    work = make_work()
    try:
        incr1, _ = analyzer.scan_incremental(work)  # 冷启动建缓存
        with open(os.path.join(work, "main.go"), "a", encoding="utf-8") as fh:
            fh.write("\n// noop\n")
        incr2, stats = analyzer.scan_incremental(work)
        full, _ = analyzer.scan_full(work)
        key = lambda fs: [(f["file"], f["line"], f["ruleId"]) for f in fs]
        assert key(incr1) == key(incr2) == key(full)
        assert "annot/pkg/handlers" not in stats["rescanned"]  # 只动路由
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_crosspkg_callee_change_rescans_caller():
    work = make_work()
    try:
        analyzer.scan_incremental(work)
        fu = os.path.join(work, "pkg/fileutil/fileutil.go")
        text = open(fu, encoding="utf-8").read()
        open(fu, "w", encoding="utf-8").write(
            text.replace("return filepath.Join(base, name)",
                         "return filepath.Clean(filepath.Join(base, name))"))
        incr, stats = analyzer.scan_incremental(work)
        assert "annot/pkg/handlers" in stats["rescanned"]  # 调用方被传播
        assert not any(f["file"] == "pkg/handlers/extra.go" for f in incr)
        full, _ = analyzer.scan_full(work)
        assert [(f["file"], f["line"]) for f in incr] == \
               [(f["file"], f["line"]) for f in full]
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_deleted_file_leaves_no_stale_findings():
    work = make_work()
    try:
        before, _ = analyzer.scan_incremental(work)
        assert any(f["file"] == "pkg/handlers/extra.go" for f in before)
        os.remove(os.path.join(work, "pkg/handlers/extra.go"))
        after, _ = analyzer.scan_incremental(work)
        # 文件删了，缓存里的 finding 必须一起消失
        assert not any(f["file"] == "pkg/handlers/extra.go" for f in after)
        full, _ = analyzer.scan_full(work)
        assert [(f["file"], f["line"]) for f in after] == \
               [(f["file"], f["line"]) for f in full]
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_sarif_schema_and_eval_interop():
    findings, _ = analyzer.scan_full(ROOT)
    sarif = analyzer.to_sarif(findings)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["rules"]
    # 与 eval.py 的 SARIF 解析路径互通
    out = subprocess.run([sys.executable, "scan.py", "--mode", "full"],
                         capture_output=True, text=True, check=True, cwd=ROOT,
                         encoding="utf-8")
    doc = json.loads(out.stdout)
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] and loc["region"]["startLine"] > 0
