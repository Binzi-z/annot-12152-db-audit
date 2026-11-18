#!/usr/bin/env python3
"""scan.py —— CLI。用法：
  python scan.py --mode full              # 全量，不碰缓存
  python scan.py --mode incr              # 增量，读写 .scancache/
  python scan.py --mode incr --stats stats.json --out findings.sarif
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analyzer


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["full", "incr"], default="incr")
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default=None, help="SARIF 输出路径（缺省 stdout）")
    ap.add_argument("--stats", default=None, help="增量统计输出路径")
    args = ap.parse_args()

    if args.mode == "full":
        findings, stats = analyzer.scan_full(args.root)
    else:
        findings, stats = analyzer.scan_incremental(args.root)

    sarif = analyzer.to_sarif(findings)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, ensure_ascii=False, indent=1)
    else:
        sys.stdout.reconfigure(encoding="utf-8")
        json.dump(sarif, sys.stdout, ensure_ascii=False, indent=1)
    if args.stats:
        with open(args.stats, "w", encoding="utf-8") as fh:
            json.dump(stats, fh, ensure_ascii=False, indent=1)
    print(f"[scan] mode={stats['mode']} rescanned={len(stats['rescanned'])}"
          f"/{len(stats['packages'])} pkgs findings={len(findings)}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
