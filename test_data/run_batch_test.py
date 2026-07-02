#!/usr/bin/env python3
"""Batch test against waf_sample_10.json (mock or real LLM)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("LLM_PROVIDER", "mock")

from secops_core import analyze  # noqa: E402


def main() -> None:
    samples = json.loads((ROOT / "waf_sample_10.json").read_text(encoding="utf-8"))
    ok = miss = err = 0

    for s in samples:
        try:
            r = analyze(s["log"], "waf")
            pred = r["verdict"].verdict == "attack"
            gt = s["label"] == "malicious"
            if pred == gt:
                ok += 1
            else:
                miss += 1
            mark = "OK" if pred == gt else "MISS"
            uri = s["log"].get("uri", "")[:60]
            print(
                f"[{mark}] {s['label']:9} -> {r['verdict'].verdict}/{r['verdict'].tp_fp} | {uri}"
            )
        except Exception as e:
            err += 1
            print(f"[ERR] {s['label']} | {e}")

    n = len(samples)
    print(f"\nTotal: {n} | Match: {ok} | Miss: {miss} | Error: {err} | Acc: {ok / n:.0%}")
    print(f"LLM_PROVIDER: {os.environ.get('LLM_PROVIDER', 'mock')}")


if __name__ == "__main__":
    main()
