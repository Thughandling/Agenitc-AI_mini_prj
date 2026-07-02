#!/usr/bin/env python3
"""100개 → 10개 샘플 파이프라인 검증."""
from __future__ import annotations

import json
import os
import random
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("LLM_PROVIDER", "mock")

from secops_core import analyze, dataset_row_to_log  # noqa: E402


def run_batch(rows: list[dict], label: str) -> tuple[int, int, list[str]]:
    ok, fail = 0, 0
    errors: list[str] = []
    for i, row in enumerate(rows):
        log = dataset_row_to_log(row)
        try:
            result = analyze(log, "waf")
            assert result["verdict"].verdict in ("attack", "normal", "investigate")
            assert result["incident_report"].title
            ok += 1
        except Exception as e:
            fail += 1
            errors.append(f"[{label} #{i} label={row.get('label')}] {e}")
            if len(errors) <= 3:
                errors.append(traceback.format_exc(limit=2))
    return ok, fail, errors


def main():
    data_path = ROOT / "ai_waf_dataset_full.json"
    if not data_path.exists():
        print(f"ERROR: {data_path} not found")
        print("Run: pip install datasets && python scripts/download_dataset.py")
        sys.exit(1)

    data = json.loads(data_path.read_text(encoding="utf-8"))
    random.seed(42)

    sample100 = random.sample(data, min(100, len(data)))
    print(f"=== Phase 1: {len(sample100)} samples (mock) ===")
    ok, fail, errors = run_batch(sample100, "100")
    print(f"Result: {ok}/{len(sample100)} OK, {fail} failed")
    if fail:
        for e in errors[:5]:
            print(e)
        sys.exit(1)

    sample10 = sample100[:10]
    print(f"\n=== Phase 2: {len(sample10)} samples (mock) ===")
    ok2, fail2, errors2 = run_batch(sample10, "10")
    print(f"Result: {ok2}/{len(sample10)} OK, {fail2} failed")
    for i, row in enumerate(sample10):
        log = dataset_row_to_log(row)
        r = analyze(log, "waf")
        print(f"  [{i+1}] gt={row['label']:9} verdict={r['verdict'].verdict:10} tp_fp={r['verdict'].tp_fp}")

    if fail2:
        sys.exit(1)
    print("\n✅ All passed.")


if __name__ == "__main__":
    main()
