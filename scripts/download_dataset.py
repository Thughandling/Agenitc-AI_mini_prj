#!/usr/bin/env python3
"""Download ai-waf-dataset from Hugging Face → test_data/ai_waf_dataset_full.json"""
from __future__ import annotations

import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "test_data" / "ai_waf_dataset_full.json"


def main() -> None:
    try:
        from datasets import load_dataset
    except ImportError:
        print("Install: pip install datasets")
        sys.exit(1)

    print("Downloading notesbymuneeb/ai-waf-dataset …")
    ds = load_dataset("notesbymuneeb/ai-waf-dataset", split="train")
    rows = [{"label": row["label"], "text": row["text"]} for row in ds]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
    print(f"Saved {len(rows):,} rows → {OUT}")


if __name__ == "__main__":
    main()
