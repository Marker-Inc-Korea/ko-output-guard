"""Portable paths for optional research and training scripts."""
from __future__ import annotations

import os
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_ROOT.parent
EVAL_ROOT = Path(
    os.environ.get("KO_GUARD_EVAL_ROOT", REPO_ROOT / ".eval-data")
).expanduser()
KO_PII_EVAL_ROOT = Path(
    os.environ.get("KO_PII_EVAL_ROOT", EVAL_ROOT / "ko-pii-external")
).expanduser()
PROMPT_SRC = REPO_ROOT / "ko-prompt-guard" / "src"
OUTPUT_SRC = PACKAGE_ROOT / "src"


def eval_path(*parts: str) -> str:
    return str(EVAL_ROOT.joinpath(*parts))


def pii_path(*parts: str) -> str:
    return str(KO_PII_EVAL_ROOT.joinpath(*parts))
