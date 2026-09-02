"""Content-minimizing CLI for text and structured model output."""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .guard import Guard
from .policy import GuardPolicy, PolicyPack


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ko-output-guard")
    parser.add_argument("mode", choices=("check", "structured"))
    parser.add_argument("input", nargs="?", default="-", help="file, literal text, or -")
    parser.add_argument("--context", type=Path, help="system prompt/context file")
    parser.add_argument("--policy", type=Path, help="GuardPolicy JSON file")
    parser.add_argument(
        "--pack",
        choices=tuple(pack.value for pack in PolicyPack),
        default="default",
    )
    parser.add_argument("--include-text", action="store_true", help="include guarded content")
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--version", action="version", version=f"ko-output-guard {__version__}")
    return parser


def _read(value: str) -> str:
    if value == "-":
        return sys.stdin.read()
    path = Path(value)
    return path.read_text("utf-8") if path.is_file() else value


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.policy:
            policy = GuardPolicy.model_validate_json(args.policy.read_text("utf-8"))
        else:
            policy = GuardPolicy.for_pack(args.pack)
        context = args.context.read_text("utf-8") if args.context else None
        source = _read(args.input)
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    guard = Guard(policy)

    try:
        if args.mode == "structured":
            structured_result = guard.check_structured(json.loads(source), context)
            payload = structured_result.to_safe_telemetry().model_dump(mode="json")
            if args.include_text:
                payload["safe_value"] = structured_result.safe_value
                payload["finding_paths"] = [
                    finding.path for finding in structured_result.findings
                ]
            forward_safe = structured_result.forward_safe
        else:
            text_result = guard.check(source, context)
            payload = text_result.to_safe_telemetry().model_dump(mode="json")
            if args.include_text:
                payload["safe_text"] = text_result.safe_text
            forward_safe = text_result.forward_safe
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        parser.error(str(exc))

    print(json.dumps(payload, ensure_ascii=False, indent=2 if args.pretty else None))
    return 0 if forward_safe else 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
