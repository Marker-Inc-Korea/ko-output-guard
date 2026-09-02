"""Shape-preserving checks for JSON responses and tool-call arguments."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .result import StructuredFinding, StructuredGuardResult, Verdict

_BLOCKED_STRUCTURE = "[BLOCKED: structured output could not be inspected safely]"


class _TraversalFailure(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _pointer(parent: str, token: object) -> str:
    escaped = str(token).replace("~", "~0").replace("/", "~1")
    return f"{parent}/{escaped}" if parent else f"/{escaped}"


def check_structured_value(
    guard: Any,
    value: object,
    *,
    context: str | None = None,
) -> StructuredGuardResult:
    """Inspect every string leaf in JSON-like data and return a guarded copy."""
    findings: list[StructuredFinding] = []
    active_containers: set[int] = set()
    nodes = 0
    strings = 0

    def walk(item: object, path: str, depth: int) -> object:
        nonlocal nodes, strings
        nodes += 1
        if nodes > guard.policy.max_structure_nodes:
            raise _TraversalFailure("structure_too_many_nodes")
        if depth > guard.policy.max_structure_depth:
            raise _TraversalFailure("structure_too_deep")

        if isinstance(item, str):
            strings += 1
            result = guard.check(item, context)
            if not result.forward_safe:
                findings.append(StructuredFinding(path=path or "/", result=result))
                return result.safe_text
            return item
        if item is None or isinstance(item, bool | int | float):
            return item
        if isinstance(item, bytes | bytearray):
            raise _TraversalFailure("structure_unsupported_type")

        identity = id(item)
        if identity in active_containers:
            raise _TraversalFailure("structure_cycle")
        if isinstance(item, Mapping):
            active_containers.add(identity)
            try:
                output: dict[str, object] = {}
                for key, child in item.items():
                    if not isinstance(key, str):
                        raise _TraversalFailure("structure_non_string_key")
                    key_path = _pointer(path, key)
                    strings += 1
                    key_result = guard.check(key, context)
                    if not key_result.forward_safe:
                        findings.append(StructuredFinding(path=key_path, result=key_result))
                        raise _TraversalFailure("structure_unsafe_key")
                    output[key] = walk(child, key_path, depth + 1)
                return output
            finally:
                active_containers.remove(identity)
        if isinstance(item, Sequence):
            active_containers.add(identity)
            try:
                return [
                    walk(child, _pointer(path, index), depth + 1)
                    for index, child in enumerate(item)
                ]
            finally:
                active_containers.remove(identity)
        raise _TraversalFailure("structure_unsupported_type")

    try:
        safe_value = walk(value, "", 0)
    except _TraversalFailure as exc:
        return StructuredGuardResult(
            verdict=Verdict.BLOCK,
            safe_value=_BLOCKED_STRUCTURE,
            findings=tuple(findings),
            scanned_strings=strings,
            degraded=any(finding.result.degraded for finding in findings),
            failure_code=exc.code,
        )

    verdict = Verdict.SAFE
    if any(finding.result.verdict is Verdict.BLOCK for finding in findings):
        verdict = Verdict.BLOCK
    elif findings:
        verdict = Verdict.FLAG
    return StructuredGuardResult(
        verdict=verdict,
        safe_value=safe_value,
        findings=tuple(findings),
        scanned_strings=strings,
        degraded=any(finding.result.degraded for finding in findings),
    )


__all__ = ["check_structured_value"]
