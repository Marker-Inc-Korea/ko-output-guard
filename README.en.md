# ko-output-guard

[한국어](README.md) | **English**

A deterministic Korean LLM output policy engine. It keeps data-loss
prevention, general content-safety signals, and MFDS-oriented unsafe-advice
screening in explicit policy packs.

**Status:** Development Preview. It is a high-confidence screening layer, not
a universal moderator, clinical validator, regulatory approval, or guarantee
that generated content is safe.

## Install

Until the first PyPI release is published:

```bash
python3 -m pip install \
  "ko-output-guard @ git+https://github.com/Marker-Inc-Korea/ko-output-guard.git@main"
```

Install `ko-pii` as well for full Korean PII detection. Without that optional
backend, results are explicitly marked `degraded=True` and are not forward-safe.

## Three-minute start

```python
from ko_output_guard import Guard, GuardPolicy

guard = Guard(GuardPolicy.dlp())
result = guard.check(model_output, context=system_prompt)

# Always forward this property, never the original output unconditionally.
safe_text = result.safe_text
event = result.to_safe_telemetry().model_dump(mode="json")
```

Available presets:

```python
GuardPolicy.dlp()             # credentials, PII, prompt echo, data exfiltration
GuardPolicy.content_safety()  # harmful-content signals, no DLP claim
GuardPolicy.mfds()            # DLP plus drug/food unsafe-advice screening
```

Callers can override any field explicitly, for example
`GuardPolicy.content_safety(detect_violence=False)`.

## Structured output and tool calls

```python
result = guard.check_structured({
    "name": "send_email",
    "arguments": {"body": model_output},
})

if result.forward_safe:
    tool_arguments = result.safe_value
else:
    print(result.to_safe_telemetry())  # finding indexes/depths, no source text
```

Every string value and mapping key is checked. Cycles, non-string mapping keys,
excessive depth, and excessive node counts fail closed. Safe telemetry exposes
only finding indexes and path depths; use the local result object or the CLI's
explicit `--include-text` option when raw JSON Pointer paths are required.

## Chunked responses

```python
from ko_output_guard import OutputStreamSession

stream = OutputStreamSession(guard, context=system_prompt)
stream.feed(first_chunk)
stream.feed(second_chunk)
result = stream.finalize()
safe_text = result.safe_text
```

`feed()` never returns source content. This pre-forward contract catches
credentials or identifiers split across arbitrary chunk boundaries. It does not
claim token-level low latency.

## CLI

The default JSON contains safe telemetry, not source output:

```bash
printf 'model output' | ko-output-guard check - --pack dlp
ko-output-guard structured tool-call.json --pack dlp
```

## Boundaries

- `SAFE` is forwardable only when `degraded=False`.
- `FLAG`, `BLOCK`, and degraded results fail closed in `Guard.enforce()`.
- Deterministic rules prioritize explainability and precision; euphemistic or
  novel semantic harms require a separately qualified Tier-2 layer.
- MFDS-oriented rules detect configured unsafe-advice patterns; they do not
  decide medical correctness or replace professional review.

The Korean README contains corpus-specific measurements and reproduction
details. They must not be generalized to an unqualified tenant distribution.

MIT licensed. Reproducible misses and benign false positives are welcome
through GitHub Issues.
