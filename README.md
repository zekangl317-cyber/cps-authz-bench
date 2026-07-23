# cps-authz-bench

[English](README.md) | [简体中文](README.zh-CN.md)

`cps-authz-bench` is a deterministic Python 3.11+ benchmark and testing toolkit
for cyber-physical authorization analyzers. It generates seeded service/effect
graphs with reference ground truth, injects named authorization defects, runs
arbitrary command-line analyzers through a bounded subprocess adapter, compares
findings, stores failures, and reduces structured counterexamples.

The runtime uses only the Python standard library. It needs no GPU, cloud
service, Docker, WSL, paid API, hardware target, network connection, or sibling
repository.

## What is modeled

A graph has versioned services, physical or logical effects owned by services,
approved grants, current grants, and requests. A request is authorized when its
caller has a current grant for the effect, the effect exists, and the request's
service version matches the current service record. The reference oracle reports
structural or authorization violations; it is not a model checker for arbitrary
plant dynamics or a proof of real-world safety.

Named mutations are:

| CLI name | Oracle rule | Mutation |
|---|---|---|
| `privilege_expansion` | `PRIVILEGE_EXPANSION` | add a current grant absent from approved grants |
| `confused_deputy` | `CONFUSED_DEPUTY` | add a request whose caller lacks the requested effect grant |
| `stale_version` | `STALE_VERSION` | select a different in-range target service version |
| `orphan_effect` | `ORPHAN_EFFECT` | add a request referencing an absent effect |
| `parser_corruption` | `PARSER_CORRUPTION` | deterministically truncate serialized JSON |

Each mutation case stores analyzer input as base64 plus separate oracle findings,
so the expected result is not sent to the external analyzer.
The mutations that create request IDs check the existing request namespace, and
`orphan_effect` also checks its synthetic missing-effect ID against the existing
effect namespace. If a preferred deterministic ID is occupied, generation uses
a deterministic numeric suffix. `apply_mutation` returns only when the
recomputed oracle contains exactly one finding with the rule promised in the
table; `mutate` checks that postcondition again immediately before writing.

The `cps-authz-graph/v1` reader is closed and bounded. It requires the exact v1
top-level and record fields, strongly typed integers and strings, unique safe
identifiers, unique grants, and valid service/effect references. The sole
intentional dangling reference is a request's effect, which is how
`ORPHAN_EFFECT` is represented. Malformed JSON and schema-invalid v1 documents
produce exactly one `PARSER_CORRUPTION` finding. Every decoded JSON string value
and object key must be encodable as UTF-8; escaped lone surrogates are rejected.
Already-decoded mappings receive the same recursive check before shape or field
inspection, without stringifying keys or values.
Generator, mutation, case, and result seeds share one non-Boolean signed-64-bit
integer domain. Serialized input is capped at 32 MiB; collections are capped at
4,096 services, 16,384 effects, 65,536 grants per grant set, and 65,536
requests.

`mutate` sends the raw input bytes through that same strict, closed, bounded
graph reader before any mutation-specific field access. The `apply_mutation`
API repeats graph validation for direct mapping callers. A malformed graph or
an unmet mutation precondition or postcondition is reported through the CLI's
stable `cps-authz-bench: input error:` diagnostic with exit `64`; no new output
file is written. In particular, a structurally valid input that already carries
another oracle finding is rejected when the requested mutation cannot leave the
case with exactly its one promised finding.

`stale_version` increments the selected request version unless it is already the
maximum signed-32-bit version, in which case it decrements it. Both schema
boundaries therefore remain in range and produce the exact `STALE_VERSION`
ground truth.

## Windows quickstart (no installation)

From the repository root in PowerShell:

```powershell
$env:PYTHONPATH = "src"

python -m cps_authz_bench generate `
  --seed 42 --services 6 --effects 10 --requests 16 `
  --output graph.json

python -m cps_authz_bench mutate `
  --input graph.json --mutation confused_deputy --seed 7 `
  --output case.json

python -m cps_authz_bench oracle --case case.json

python -m cps_authz_bench run `
  --case case.json --tool-name reference-oracle `
  --timeout 2 --max-output-bytes 65536 --result result.jsonl `
  -- python examples/tools/reference_analyzer.py
```

The reference analyzer is only a smoke-test adapter around this package's
oracle. Replace the command after `--` with any external analyzer that follows
the stdin/stdout contract below. An editable install is optional:

```powershell
python -m pip install --no-build-isolation -e .
cps-authz-bench --help
```

## External analyzer contract

The adapter executes an argument list directly with `shell=False`. It writes the
case payload bytes to stdin. A successful analyzer exits `0` and emits exactly
one UTF-8 JSON object on stdout:

```json
{
  "findings": [
    {"rule_id": "CONFUSED_DEPUTY", "subject": "request-confused-016"}
  ]
}
```

The analyzer document is closed: `findings` is its only top-level field. Each
finding requires bounded `rule_id` and `subject` strings and may additionally
contain only a bounded `message`, flat scalar `details`, and finite `[0, 1]`
`confidence`. Duplicate JSON members, non-standard numbers, escaped lone
surrogates in string values or object keys, unknown fields, and more than 65,536
findings are malformed output. Subject, message, detail-key, and string-detail
values reject all C0 and C1 controls (`U+0000`--`U+001F` and
`U+007F`--`U+009F`) in both literal and escaped JSON. Unicode format characters
(General Category `Cf`) are accepted and preserved without normalization.
Findings are compared as a set of `(rule_id, subject)` identities.
Timeout, nonzero exit, malformed JSON, and combined stdout/stderr overflow have
distinct statuses. `timeout_seconds` must be a finite real number in
`(0, 300]`; `max_output_bytes` must be an integer in `[1, 16,777,216]`.
Process stdout and stderr are stored in explicit `{encoding, data}` captures.
Valid UTF-8 remains text; malformed UTF-8 is canonical base64, so every bounded
raw byte stream has one injective, byte-for-byte recoverable representation.
The in-process `invalid-utf8-base64:` display is diagnostic only and is never
the serialized evidence boundary.
Timeout and overflow cleanup targets the analyzer's ordinary descendant tree
through a Windows kill-on-close Job Object or a POSIX process group, including
the case where a launcher exits while a child retains its pipes. Windows starts
the analyzer suspended, configures and assigns the Job before the first
instruction can run, and resumes only after containment succeeds. Containment
setup failure is a fail-closed `launch_error`. The adapter is a resource guard,
**not an operating-system sandbox**; independently detached or breakaway
processes may escape where the operating system permits, so do not run
untrusted executables on a sensitive host.

`run` exits `0` for an exact match, `1` for an analyzer/oracle mismatch, `2` for
a tool execution failure, and `64` for invalid benchmark input.

## Failure corpus and reduction

Capture a mismatch with the intentionally incomplete example analyzer:

```powershell
python -m cps_authz_bench run `
  --case case.json --tool-name always-empty `
  --corpus failure-corpus --result result.jsonl `
  -- python examples/tools/always_empty.py

python -m cps_authz_bench corpus-list --corpus failure-corpus
```

The corpus stores a deterministic `.case.json` envelope and `.result.json` next
to each other. Exact successful runs are rejected from the failure corpus.

For structured (non-parser-corruption) cases, reduce a target oracle finding:

```powershell
python -m cps_authz_bench reduce `
  --case case.json --rule-id CONFUSED_DEPUTY --output reduced.json
```

The library also exports generic `ddmin(items, predicate)` and
`reduce_graph(graph, predicate)` functions. Both verify the predicate before
reducing, preserve item order, avoid mutating caller data, and return a
predicate-preserving result. Delta debugging finds a 1-minimal result for the
tested deletion strategy, not a globally smallest graph.

## Differential comparison

Given analyzer-output JSON files with `findings` arrays:

```powershell
python -m cps_authz_bench diff `
  --tool analyzer-a=output-a.json `
  --tool analyzer-b=output-b.json
```

The API functions `compare_findings` and `differential_compare` expose oracle
precision/recall and pairwise cross-tool disagreements. Duplicate finding
identities are deduplicated before scoring.

## JSONL result schema

Every `run` record uses `schema_version: "cps-authz-result/v2"` and contains the
case identity, tool name, normalized execution outcome, separate oracle and tool
findings, and comparison metrics. No timestamp or measured duration is included,
so the harness does not add nondeterministic fields. The machine-readable schema
is [`docs/cps-authz-result.schema.json`](docs/cps-authz-result.schema.json).
Validation does not trust stored scores or stored finding summaries: it closes
every nested shape, checks execution-status coherence, reparses findings from
the stored analyzer stdout, and recomputes the complete comparison. A
`malformed_output` record must conversely contain stdout that fails the strict
analyzer parser. Failure-corpus add/load operations also bind
case ID, mutation, seed, oracle findings, and recomputed comparison to the paired
case envelope. JSONL parsing treats only LF (`U+000A`) as a record delimiter.
CRLF is accepted because the CR is JSON whitespace; a bare CR does not split
records. Literal line and paragraph separators (`U+2028` and `U+2029`) remain
JSON string data and round-trip through `render_jsonl` and `parse_jsonl`.

## Python API

```python
from cps_authz_bench import (
    apply_mutation,
    build_result,
    compare_findings,
    generate_graph,
    run_tool,
)

graph = generate_graph(seed=42, service_count=6, effect_count=10, request_count=16)
case = apply_mutation(graph, "stale_version", seed=7)
execution = run_tool(["python", "my_analyzer.py"], case.payload)
result = build_result(case, "my-analyzer", execution)
```

See [`docs/architecture.md`](docs/architecture.md) for the model, oracle, trust
boundary, and determinism design. The checked-in
[`examples/fixtures/base-graph.json`](examples/fixtures/base-graph.json) is a
small readable fixture; generated cases are deterministic for a seed and size.

## Tests

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
$env:PYTHONPATH = "src"
python -B -m unittest discover -s tests -v
```

Tests cover seeded reproducibility, oracle correctness, every mutation,
source-graph immutability, tool timeout, malformed and oversized output,
descendant cleanup, atomic Windows immediate-child containment, escaped and
literal C1 rejection, adversarial v1 schema inputs, per-mutation CLI rejection
of missing and wrong-typed graph fields, mutation-ID collision and exact
postcondition enforcement, LF-only JSONL framing and literal U+2028/U+2029
round trips, differential scoring, corpus round trips, CLI artifacts, and
predicate-preserving reduction.

## Project status

Version 0.1.0 is a reference benchmark format and harness. Its oracle defines
the benchmark's synthetic ground truth; it does not establish the correctness
of an authorization design outside this model and has not been certified under
an industrial control or functional-safety standard.
