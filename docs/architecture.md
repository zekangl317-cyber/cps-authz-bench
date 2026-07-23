# Architecture and benchmark design

## Goals and non-goals

The toolkit provides reproducible inputs and observable failure classifications
for authorization analyzers. Its deep public modules are generation, mutation,
oracle evaluation, subprocess adaptation, comparison, result serialization,
failure-corpus storage, and reduction.

The package does not simulate control physics, verify temporal safety
properties, sandbox arbitrary programs, discover production topology, or claim
that the benchmark oracle is a complete authorization theory. External tools
remain responsible for parsing and analysis.

## Graph schema: `cps-authz-graph/v1`

- `seed` records the generator seed.
- `services` contain stable IDs, integer versions, and zones.
- `effects` contain stable IDs, owning services, resources, operations, and
  descriptive safety classes.
- `approved_grants` is the policy baseline of `(principal, effect)` pairs.
- `grants` is the current authorization state.
- `requests` identify caller, serving service, effect, and expected service
  version.
- generated graphs include `ground_truth.findings`; mutation payloads remove
  that field before invoking an analyzer.

The v1 parser is closed: unknown or missing keys, wrong nested shapes, Boolean
integers, non-standard JSON numbers, duplicate JSON keys, duplicate record
identities, decoded string values or object keys containing lone surrogates,
malformed identifiers, and broken structural references are schema corruption.
For existing mappings, a recursive UTF-8-encodability pass examines string
values and object keys before schema shape or field access and never coerces
them to strings.
IDs use a 1--128 character ASCII token alphabet. Other labels are trimmed
Unicode scalar sequences of at most 256 characters with every C0 and C1
control code point rejected (`U+0000`--`U+001F` and
`U+007F`--`U+009F`). Unicode format characters (General Category `Cf`) are
not C0/C1 controls; they are accepted and preserved without normalization,
including zero-width and bidirectional formatting characters. Seeds are
non-Boolean signed 64-bit integers and versions are positive signed 32-bit
integers. At least one service and effect are required. Limits are 4,096
services, 16,384 effects, 65,536 entries in each grant collection, 65,536
requests, and 32 MiB for a serialized document. An optional `ground_truth`
member is accepted only in its exact generated, empty-oracle shape.

All service, owner, caller, and grant references must resolve, and every known
request effect must be served by its owning service. A missing request effect
is the one deliberate semantic exception: it remains a validly encoded
`ORPHAN_EFFECT` case rather than being collapsed into schema corruption.

Generation uses a local `random.Random(seed)` instance. It never reads global
random state. Records have zero-padded IDs and deterministic ordering. Requests
are generated only after a corresponding grant is installed, so an unmutated
graph has an empty oracle finding set.

## Reference oracle

`evaluate_oracle` parses bytes, text, or an existing mapping and returns sorted
findings:

1. Invalid UTF-8/JSON or any violation of the closed v1 schema is exactly one
   `PARSER_CORRUPTION`; ordinary authorization rules are not evaluated for that
   document.
2. A current grant absent from `approved_grants` is
   `PRIVILEGE_EXPANSION`, keyed by `principal|effect`.
3. A request for an absent effect is `ORPHAN_EFFECT`, keyed by request ID.
4. A request whose service version differs from the current service record is
   `STALE_VERSION`, keyed by request ID.
5. A structurally resolvable request whose caller lacks a current effect grant
   is `CONFUSED_DEPUTY`, keyed by request ID.

The order is not a priority order; final findings are sorted by rule and
subject. Multiple independent defects can be reported for arbitrary caller
graphs. Named mutation validation is stricter: each shipped mutation must
produce exactly its one promised rule on a clean generated graph.

## Mutation case schema: `cps-authz-case/v1`

A `BenchmarkCase` stores:

- deterministic `case_id` derived from mutation name and payload SHA-256;
- mutation name and mutation seed;
- exact analyzer input as `payload_base64`; and
- separate `ground_truth.findings`.

Base64 permits malformed parser inputs to coexist with valid case metadata. The
ground truth is outside the decoded analyzer payload, preventing accidental
oracle leakage through stdin. Mutation seeds use the same non-Boolean signed
64-bit predicate at construction, serialization, result, CLI, and
deserialization boundaries.

Mutation input has one graph-validation path. The CLI passes raw bytes to the
same parser used by the oracle, retaining the 32 MiB document bound, strict
recursive JSON checks, and closed structural validation before mutation code
can index a record. `apply_mutation` invokes the validator again so direct
mapping callers receive the same schema contract. Validation and
mutation-specific precondition failures are `ValueError` instances; the CLI
maps them to its stable input diagnostic and exit `64` before opening the
requested output.

Mutation-created request IDs are allocated against the request namespace. The
synthetic missing-effect reference used by `orphan_effect` is separately
allocated against the effect namespace. The preferred seed/count-derived ID is
retained when free; otherwise a deterministic numeric suffix is selected.
After constructing a case, `apply_mutation` rederives the payload oracle and
requires exactly one finding whose rule is the mutation's documented rule. The
CLI repeats that check immediately before serialization. Thus generation fails
instead of emitting a mislabeled case whenever an unresolved namespace or
collection-bound issue, or a surviving pre-existing finding, leaves the oracle
with a different shape.

The stale-version mutation deterministically chooses a different valid
signed-32-bit request version: one greater than the selected version, except at
the maximum where it chooses one less. It changes neither the source graph nor
the graph seed, and the case retains the supplied mutation seed.

## Subprocess adapter

`run_tool` accepts an argument sequence and always uses `shell=False`. Dedicated
threads concurrently write stdin and drain stdout/stderr. A shared byte counter
caps combined output; the main loop also enforces a monotonic timeout. Output is
accepted only when the direct process exits zero and stdout is one strict UTF-8
JSON object whose only member is a valid `findings` array. The shared boundary
decoder recursively rejects duplicate object members, NaN, infinities, and any
decoded string value or object key that cannot encode as UTF-8 for analyzer
output, case/result files, JSONL, differential inputs, failure corpora, and
graph payloads.

Every process stream is serialized as a closed `{encoding, data}` object. Valid
UTF-8 uses the `utf-8` tag; every other bounded byte sequence uses canonical
`base64`. This tagged representation is injective even when valid analyzer text
looks like a diagnostic prefix. Replacement decoding is never used.

The finding schema is closed and bounded. At most 65,536 findings are accepted.
Every record requires `rule_id` and `subject`; optional fields are a bounded
`message`, a flat bounded map of JSON-scalar `details`, and finite `[0, 1]`
`confidence`. Subject, message, detail-key, and string-detail values reject the
full C0/C1 ranges whether encoded literally or as JSON escapes. They follow the
same format-character policy as graph labels. Unknown fields and nested detail
containers are rejected.

The timeout is a finite real number greater than zero and at most 300 seconds.
The combined-output limit is an integer from 1 through 16,777,216 bytes;
Booleans, non-numeric values, fractional byte counts, NaN, and infinities are
rejected before process launch.

Normalized statuses are `ok`, `timeout`, `output_limit`, `tool_error`,
`launch_error`, and `malformed_output`. The result excludes elapsed time and
timestamps. On Windows, the direct process is created with `CREATE_SUSPENDED`;
the adapter configures a kill-on-close Job Object and assigns the suspended
process before resuming its sole primary thread. Job configuration, assignment,
or resume failure kills the process without allowing an uncontained launch and
is normalized as `launch_error`. On timeout or overflow, that Job Object or the
unchanged POSIX process group terminates the ordinary descendant tree and
releases inherited pipes even if the direct launcher has already exited. This
is not kernel isolation: it supplies no CPU/memory quota or filesystem control,
and a process that deliberately detaches or breaks away where the operating
system permits may escape.

## Comparison and result records

Finding identity is `(rule_id, subject)`; messages, details, and confidence are
not part of scoring. `compare_findings` returns exact-match state, sorted true
positives, false positives, false negatives, counts, precision, recall, and F1.
`differential_compare` returns the union, all-tool consensus, and sorted
pairwise disagreements.

`cps-authz-result/v2` JSONL records combine case identity, tool identity,
execution data, oracle findings, and comparison. Rendering uses compact sorted
JSON and one final newline per record. Parsing uses LF as the only record
delimiter. A CR before LF is accepted as JSON whitespace, but bare CR is not a
delimiter; literal U+2028/U+2029 therefore remain inside JSON strings. The
schema deliberately omits host paths, current time, random run IDs, and
duration.

Result validation treats every stored score as untrusted. Case, tool, execution,
finding, count, and comparison records are closed and bounded; execution status,
exit code, findings, and error fields must agree. For an `ok` execution, the
validator strictly reparses stored stdout and requires the resulting normalized
findings to equal the stored findings. It then recomputes the entire comparison
from normalized oracle and analyzer findings and requires a
byte-equivalent canonical JSON value, so a stored `exact_match`, count, metric,
or finding summary cannot override the evidence.

## Failure corpus

`FailureCorpus` accepts only non-exact or failed executions. It validates a
path-safe case ID and writes deterministic `<id>.case.json` and
`<id>.result.json` files. Repeating an identical run replaces the pair with the
same bytes. Corpus directories are user-selected and no global cache is used.
Both add and load revalidate the closed case envelope, rederive its payload
oracle, bind result ID/mutation/seed/oracle to that exact case, and recompute the
comparison before deciding whether the record is a failure.

## Delta debugging

`ddmin` applies deterministic complement deletion to an ordered sequence and
requires the initial predicate to hold. `reduce_graph` applies `ddmin` in this
order: requests, current grants, approved grants, effects, services. Each trial
is a deep copy, and the predicate is rechecked at the public boundary.

The result is relative to field order and deletion-only transformations. It can
retain records that a semantic rewrite could remove and can expose additional
oracle findings while preserving the requested predicate. Callers needing a
different notion of minimality should supply their own item sequence and
predicate to `ddmin`.

## Determinism checklist

- explicit generator and mutation seeds;
- local pseudo-random generators only;
- sorted record identities and findings;
- canonical JSON payloads and result lines;
- no wall-clock, duration, host, or environment fields;
- no network or shared mutable cache; and
- reduction order fixed by the API default.

External analyzers can still be nondeterministic. Repeated-run analysis belongs
in the caller or a future schema extension that records repetitions explicitly.
