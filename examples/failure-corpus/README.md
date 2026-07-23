# Failure corpus example

This directory is intentionally empty except for this explanation. Use the
README quickstart with `--corpus failure-corpus` to create deterministic case
and result pairs locally. Runtime-generated corpus entries are not committed
because they describe the analyzer and case under test.

Each stored failure consists of:

- `<case-id>.case.json`: a `cps-authz-case/v1` envelope containing exact payload
  bytes and ground truth; and
- `<case-id>.result.json`: a `cps-authz-result/v2` execution and comparison.

`FailureCorpus` rejects exact successful runs and unsafe case IDs.
