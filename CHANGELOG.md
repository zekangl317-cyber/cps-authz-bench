# Changelog

All notable changes are documented here. This project follows semantic
versioning while graph, case, oracle, and result schemas are versioned
independently.

## [Unreleased]

### Fixed

- Preserve analyzer stdout and stderr injectively in `cps-authz-result/v2`
  with explicit UTF-8/base64 tagged captures, so arbitrary output bytes cannot
  collide with diagnostic display text and all scoring remains bound to the
  exact captured bytes.
- Allocate mutation-created request IDs and orphan-effect references against
  their occupied namespaces, including the `effect-orphan-00000000` seed-zero
  collision, and reject generation unless the recomputed oracle is exactly the
  requested mutation's single finding. The CLI rechecks before writing.
- Frame result JSONL only on LF so literal U+2028/U+2029 inside unescaped
  Unicode JSON strings remain record data; CRLF remains accepted while bare CR
  is not a record separator.
- Close the Windows immediate-child escape window by launching analyzers
  suspended, assigning a configured kill-on-close Job Object before resume,
  and failing closed with `launch_error` if containment cannot be established.
- Reject the full C0 and C1 control ranges in bounded graph, finding, and result
  text while explicitly preserving Unicode format characters.
- Validate raw CLI mutation input and direct `apply_mutation` mappings with the
  shared strict, closed, bounded graph validator before mutation-specific field
  access; malformed records now produce the stable input-error exit `64`
  without a traceback or output artifact.
- Reject lone surrogates in every nested string value or object key for bytes,
  text, and already-decoded graph mappings using one recursive check before
  shape or field access and without coercion.
- Keep `stale_version` mutations inside the positive signed-32-bit version
  domain at both boundaries, preserving the exact single `STALE_VERSION`
  ground truth instead of turning the maximum into parser corruption.
- Enforce one non-Boolean signed-64-bit seed domain for generation, mutation,
  case construction and serialization, CLI commands, results, and corpus
  round trips; invalid CLI seeds create no output artifact.
- Reject invalid, non-finite, Boolean, fractional, or excessive subprocess
  limits before launch and terminate ordinary descendant trees on timeout or
  output overflow.
- Validate `cps-authz-graph/v1` as a closed, bounded schema with exact nested
  shapes, safe unique IDs, duplicate rejection, and structural reference
  checks before evaluating authorization findings.
- Keep orphan-effect mutations structurally valid by encoding the missing
  effect only at the request reference that the oracle is designed to report.

## [0.1.0] - 2026-07-23

### Added

- Seeded service/effect graph generation with reference ground truth.
- Privilege-expansion, confused-deputy, stale-version, orphan-effect, and
  parser-corruption mutations.
- Deterministic oracle findings and mutation validation.
- Generic subprocess adapter with timeout and combined-output limits.
- Oracle scoring and multi-tool differential comparison.
- Versioned deterministic JSONL result records.
- On-disk failure corpus with case/result round trips.
- Generic `ddmin` and graph-aware predicate-preserving reduction.
- Standard-library CLI, readable fixtures, example analyzers, tests, and CI.
