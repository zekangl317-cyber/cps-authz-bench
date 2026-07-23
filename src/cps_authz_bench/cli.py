"""Command-line interface for generation, mutation, execution, and reduction."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from .adapter import run_tool
from .comparison import differential_compare
from .corpus import FailureCorpus
from .generation import generate_graph
from .json_boundary import normalize_findings, strict_json_loads
from .model import BenchmarkCase
from .mutations import (
    MUTATION_NAMES,
    _require_mutation_postcondition,
    apply_mutation,
)
from .oracle import evaluate_oracle, require_graph
from .reduction import reduce_graph
from .results import build_result, render_jsonl
from .seeds import require_seed


OK_EXIT = 0
MISMATCH_EXIT = 1
TOOL_FAILURE_EXIT = 2
INPUT_ERROR_EXIT = 64


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cps-authz-bench",
        description="Deterministic benchmark tooling for cyber-physical authorization analyzers.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    generate = commands.add_parser("generate", help="generate a valid graph with ground truth")
    generate.add_argument("--seed", type=int, required=True)
    generate.add_argument("--services", type=int, default=5)
    generate.add_argument("--effects", type=int, default=8)
    generate.add_argument("--requests", type=int, default=10)
    generate.add_argument("--output", type=Path, required=True)

    mutate = commands.add_parser("mutate", help="create a named mutation case envelope")
    mutate.add_argument("--input", type=Path, required=True)
    mutate.add_argument("--mutation", choices=MUTATION_NAMES, required=True)
    mutate.add_argument("--seed", type=int, default=0)
    mutate.add_argument("--output", type=Path, required=True)

    oracle = commands.add_parser("oracle", help="evaluate the oracle for a case envelope")
    oracle.add_argument("--case", type=Path, required=True)
    oracle.add_argument("--output", type=Path)

    run = commands.add_parser("run", help="run an external analyzer against a case")
    run.add_argument("--case", type=Path, required=True)
    run.add_argument("--tool-name", required=True)
    run.add_argument("--timeout", type=float, default=2.0)
    run.add_argument("--max-output-bytes", type=int, default=1_000_000)
    run.add_argument("--result", type=Path)
    run.add_argument("--corpus", type=Path)
    run.add_argument("tool_command", nargs=argparse.REMAINDER)

    diff = commands.add_parser("diff", help="compare findings from two or more tools")
    diff.add_argument(
        "--tool",
        action="append",
        required=True,
        metavar="NAME=JSON",
        help="tool name and JSON output file containing a findings array",
    )
    diff.add_argument("--output", type=Path)

    reduce = commands.add_parser("reduce", help="reduce a structured case for one oracle rule")
    reduce.add_argument("--case", type=Path, required=True)
    reduce.add_argument("--rule-id", required=True)
    reduce.add_argument("--output", type=Path, required=True)

    corpus = commands.add_parser("corpus-list", help="list deterministic failure corpus ids")
    corpus.add_argument("--corpus", type=Path, required=True)
    corpus.add_argument("--output", type=Path)
    return parser


def _load_object(path: Path) -> dict[str, Any]:
    value = strict_json_loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    return value


def _pretty(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def _write(path: Path, value: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(value)


def _emit(value: Any, output: Path | None) -> None:
    rendered = _pretty(value)
    if output is None:
        sys.stdout.write(rendered)
    else:
        _write(output, rendered)


def _load_case(path: Path) -> BenchmarkCase:
    return BenchmarkCase.from_envelope(_load_object(path))


def _load_mutation_graph(path: Path) -> Mapping[str, Any]:
    return require_graph(path.read_bytes(), label="mutation input")


def _run_command(args: argparse.Namespace) -> int:
    if args.command == "generate":
        seed = require_seed(args.seed)
        graph = generate_graph(
            seed=seed,
            service_count=args.services,
            effect_count=args.effects,
            request_count=args.requests,
        )
        _write(args.output, _pretty(graph))
        return OK_EXIT

    if args.command == "mutate":
        seed = require_seed(args.seed, label="mutation seed")
        case = apply_mutation(
            _load_mutation_graph(args.input), args.mutation, seed=seed
        )
        _require_mutation_postcondition(case)
        _write(args.output, _pretty(case.to_envelope()))
        return OK_EXIT

    if args.command == "oracle":
        case = _load_case(args.case)
        findings = evaluate_oracle(case.payload)
        _emit(
            {"schema_version": "cps-authz-oracle/v1", "findings": findings},
            args.output,
        )
        return OK_EXIT if tuple(findings) == case.expected_findings else MISMATCH_EXIT

    if args.command == "run":
        command = list(args.tool_command)
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            raise ValueError("run requires an analyzer command after '--'")
        case = _load_case(args.case)
        execution = run_tool(
            command,
            case.payload,
            timeout_seconds=args.timeout,
            max_output_bytes=args.max_output_bytes,
        )
        result = build_result(case, args.tool_name, execution)
        rendered = render_jsonl([result])
        if args.result is None:
            sys.stdout.write(rendered)
        else:
            _write(args.result, rendered)
        exact = isinstance(result.get("comparison"), Mapping) and result["comparison"].get(
            "exact_match"
        ) is True
        if args.corpus is not None and (execution.status != "ok" or not exact):
            FailureCorpus(args.corpus).add(case, result)
        if execution.status != "ok":
            return TOOL_FAILURE_EXIT
        return OK_EXIT if exact else MISMATCH_EXIT

    if args.command == "diff":
        outputs: dict[str, list[dict[str, Any]]] = {}
        for specification in args.tool:
            if "=" not in specification:
                raise ValueError("--tool must use NAME=JSON syntax")
            name, raw_path = specification.split("=", 1)
            if not name or name in outputs:
                raise ValueError("tool names must be non-empty and unique")
            value = _load_object(Path(raw_path))
            if frozenset(value) != {"findings"}:
                raise ValueError(f"{raw_path}: output must contain only findings")
            outputs[name] = list(normalize_findings(value["findings"]))
        _emit(differential_compare(outputs), args.output)
        return OK_EXIT

    if args.command == "reduce":
        case = _load_case(args.case)
        graph = strict_json_loads(case.payload)
        if not isinstance(graph, dict):
            raise ValueError("case payload must be a structured graph for reduction")

        def predicate(candidate: dict[str, Any]) -> bool:
            return any(
                finding["rule_id"] == args.rule_id for finding in evaluate_oracle(candidate)
            )

        _write(args.output, _pretty(reduce_graph(graph, predicate)))
        return OK_EXIT

    if args.command == "corpus-list":
        _emit(
            {
                "schema_version": "cps-authz-corpus-index/v1",
                "case_ids": FailureCorpus(args.corpus).list_ids(),
            },
            args.output,
        )
        return OK_EXIT

    raise ValueError(f"unsupported command {args.command!r}")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _run_command(args)
    except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as error:
        sys.stderr.write(f"cps-authz-bench: input error: {error}\n")
        return INPUT_ERROR_EXIT


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
