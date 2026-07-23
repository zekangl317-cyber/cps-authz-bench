"""Public API for deterministic cyber-physical authorization benchmarks."""

from .adapter import ToolExecution, run_tool
from .comparison import compare_findings, differential_compare
from .corpus import FailureCorpus
from .generation import generate_graph
from .model import BenchmarkCase
from .mutations import MUTATION_NAMES, apply_mutation, validate_mutation
from .oracle import evaluate_oracle
from .reduction import ddmin, reduce_graph
from .results import (
    build_result,
    parse_jsonl,
    render_jsonl,
    validate_result,
    validate_result_for_case,
)

__all__ = [
    "BenchmarkCase",
    "FailureCorpus",
    "MUTATION_NAMES",
    "apply_mutation",
    "build_result",
    "compare_findings",
    "differential_compare",
    "ddmin",
    "evaluate_oracle",
    "generate_graph",
    "parse_jsonl",
    "render_jsonl",
    "run_tool",
    "reduce_graph",
    "ToolExecution",
    "validate_mutation",
    "validate_result",
    "validate_result_for_case",
]
