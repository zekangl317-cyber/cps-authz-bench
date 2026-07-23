"""Versioned JSONL benchmark result schema."""

from __future__ import annotations

import json
import re
from typing import Any, Iterable, Mapping

from .adapter import MAX_OUTPUT_BYTES, OutputCapture, ToolExecution
from .comparison import compare_findings
from .json_boundary import (
    _contains_c0_or_c1_control,
    normalize_findings,
    parse_analyzer_output,
    strict_json_loads,
)
from .model import BenchmarkCase
from .seeds import require_seed


RESULT_SCHEMA_VERSION = "cps-authz-result/v2"
MAX_RESULT_LINE_BYTES = 2 * MAX_OUTPUT_BYTES + 4 * 1024 * 1024
MAX_TOOL_NAME_CHARACTERS = 256
MAX_ERROR_CHARACTERS = 4_096
MAX_STORED_OUTPUT_BYTES = MAX_OUTPUT_BYTES
_RESULT_FIELDS = frozenset(
    {"schema_version", "case", "tool", "execution", "oracle_findings", "comparison"}
)
_CASE_FIELDS = frozenset({"id", "mutation", "seed"})
_TOOL_FIELDS = frozenset({"name"})
_EXECUTION_FIELDS = frozenset(
    {"status", "exit_code", "findings", "stdout", "stderr", "error"}
)
_EXECUTION_STATUSES = frozenset(
    {"ok", "timeout", "output_limit", "tool_error", "launch_error", "malformed_output"}
)
_CAPTURE_FIELDS = frozenset({"encoding", "data"})
_MUTATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)
_CASE_ID_SUFFIX = re.compile(r"[0-9a-f]{16}\Z", re.ASCII)


def _bounded_text(value: Any, *, label: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    if _contains_c0_or_c1_control(value):
        raise ValueError(f"{label} must not contain control characters")
    if not value or value != value.strip() or len(value) > limit:
        raise ValueError(f"{label} must be a non-empty trimmed string of at most {limit} characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} must contain valid Unicode scalar values") from error
    return value


def _canonical_json(value: Any, *, label: str) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (OverflowError, TypeError, ValueError) as error:
        raise ValueError(f"{label} is not canonical JSON: {error}") from error


def _same_json(actual: Any, expected: Any, *, label: str) -> None:
    if _canonical_json(actual, label=label) != _canonical_json(expected, label=label):
        raise ValueError(f"{label} does not match recomputed evidence")


def _validated_case_identity(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or frozenset(value) != _CASE_FIELDS:
        raise ValueError("result.case must use the closed id/mutation/seed shape")
    mutation = value["mutation"]
    if not isinstance(mutation, str) or _MUTATION.fullmatch(mutation) is None:
        raise ValueError("result.case.mutation must be a bounded identifier")
    case_id = value["id"]
    prefix = mutation + "-"
    if (
        not isinstance(case_id, str)
        or not case_id.startswith(prefix)
        or _CASE_ID_SUFFIX.fullmatch(case_id[len(prefix) :]) is None
    ):
        raise ValueError("result.case.id must bind mutation to a 16-digit lowercase digest")
    seed = require_seed(value["seed"], label="result.case.seed")
    return {"id": case_id, "mutation": mutation, "seed": seed}


def _validated_capture(value: Any, *, label: str) -> tuple[dict[str, str], bytes]:
    if not isinstance(value, Mapping) or frozenset(value) != _CAPTURE_FIELDS:
        raise ValueError(f"{label} must use the closed encoding/data shape")
    try:
        capture = OutputCapture(value["encoding"], value["data"])
        raw = capture.raw_bytes()
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} is not a canonical tagged byte capture") from error
    normalized = capture.to_dict()
    _same_json(value, normalized, label=label)
    return normalized, raw


def _validated_execution(value: Any) -> tuple[dict[str, Any], list[dict[str, Any]] | None]:
    if not isinstance(value, Mapping) or frozenset(value) != _EXECUTION_FIELDS:
        raise ValueError("result.execution must use the closed v2 shape")
    status = value["status"]
    if not isinstance(status, str) or status not in _EXECUTION_STATUSES:
        raise ValueError("result.execution.status is unsupported")
    exit_code = value["exit_code"]
    if exit_code is not None and (
        not isinstance(exit_code, int) or isinstance(exit_code, bool)
    ):
        raise ValueError("result.execution.exit_code must be an integer or null")
    stdout, stdout_bytes = _validated_capture(
        value["stdout"], label="result.execution.stdout"
    )
    stderr, stderr_bytes = _validated_capture(
        value["stderr"], label="result.execution.stderr"
    )
    output_bytes = len(stdout_bytes) + len(stderr_bytes)
    if output_bytes > MAX_STORED_OUTPUT_BYTES:
        raise ValueError(
            "result.execution encoded output exceeds "
            f"{MAX_STORED_OUTPUT_BYTES} bytes"
        )
    error = value["error"]
    if error is not None:
        _bounded_text(error, label="result.execution.error", limit=MAX_ERROR_CHARACTERS)

    findings: list[dict[str, Any]] | None
    if value["findings"] is None:
        findings = None
    else:
        findings = [dict(item) for item in normalize_findings(value["findings"])]
        _same_json(value["findings"], findings, label="result.execution.findings")

    if status == "ok":
        if exit_code != 0 or findings is None or error is not None:
            raise ValueError("ok execution requires exit_code 0, findings, and null error")
        try:
            parsed_findings = [
                dict(item) for item in parse_analyzer_output(stdout_bytes)
            ]
        except ValueError as parse_error:
            raise ValueError(
                "ok execution stdout must be the strict analyzer finding document"
            ) from parse_error
        _same_json(
            findings,
            parsed_findings,
            label="result.execution findings derived from stdout",
        )
        findings = parsed_findings
    else:
        if findings is not None or not isinstance(error, str):
            raise ValueError("failed execution requires null findings and a non-empty error")
        if status in {"timeout", "launch_error"} and exit_code is not None:
            raise ValueError(f"{status} execution requires a null exit_code")
        if status == "malformed_output" and exit_code != 0:
            raise ValueError("malformed_output execution requires exit_code 0")
        if status == "malformed_output":
            try:
                parse_analyzer_output(stdout_bytes)
            except ValueError:
                pass
            else:
                raise ValueError(
                    "malformed_output stdout must fail strict analyzer parsing"
                )
        if status == "tool_error" and (exit_code is None or exit_code == 0):
            raise ValueError("tool_error execution requires a nonzero exit_code")
    normalized = {
        "status": status,
        "exit_code": exit_code,
        "findings": findings,
        "stdout": stdout,
        "stderr": stderr,
        "error": error,
    }
    return normalized, findings


def build_result(
    case: BenchmarkCase, tool_name: str, execution: ToolExecution
) -> dict[str, Any]:
    """Build one deterministic result record without wall-clock fields."""

    tool_name = _bounded_text(
        tool_name, label="tool_name", limit=MAX_TOOL_NAME_CHARACTERS
    )
    oracle_findings = [dict(item) for item in case._verified_oracle_findings()]
    execution_value = execution.to_dict()
    if execution_value["findings"] is not None:
        execution_value["findings"] = [
            dict(item) for item in normalize_findings(execution_value["findings"])
        ]
    comparison = (
        None
        if execution_value["findings"] is None
        else compare_findings(oracle_findings, execution_value["findings"])
    )
    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "case": {"id": case.case_id, "mutation": case.mutation, "seed": case.seed},
        "tool": {"name": tool_name},
        "execution": execution_value,
        "oracle_findings": oracle_findings,
        "comparison": comparison,
    }
    validate_result(result)
    return result


def validate_result(value: Mapping[str, Any]) -> None:
    """Validate and rederive every evidence-bearing field in a v2 result."""

    if frozenset(value) != _RESULT_FIELDS:
        raise ValueError("result must use the closed cps-authz-result/v2 shape")
    if value.get("schema_version") != RESULT_SCHEMA_VERSION:
        raise ValueError(f"result schema_version must be {RESULT_SCHEMA_VERSION!r}")
    _validated_case_identity(value.get("case"))
    tool = value.get("tool")
    if not isinstance(tool, Mapping) or frozenset(tool) != _TOOL_FIELDS:
        raise ValueError("result.tool must use the closed name shape")
    _bounded_text(
        tool["name"], label="result.tool.name", limit=MAX_TOOL_NAME_CHARACTERS
    )
    _, execution_findings = _validated_execution(value.get("execution"))
    oracle_value = value.get("oracle_findings")
    if not isinstance(oracle_value, list):
        raise ValueError("result.oracle_findings must be an array")
    oracle_findings = [dict(item) for item in normalize_findings(oracle_value)]
    _same_json(oracle_value, oracle_findings, label="result.oracle_findings")
    expected_comparison = (
        None
        if execution_findings is None
        else compare_findings(oracle_findings, execution_findings)
    )
    _same_json(value.get("comparison"), expected_comparison, label="result.comparison")


def validate_result_for_case(value: Mapping[str, Any], case: BenchmarkCase) -> None:
    """Bind a standalone result to the exact paired benchmark case."""

    validate_result(value)
    expected_case = {"id": case.case_id, "mutation": case.mutation, "seed": case.seed}
    _same_json(value["case"], expected_case, label="result.case")
    expected_oracle = [dict(item) for item in case._verified_oracle_findings()]
    _same_json(value["oracle_findings"], expected_oracle, label="result.oracle_findings")


def render_jsonl(results: Iterable[Mapping[str, Any]]) -> str:
    """Render validated records as canonical one-object-per-line JSON."""

    lines = []
    for result in results:
        validate_result(result)
        lines.append(_canonical_json(result, label="result"))
    return "" if not lines else "\n".join(lines) + "\n"


def parse_jsonl(value: str) -> list[dict[str, Any]]:
    """Parse JSONL using LF alone as the record delimiter, then validate it."""

    records = []
    for line_number, line in enumerate(value.split("\n"), start=1):
        if not line.strip():
            continue
        try:
            if len(line.encode("utf-8")) > MAX_RESULT_LINE_BYTES:
                raise ValueError(f"result line exceeds {MAX_RESULT_LINE_BYTES} bytes")
            record = strict_json_loads(line)
        except (UnicodeEncodeError, ValueError) as error:
            raise ValueError(f"invalid JSONL at line {line_number}: {error}") from error
        if not isinstance(record, dict):
            raise ValueError(f"JSONL line {line_number} must be an object")
        validate_result(record)
        records.append(record)
    return records
