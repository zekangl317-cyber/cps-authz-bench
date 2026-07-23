"""On-disk, deterministic failure corpus storage."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping

from .json_boundary import strict_json_loads
from .model import BenchmarkCase
from .results import validate_result_for_case


_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}\Z")


def _canonical_pretty(value: Mapping[str, Any]) -> str:
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


class FailureCorpus:
    """Store failing case envelopes beside their result records."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    @staticmethod
    def _validate_id(case_id: str) -> None:
        if not _SAFE_ID.fullmatch(case_id):
            raise ValueError("case_id contains unsafe path characters")

    def add(self, case: BenchmarkCase, result: Mapping[str, Any]) -> None:
        """Add or deterministically replace a failure record."""

        self._validate_id(case.case_id)
        validate_result_for_case(result, case)
        result_case = result.get("case", {})
        if result_case.get("id") != case.case_id:
            raise ValueError("result case id does not match benchmark case")
        execution = result.get("execution", {})
        comparison = result.get("comparison")
        is_failure = execution.get("status") != "ok" or not (
            isinstance(comparison, Mapping) and comparison.get("exact_match") is True
        )
        if not is_failure:
            raise ValueError("failure corpus accepts only failed or non-exact results")
        self.root.mkdir(parents=True, exist_ok=True)
        _write(self.root / f"{case.case_id}.case.json", _canonical_pretty(case.to_envelope()))
        _write(self.root / f"{case.case_id}.result.json", _canonical_pretty(dict(result)))

    def list_ids(self) -> list[str]:
        if not self.root.exists():
            return []
        suffix = ".case.json"
        return sorted(path.name[: -len(suffix)] for path in self.root.glob(f"*{suffix}"))

    def load(self, case_id: str) -> tuple[BenchmarkCase, dict[str, Any]]:
        self._validate_id(case_id)
        case_value = strict_json_loads(
            (self.root / f"{case_id}.case.json").read_bytes()
        )
        result = strict_json_loads(
            (self.root / f"{case_id}.result.json").read_bytes()
        )
        if not isinstance(case_value, dict) or not isinstance(result, dict):
            raise ValueError("failure corpus records must contain JSON objects")
        case = BenchmarkCase.from_envelope(case_value)
        validate_result_for_case(result, case)
        return case, result
