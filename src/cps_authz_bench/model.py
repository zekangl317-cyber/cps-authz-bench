"""Serializable benchmark case model."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .json_boundary import normalize_findings
from .oracle import MAX_GRAPH_BYTES, evaluate_oracle
from .seeds import require_seed


_CASE_FIELDS = frozenset(
    {"schema_version", "case_id", "mutation", "seed", "payload_base64", "ground_truth"}
)
_GROUND_TRUTH_FIELDS = frozenset({"findings"})
_MUTATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)


def _canonical_case_id(mutation: str, payload: bytes) -> str:
    digest = hashlib.sha256(payload).hexdigest()[:16]
    return f"{mutation}-{digest}"


def _verified_case_findings(
    case_id: Any,
    mutation: Any,
    payload: Any,
    findings: Any,
) -> tuple[dict[str, Any], ...]:
    if not isinstance(case_id, str):
        raise ValueError("benchmark case case_id must be a string")
    if not isinstance(mutation, str) or _MUTATION.fullmatch(mutation) is None:
        raise ValueError("benchmark case mutation must be a bounded identifier")
    if not isinstance(payload, bytes):
        raise ValueError("benchmark case payload must be bytes")
    if len(payload) > MAX_GRAPH_BYTES:
        raise ValueError(f"benchmark case payload exceeds {MAX_GRAPH_BYTES} bytes")
    if not isinstance(findings, (list, tuple)):
        raise ValueError("benchmark case ground_truth.findings must be an array of objects")
    for index, finding in enumerate(findings):
        if not isinstance(finding, Mapping) or not isinstance(
            finding.get("rule_id"), str
        ) or not isinstance(finding.get("subject"), str):
            raise ValueError(
                "benchmark case ground_truth.findings"
                f"[{index}] needs string rule_id and subject"
            )
    normalized_findings = normalize_findings(list(findings))
    if case_id != _canonical_case_id(mutation, payload):
        raise ValueError("benchmark case case_id does not match mutation and payload")
    oracle_findings = tuple(evaluate_oracle(payload))
    if normalized_findings != oracle_findings:
        raise ValueError(
            "benchmark case ground_truth.findings do not match decoded payload oracle"
        )
    return oracle_findings


@dataclass(frozen=True)
class BenchmarkCase:
    """One analyzer input and its mutation-specific oracle findings."""

    case_id: str
    mutation: str
    seed: int
    payload: bytes
    expected_findings: tuple[dict[str, Any], ...]

    def __post_init__(self) -> None:
        require_seed(self.seed, label="benchmark case seed")

    def _verified_oracle_findings(self) -> tuple[dict[str, Any], ...]:
        return _verified_case_findings(
            self.case_id,
            self.mutation,
            self.payload,
            self.expected_findings,
        )

    def to_envelope(self) -> dict[str, Any]:
        seed = require_seed(self.seed, label="benchmark case seed")
        oracle_findings = self._verified_oracle_findings()
        return {
            "schema_version": "cps-authz-case/v1",
            "case_id": self.case_id,
            "mutation": self.mutation,
            "seed": seed,
            "payload_base64": base64.b64encode(self.payload).decode("ascii"),
            "ground_truth": {"findings": [dict(item) for item in oracle_findings]},
        }

    @classmethod
    def from_envelope(cls, value: Mapping[str, Any]) -> "BenchmarkCase":
        if frozenset(value) != _CASE_FIELDS:
            raise ValueError("benchmark case must use the closed cps-authz-case/v1 shape")
        if value.get("schema_version") != "cps-authz-case/v1":
            raise ValueError("unsupported benchmark case schema_version")
        seed = require_seed(
            value.get("seed"),
            label="benchmark case seed",
        )
        payload_base64 = value.get("payload_base64")
        if not isinstance(payload_base64, str):
            raise ValueError("invalid benchmark case payload_base64")
        try:
            payload = base64.b64decode(payload_base64, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("invalid benchmark case payload_base64") from error
        ground_truth = value.get("ground_truth")
        if (
            not isinstance(ground_truth, Mapping)
            or frozenset(ground_truth) != _GROUND_TRUTH_FIELDS
        ):
            raise ValueError("benchmark case ground_truth must be an object")
        findings = ground_truth.get("findings")
        if not isinstance(findings, list):
            raise ValueError(
                "benchmark case ground_truth.findings must be an array of objects"
            )
        case_id = value.get("case_id")
        mutation = value.get("mutation")
        oracle_findings = _verified_case_findings(
            case_id,
            mutation,
            payload,
            findings,
        )
        return cls(
            case_id=case_id,
            mutation=mutation,
            seed=seed,
            payload=payload,
            expected_findings=oracle_findings,
        )
