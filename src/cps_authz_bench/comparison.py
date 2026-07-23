"""Deterministic oracle and cross-tool comparison."""

from __future__ import annotations

from itertools import combinations
from typing import Any, Iterable, Mapping


FindingKey = tuple[str, str]


def _keys(findings: Iterable[Mapping[str, Any]]) -> set[FindingKey]:
    result: set[FindingKey] = set()
    for index, finding in enumerate(findings):
        rule_id = finding.get("rule_id")
        subject = finding.get("subject")
        if not isinstance(rule_id, str) or not isinstance(subject, str):
            raise ValueError(f"finding {index} needs string rule_id and subject")
        result.add((rule_id, subject))
    return result


def _records(keys: Iterable[FindingKey]) -> list[dict[str, str]]:
    return [
        {"rule_id": rule_id, "subject": subject}
        for rule_id, subject in sorted(keys)
    ]


def compare_findings(
    expected: Iterable[Mapping[str, Any]], observed: Iterable[Mapping[str, Any]]
) -> dict[str, Any]:
    """Compare tool findings to oracle findings by ``(rule_id, subject)``."""

    expected_keys = _keys(expected)
    observed_keys = _keys(observed)
    true_positive = expected_keys & observed_keys
    false_positive = observed_keys - expected_keys
    false_negative = expected_keys - observed_keys
    precision = (
        len(true_positive) / len(observed_keys)
        if observed_keys
        else (1.0 if not expected_keys else 0.0)
    )
    recall = (
        len(true_positive) / len(expected_keys)
        if expected_keys
        else 1.0
    )
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "exact_match": expected_keys == observed_keys,
        "true_positives": _records(true_positive),
        "false_positives": _records(false_positive),
        "false_negatives": _records(false_negative),
        "counts": {
            "true_positive": len(true_positive),
            "false_positive": len(false_positive),
            "false_negative": len(false_negative),
        },
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
    }


def differential_compare(
    tool_findings: Mapping[str, Iterable[Mapping[str, Any]]]
) -> dict[str, Any]:
    """Describe consensus and pairwise disagreements across named tools."""

    normalized = {name: _keys(findings) for name, findings in sorted(tool_findings.items())}
    sets = list(normalized.values())
    union = set().union(*sets) if sets else set()
    consensus = set.intersection(*sets) if sets else set()
    disagreements = []
    for left_name, right_name in combinations(sorted(normalized), 2):
        left = normalized[left_name]
        right = normalized[right_name]
        if left == right:
            continue
        disagreements.append(
            {
                "tools": [left_name, right_name],
                "only_left": _records(left - right),
                "only_right": _records(right - left),
            }
        )
    return {
        "tools": sorted(normalized),
        "consensus": _records(consensus),
        "union": _records(union),
        "pairwise_disagreements": disagreements,
    }

