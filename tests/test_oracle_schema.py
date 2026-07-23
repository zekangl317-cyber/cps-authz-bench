from __future__ import annotations

import json
import sys
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class ClosedOracleSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        from cps_authz_bench import generate_graph

        self.graph = generate_graph(
            seed=211, service_count=3, effect_count=4, request_count=5
        )

    def assertParserCorruption(self, value: Any) -> None:  # noqa: N802
        from cps_authz_bench import evaluate_oracle

        findings = evaluate_oracle(value)
        self.assertEqual(1, len(findings), findings)
        self.assertEqual("PARSER_CORRUPTION", findings[0]["rule_id"])

    def test_top_level_shape_is_required_and_closed(self) -> None:
        required = {
            "schema_version",
            "seed",
            "services",
            "effects",
            "approved_grants",
            "grants",
            "requests",
        }
        for field in sorted(required):
            with self.subTest(case="missing", field=field):
                malformed = deepcopy(self.graph)
                malformed.pop(field)
                self.assertParserCorruption(malformed)

        malformed = deepcopy(self.graph)
        malformed["unexpected"] = "not part of v1"
        self.assertParserCorruption(malformed)

    def test_nested_records_are_closed_and_strongly_typed(self) -> None:
        malformed_graphs: list[tuple[str, dict[str, Any]]] = []

        for value in (True, 1.5, "211", None):
            graph = deepcopy(self.graph)
            graph["seed"] = value
            malformed_graphs.append((f"seed={value!r}", graph))

        for field in ("services", "effects", "approved_grants", "grants", "requests"):
            graph = deepcopy(self.graph)
            graph[field] = tuple(graph[field])
            malformed_graphs.append((f"{field}-not-array", graph))

        record_cases = (
            ("services", "zone", "missing"),
            ("services", "extra", "extra"),
            ("services", "version", True),
            ("effects", "resource", "missing"),
            ("effects", "extra", "extra"),
            ("effects", "operation", 7),
            ("approved_grants", "principal", "missing"),
            ("approved_grants", "extra", "extra"),
            ("grants", "effect", None),
            ("requests", "caller", "missing"),
            ("requests", "extra", "extra"),
            ("requests", "service_version", 2.0),
        )
        for collection, field, value in record_cases:
            graph = deepcopy(self.graph)
            record = graph[collection][0]
            if value == "missing":
                record.pop(field)
            else:
                record[field] = value
            malformed_graphs.append((f"{collection}.{field}={value!r}", graph))

        for label, ground_truth in (
            ("missing-schema", {"findings": []}),
            (
                "extra-field",
                {
                    "schema_version": "cps-authz-oracle/v1",
                    "findings": [],
                    "extra": True,
                },
            ),
            (
                "wrong-findings-type",
                {"schema_version": "cps-authz-oracle/v1", "findings": ()},
            ),
            (
                "nonempty-generated-ground-truth",
                {
                    "schema_version": "cps-authz-oracle/v1",
                    "findings": [{"rule_id": "FORGED"}],
                },
            ),
        ):
            graph = deepcopy(self.graph)
            graph["ground_truth"] = ground_truth
            malformed_graphs.append((f"ground_truth-{label}", graph))

        for label, malformed in malformed_graphs:
            with self.subTest(label=label):
                self.assertParserCorruption(malformed)

    def test_identifiers_references_and_duplicates_are_validated(self) -> None:
        malformed_graphs: list[tuple[str, dict[str, Any]]] = []

        for field, collection in (
            ("id", "services"),
            ("id", "effects"),
            ("id", "requests"),
        ):
            for value in ("", " leading-space", "contains/slash", "x" * 129):
                graph = deepcopy(self.graph)
                graph[collection][0][field] = value
                malformed_graphs.append((f"{collection}-invalid-id-{value!r}", graph))

        for collection in ("services", "effects", "requests"):
            graph = deepcopy(self.graph)
            graph[collection].append(deepcopy(graph[collection][0]))
            malformed_graphs.append((f"duplicate-{collection}-id", graph))

        for collection in ("approved_grants", "grants"):
            graph = deepcopy(self.graph)
            graph[collection].append(deepcopy(graph[collection][0]))
            malformed_graphs.append((f"duplicate-{collection}-record", graph))

        reference_mutations = (
            ("effect-owner", "effects", "owner", "service-missing"),
            ("approved-principal", "approved_grants", "principal", "service-missing"),
            ("approved-effect", "approved_grants", "effect", "effect-missing"),
            ("grant-principal", "grants", "principal", "service-missing"),
            ("grant-effect", "grants", "effect", "effect-missing"),
            ("request-caller", "requests", "caller", "service-missing"),
            ("request-service", "requests", "service", "service-missing"),
        )
        for label, collection, field, value in reference_mutations:
            graph = deepcopy(self.graph)
            graph[collection][0][field] = value
            malformed_graphs.append((label, graph))

        graph = deepcopy(self.graph)
        request = graph["requests"][0]
        owner = next(
            effect["owner"] for effect in graph["effects"] if effect["id"] == request["effect"]
        )
        request["service"] = next(
            service["id"] for service in graph["services"] if service["id"] != owner
        )
        malformed_graphs.append(("known-effect-served-by-non-owner", graph))

        for label, malformed in malformed_graphs:
            with self.subTest(label=label):
                self.assertParserCorruption(malformed)

    def test_intentional_domain_defects_remain_semantic_findings(self) -> None:
        from cps_authz_bench import apply_mutation, evaluate_oracle

        expected = {
            "privilege_expansion": "PRIVILEGE_EXPANSION",
            "confused_deputy": "CONFUSED_DEPUTY",
            "stale_version": "STALE_VERSION",
            "orphan_effect": "ORPHAN_EFFECT",
        }
        for index, (mutation, rule_id) in enumerate(expected.items()):
            with self.subTest(mutation=mutation):
                case = apply_mutation(self.graph, mutation, seed=223 + index)
                findings = evaluate_oracle(case.payload)
                self.assertEqual([rule_id], [item["rule_id"] for item in findings])

    def test_scalar_text_document_and_collection_bounds_are_enforced(self) -> None:
        malformed_graphs: list[tuple[str, dict[str, Any]]] = []

        for field in ("services", "effects"):
            graph = deepcopy(self.graph)
            graph[field] = []
            malformed_graphs.append((f"empty-{field}", graph))

        for value in (-(2**63) - 1, 2**63):
            graph = deepcopy(self.graph)
            graph["seed"] = value
            malformed_graphs.append((f"seed-out-of-range-{value}", graph))

        for collection, field in (
            ("services", "version"),
            ("requests", "service_version"),
        ):
            for value in (0, 2**31):
                graph = deepcopy(self.graph)
                graph[collection][0][field] = value
                malformed_graphs.append((f"{collection}.{field}={value}", graph))

        for collection, field in (
            ("services", "zone"),
            ("effects", "resource"),
            ("effects", "operation"),
            ("effects", "safety_class"),
        ):
            for value in (
                "",
                " leading",
                "trailing ",
                "c0\u0001control",
                "c1\u0085control",
                "x" * 257,
            ):
                graph = deepcopy(self.graph)
                graph[collection][0][field] = value
                malformed_graphs.append((f"{collection}.{field}={value!r}", graph))

        graph = deepcopy(self.graph)
        graph["services"] = [
            {"id": f"service-{index:03d}", "version": 1, "zone": "bounded"}
            for index in range(4097)
        ]
        malformed_graphs.append(("services-over-4096", graph))

        for label, malformed in malformed_graphs:
            with self.subTest(label=label):
                self.assertParserCorruption(malformed)

        oversized_document = b" " * (32 * 1024 * 1024 + 1)
        self.assertParserCorruption(oversized_document)

    def test_raw_json_rejects_duplicate_keys_nonfinite_numbers_and_excess_depth(self) -> None:
        compact = json.dumps(self.graph, sort_keys=True, separators=(",", ":"))
        duplicate_top_level = compact[:-1] + ',"seed":211}'
        duplicate_nested = compact.replace(
            '"id":"service-000"',
            '"id":"shadow","id":"service-000"',
            1,
        )
        nonstandard_numbers = (
            compact.replace('"seed":211', '"seed":NaN', 1),
            compact.replace('"seed":211', '"seed":Infinity', 1),
            compact.replace('"seed":211', '"seed":-Infinity', 1),
        )
        excessive_depth = "[" * 2000 + "0" + "]" * 2000

        for label, payload in (
            ("duplicate-top-level-key", duplicate_top_level),
            ("duplicate-nested-key", duplicate_nested),
            *(('nonstandard-number', payload) for payload in nonstandard_numbers),
            ("excessive-depth", excessive_depth),
            ("invalid-utf8", b"\xff\xfe"),
        ):
            with self.subTest(label=label, payload=payload[:80]):
                self.assertParserCorruption(payload)

    def test_non_object_collection_members_are_schema_corruption(self) -> None:
        for field in ("services", "effects", "approved_grants", "grants", "requests"):
            for value in (None, True, 7, "record", []):
                with self.subTest(field=field, value=value):
                    graph = deepcopy(self.graph)
                    graph[field][0] = value
                    self.assertParserCorruption(graph)


if __name__ == "__main__":
    unittest.main()
