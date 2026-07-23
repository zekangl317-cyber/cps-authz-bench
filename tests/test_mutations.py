from __future__ import annotations

import json
import sys
import unittest
from copy import deepcopy
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class MutationOracleTests(unittest.TestCase):
    def test_mutation_seed_is_a_non_boolean_signed_64_bit_integer(self) -> None:
        from cps_authz_bench import BenchmarkCase, apply_mutation, generate_graph

        graph = generate_graph(seed=17)
        for seed in (-(2**63), 2**63 - 1):
            with self.subTest(valid_seed=seed):
                case = apply_mutation(graph, "stale_version", seed=seed)
                self.assertEqual(seed, case.seed)
                self.assertEqual(case, BenchmarkCase.from_envelope(case.to_envelope()))

        for seed in (-(2**63) - 1, 2**63, False, True):
            with self.subTest(invalid_seed=seed):
                with self.assertRaisesRegex(ValueError, "signed 64-bit integer"):
                    apply_mutation(graph, "stale_version", seed=seed)

    def test_privilege_expansion_mutation_has_exact_ground_truth(self) -> None:
        from cps_authz_bench import apply_mutation, evaluate_oracle, generate_graph

        graph = generate_graph(seed=19, service_count=5, effect_count=8, request_count=9)

        case = apply_mutation(graph, "privilege_expansion", seed=71)
        findings = evaluate_oracle(case.payload)

        self.assertEqual("privilege_expansion", case.mutation)
        self.assertEqual(case.expected_findings, tuple(findings))
        self.assertEqual(["PRIVILEGE_EXPANSION"], [item["rule_id"] for item in findings])

    def test_confused_deputy_mutation_creates_ungranted_request(self) -> None:
        from cps_authz_bench import apply_mutation, evaluate_oracle, generate_graph

        graph = generate_graph(seed=23, service_count=5, effect_count=8, request_count=9)

        case = apply_mutation(graph, "confused_deputy", seed=73)
        findings = evaluate_oracle(case.payload)

        self.assertEqual(case.expected_findings, tuple(findings))
        self.assertEqual(["CONFUSED_DEPUTY"], [item["rule_id"] for item in findings])

    def test_stale_version_mutation_changes_request_version_only(self) -> None:
        from cps_authz_bench import apply_mutation, evaluate_oracle, generate_graph

        graph = generate_graph(seed=29, service_count=5, effect_count=8, request_count=9)

        case = apply_mutation(graph, "stale_version", seed=79)
        findings = evaluate_oracle(case.payload)

        self.assertEqual(case.expected_findings, tuple(findings))
        self.assertEqual(["STALE_VERSION"], [item["rule_id"] for item in findings])

    def test_stale_version_has_exact_ground_truth_at_version_boundaries(self) -> None:
        from cps_authz_bench import apply_mutation, evaluate_oracle, generate_graph
        from cps_authz_bench.oracle import MAX_VERSION

        for version, stale_version in ((1, 2), (MAX_VERSION, MAX_VERSION - 1)):
            with self.subTest(version=version):
                graph = generate_graph(
                    seed=97,
                    service_count=1,
                    effect_count=1,
                    request_count=1,
                )
                graph["services"][0]["version"] = version
                graph["requests"][0]["service_version"] = version
                original = deepcopy(graph)

                case = apply_mutation(graph, "stale_version", seed=101)
                payload = json.loads(case.payload)
                expected = (
                    {
                        "rule_id": "STALE_VERSION",
                        "subject": "request-000",
                        "message": (
                            "A request targets a service version different from "
                            "the current graph."
                        ),
                        "details": {
                            "requested_version": stale_version,
                            "current_version": version,
                            "service": "service-000",
                        },
                    },
                )

                self.assertEqual(original, graph)
                self.assertEqual(101, case.seed)
                self.assertEqual(graph["seed"], payload["seed"])
                self.assertEqual(version, payload["services"][0]["version"])
                self.assertEqual(
                    stale_version,
                    payload["requests"][0]["service_version"],
                )
                self.assertEqual(expected, case.expected_findings)
                self.assertEqual(expected, tuple(evaluate_oracle(case.payload)))

    def test_orphan_effect_mutation_creates_dangling_request(self) -> None:
        from cps_authz_bench import apply_mutation, evaluate_oracle, generate_graph

        graph = generate_graph(seed=31, service_count=5, effect_count=8, request_count=9)

        case = apply_mutation(graph, "orphan_effect", seed=83)
        findings = evaluate_oracle(case.payload)

        self.assertEqual(case.expected_findings, tuple(findings))
        self.assertEqual(["ORPHAN_EFFECT"], [item["rule_id"] for item in findings])

    def test_orphan_effect_seed_zero_avoids_existing_effect_id(self) -> None:
        from cps_authz_bench import apply_mutation, generate_graph, validate_mutation

        graph = generate_graph(
            seed=1,
            service_count=1,
            effect_count=1,
            request_count=0,
        )
        colliding_effect_id = "effect-orphan-00000000"
        graph["effects"][0]["id"] = colliding_effect_id
        grant = {"principal": "service-000", "effect": colliding_effect_id}
        graph["approved_grants"] = [grant]
        graph["grants"] = [dict(grant)]

        case = apply_mutation(graph, "orphan_effect", seed=0)
        payload = json.loads(case.payload)
        request = payload["requests"][-1]

        self.assertNotIn(
            request["effect"],
            {effect["id"] for effect in payload["effects"]},
        )
        self.assertEqual(
            (
                {
                    "rule_id": "ORPHAN_EFFECT",
                    "subject": request["id"],
                    "message": "A request references an effect absent from the graph.",
                    "details": {"effect": request["effect"]},
                },
            ),
            case.expected_findings,
        )
        self.assertTrue(validate_mutation(case))

    def test_generated_request_ids_avoid_request_namespace_collisions(self) -> None:
        from cps_authz_bench import apply_mutation, generate_graph

        cases = (
            ("confused_deputy", "request-confused-001", "CONFUSED_DEPUTY"),
            ("orphan_effect", "request-orphan-001", "ORPHAN_EFFECT"),
        )
        for mutation, colliding_request_id, expected_rule in cases:
            with self.subTest(mutation=mutation):
                graph = generate_graph(
                    seed=11,
                    service_count=2,
                    effect_count=2,
                    request_count=1,
                )
                graph["requests"][0]["id"] = colliding_request_id

                case = apply_mutation(graph, mutation, seed=13)
                payload = json.loads(case.payload)
                request_ids = [request["id"] for request in payload["requests"]]

                self.assertEqual(len(request_ids), len(set(request_ids)))
                self.assertNotEqual(colliding_request_id, request_ids[-1])
                self.assertEqual(
                    [(expected_rule, request_ids[-1])],
                    [
                        (finding["rule_id"], finding["subject"])
                        for finding in case.expected_findings
                    ],
                )

    def test_apply_mutation_rejects_a_non_exact_oracle_postcondition(self) -> None:
        from cps_authz_bench import apply_mutation, generate_graph

        graph = generate_graph(
            seed=17,
            service_count=1,
            effect_count=1,
            request_count=0,
        )
        graph["grants"] = [
            {"principal": "service-000", "effect": "effect-000"}
        ]

        with self.assertRaisesRegex(
            ValueError,
            "orphan_effect mutation must produce exactly one ORPHAN_EFFECT finding",
        ):
            apply_mutation(graph, "orphan_effect", seed=19)

    def test_parser_corruption_mutation_is_malformed_by_construction(self) -> None:
        from cps_authz_bench import apply_mutation, evaluate_oracle, generate_graph

        graph = generate_graph(seed=37, service_count=5, effect_count=8, request_count=9)

        case = apply_mutation(graph, "parser_corruption", seed=89)
        findings = evaluate_oracle(case.payload)

        self.assertEqual(case.expected_findings, tuple(findings))
        self.assertEqual(["PARSER_CORRUPTION"], [item["rule_id"] for item in findings])

    def test_every_named_mutation_is_valid_and_leaves_source_unchanged(self) -> None:
        from cps_authz_bench import (
            MUTATION_NAMES,
            apply_mutation,
            generate_graph,
            validate_mutation,
        )

        graph = generate_graph(seed=41, service_count=6, effect_count=9, request_count=10)
        original = deepcopy(graph)

        for index, name in enumerate(MUTATION_NAMES):
            with self.subTest(mutation=name):
                case = apply_mutation(graph, name, seed=101 + index)
                self.assertTrue(validate_mutation(case))
                self.assertEqual(original, graph)

    def test_every_mutation_validates_graph_records_before_field_access(self) -> None:
        from cps_authz_bench import apply_mutation, generate_graph

        malformed_fields = {
            "privilege_expansion": ("approved_grants", "principal"),
            "confused_deputy": ("effects", "owner"),
            "stale_version": ("requests", "service_version"),
            "orphan_effect": ("services", "id"),
            "parser_corruption": ("effects", "id"),
        }
        graph = generate_graph(seed=151)
        for mutation, (collection, field) in malformed_fields.items():
            for malformed_kind in ("missing", "wrong-type"):
                with self.subTest(
                    mutation=mutation,
                    field=f"{collection}.{field}",
                    malformed_kind=malformed_kind,
                ):
                    malformed = deepcopy(graph)
                    if malformed_kind == "missing":
                        malformed[collection][0].pop(field)
                    else:
                        malformed[collection][0][field] = []

                    with self.assertRaisesRegex(
                        ValueError,
                        "mutation input must be a well-formed, schema-valid "
                        "cps-authz-graph/v1 document",
                    ):
                        apply_mutation(malformed, mutation)


if __name__ == "__main__":
    unittest.main()
