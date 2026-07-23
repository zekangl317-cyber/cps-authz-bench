from __future__ import annotations

import sys
import unittest
import json
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class GraphGenerationTests(unittest.TestCase):
    def test_seed_is_a_non_boolean_signed_64_bit_integer(self) -> None:
        from cps_authz_bench import generate_graph

        for seed in (-(2**63), 2**63 - 1):
            with self.subTest(valid_seed=seed):
                self.assertEqual(seed, generate_graph(seed=seed)["seed"])

        for seed in (-(2**63) - 1, 2**63, False, True):
            with self.subTest(invalid_seed=seed):
                with self.assertRaisesRegex(ValueError, "signed 64-bit integer"):
                    generate_graph(seed=seed)

    def test_same_seed_produces_identical_graph_and_ground_truth(self) -> None:
        from cps_authz_bench import generate_graph

        first = generate_graph(seed=4107, service_count=6, effect_count=9, request_count=12)
        second = generate_graph(seed=4107, service_count=6, effect_count=9, request_count=12)

        self.assertEqual(first, second)
        self.assertEqual(6, len(first["services"]))
        self.assertEqual(9, len(first["effects"]))
        self.assertEqual(12, len(first["requests"]))
        self.assertEqual([], first["ground_truth"]["findings"])

    def test_readable_fixture_matches_reference_oracle(self) -> None:
        from cps_authz_bench import evaluate_oracle

        fixture_path = (
            Path(__file__).resolve().parents[1]
            / "examples"
            / "fixtures"
            / "base-graph.json"
        )
        graph = json.loads(fixture_path.read_text(encoding="utf-8"))

        self.assertEqual(graph["ground_truth"]["findings"], evaluate_oracle(graph))

    def test_generator_cannot_emit_values_outside_the_v1_oracle_bounds(self) -> None:
        from cps_authz_bench import generate_graph

        invalid_calls = (
            {"seed": True},
            {"seed": 2**63},
            {"seed": 1, "service_count": True},
            {"seed": 1, "service_count": 0},
            {"seed": 1, "service_count": 4097},
            {"seed": 1, "effect_count": True},
            {"seed": 1, "effect_count": 0},
            {"seed": 1, "effect_count": 16_385},
            {"seed": 1, "request_count": True},
            {"seed": 1, "request_count": -1},
            {"seed": 1, "request_count": 65_537},
        )
        for arguments in invalid_calls:
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValueError):
                    generate_graph(**arguments)


if __name__ == "__main__":
    unittest.main()
