from __future__ import annotations

import sys
import unittest
import json
from copy import deepcopy
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class DeltaDebuggingTests(unittest.TestCase):
    def test_ddmin_removes_irrelevant_items_while_preserving_predicate(self) -> None:
        from cps_authz_bench import ddmin

        original = list(range(12))
        predicate = lambda items: 3 in items and 7 in items

        reduced = ddmin(original, predicate)

        self.assertEqual([3, 7], reduced)
        self.assertTrue(predicate(reduced))
        self.assertEqual(list(range(12)), original)

    def test_graph_reducer_preserves_requested_oracle_rule(self) -> None:
        from cps_authz_bench import (
            apply_mutation,
            evaluate_oracle,
            generate_graph,
            reduce_graph,
        )

        graph = generate_graph(seed=43, service_count=7, effect_count=12, request_count=20)
        case = apply_mutation(graph, "confused_deputy", seed=107)
        mutated = json.loads(case.payload)
        original = deepcopy(mutated)
        predicate = lambda value: any(
            item["rule_id"] == "CONFUSED_DEPUTY" for item in evaluate_oracle(value)
        )

        reduced = reduce_graph(mutated, predicate)

        self.assertTrue(predicate(reduced))
        self.assertLess(len(reduced["requests"]), len(mutated["requests"]))
        self.assertEqual(original, mutated)


if __name__ == "__main__":
    unittest.main()
