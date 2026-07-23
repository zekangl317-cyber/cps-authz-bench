from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class DifferentialComparisonTests(unittest.TestCase):
    def test_oracle_comparison_reports_exact_false_positives_and_negatives(self) -> None:
        from cps_authz_bench import compare_findings

        oracle = [
            {"rule_id": "CONFUSED_DEPUTY", "subject": "request-1"},
            {"rule_id": "STALE_VERSION", "subject": "request-2"},
        ]
        observed = [
            {"rule_id": "CONFUSED_DEPUTY", "subject": "request-1", "confidence": 0.9},
            {"rule_id": "ORPHAN_EFFECT", "subject": "request-3"},
        ]

        comparison = compare_findings(oracle, observed)

        self.assertEqual(
            [{"rule_id": "CONFUSED_DEPUTY", "subject": "request-1"}],
            comparison["true_positives"],
        )
        self.assertEqual(
            [{"rule_id": "ORPHAN_EFFECT", "subject": "request-3"}],
            comparison["false_positives"],
        )
        self.assertEqual(
            [{"rule_id": "STALE_VERSION", "subject": "request-2"}],
            comparison["false_negatives"],
        )
        self.assertEqual(0.5, comparison["precision"])
        self.assertEqual(0.5, comparison["recall"])
        self.assertFalse(comparison["exact_match"])


if __name__ == "__main__":
    unittest.main()
