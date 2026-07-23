from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class ResultSchemaTests(unittest.TestCase):
    def test_jsonl_result_is_deterministic_and_oracle_compared(self) -> None:
        from cps_authz_bench import (
            ToolExecution,
            apply_mutation,
            build_result,
            generate_graph,
            render_jsonl,
        )

        case = apply_mutation(generate_graph(seed=47), "privilege_expansion", seed=109)
        execution = ToolExecution(
            status="ok",
            exit_code=0,
            findings=case.expected_findings,
            stdout=json.dumps({"findings": list(case.expected_findings)}),
            stderr="",
        )

        result = build_result(case, "example-analyzer", execution)
        first = render_jsonl([result])

        self.assertEqual(first, render_jsonl([result]))
        self.assertTrue(first.endswith("\n"))
        parsed = json.loads(first)
        self.assertEqual("cps-authz-result/v2", parsed["schema_version"])
        self.assertTrue(parsed["comparison"]["exact_match"])
        self.assertEqual(case.case_id, parsed["case"]["id"])


if __name__ == "__main__":
    unittest.main()
