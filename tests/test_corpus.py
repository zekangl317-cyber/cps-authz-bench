from __future__ import annotations

import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))


class FailureCorpusTests(unittest.TestCase):
    def test_failed_case_round_trips_through_corpus(self) -> None:
        from cps_authz_bench import (
            FailureCorpus,
            ToolExecution,
            apply_mutation,
            build_result,
            generate_graph,
        )

        case = apply_mutation(generate_graph(seed=53), "stale_version", seed=113)
        execution = ToolExecution("ok", 0, tuple(), '{"findings":[]}', "")
        result = build_result(case, "misses-everything", execution)

        with tempfile.TemporaryDirectory() as directory:
            corpus = FailureCorpus(Path(directory))
            corpus.add(case, result)
            loaded_case, loaded_result = corpus.load(case.case_id)

            self.assertEqual([case.case_id], corpus.list_ids())
            self.assertEqual(case, loaded_case)
            self.assertEqual(result, loaded_result)

    def test_seed_endpoints_round_trip_through_case_result_and_corpus(self) -> None:
        from cps_authz_bench import (
            FailureCorpus,
            ToolExecution,
            apply_mutation,
            build_result,
            generate_graph,
        )

        base_case = apply_mutation(
            generate_graph(seed=59),
            "stale_version",
            seed=61,
        )
        execution = ToolExecution("ok", 0, tuple(), '{"findings":[]}', "")

        with tempfile.TemporaryDirectory() as directory:
            for index, seed in enumerate((-(2**63), 2**63 - 1)):
                with self.subTest(seed=seed):
                    case = replace(base_case, seed=seed)
                    result = build_result(case, "seed-boundary", execution)
                    corpus = FailureCorpus(Path(directory) / str(index))
                    corpus.add(case, result)
                    loaded_case, loaded_result = corpus.load(case.case_id)

                    self.assertEqual(seed, loaded_case.seed)
                    self.assertEqual(seed, loaded_result["case"]["seed"])


if __name__ == "__main__":
    unittest.main()
