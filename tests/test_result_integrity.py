from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class ResultIntegrityTests(unittest.TestCase):
    @staticmethod
    def _case_and_result():
        from cps_authz_bench import (
            ToolExecution,
            apply_mutation,
            build_result,
            generate_graph,
        )

        case = apply_mutation(generate_graph(seed=307), "stale_version", seed=311)
        result = build_result(
            case,
            "misses-everything",
            ToolExecution("ok", 0, tuple(), '{"findings":[]}', ""),
        )
        return case, result

    def test_case_construction_rejects_non_signed_64_bit_seeds(self) -> None:
        case, _ = self._case_and_result()

        for seed in (-(2**63) - 1, 2**63, False, True):
            with self.subTest(seed=seed):
                with self.assertRaisesRegex(ValueError, "signed 64-bit integer"):
                    replace(case, seed=seed)

    def test_case_and_result_deserialization_reject_invalid_seeds(self) -> None:
        from cps_authz_bench import BenchmarkCase, parse_jsonl

        case, result = self._case_and_result()
        for seed in (-(2**63) - 1, 2**63, False, True):
            with self.subTest(seed=seed):
                envelope = case.to_envelope()
                envelope["seed"] = seed
                with self.assertRaisesRegex(ValueError, "signed 64-bit integer"):
                    BenchmarkCase.from_envelope(envelope)

                forged_result = copy.deepcopy(result)
                forged_result["case"]["seed"] = seed
                with self.assertRaisesRegex(ValueError, "signed 64-bit integer"):
                    parse_jsonl(json.dumps(forged_result) + "\n")

    def test_comparison_is_recomputed_not_trusted(self) -> None:
        from cps_authz_bench import validate_result

        _, result = self._case_and_result()
        mutations = []
        forged_exact = copy.deepcopy(result)
        forged_exact["comparison"] = {"exact_match": True, "invented": "accepted"}
        mutations.append(forged_exact)
        forged_count = copy.deepcopy(result)
        forged_count["comparison"]["counts"]["false_negative"] = 0
        mutations.append(forged_count)
        forged_summary = copy.deepcopy(result)
        forged_summary["comparison"]["false_negatives"] = []
        mutations.append(forged_summary)
        for value in mutations:
            with self.subTest(comparison=value["comparison"]):
                with self.assertRaisesRegex(ValueError, "result.comparison"):
                    validate_result(value)

    def test_execution_status_and_nested_shapes_are_closed_and_coherent(self) -> None:
        from cps_authz_bench import validate_result

        _, result = self._case_and_result()
        invalid_values = []
        nonzero_ok = copy.deepcopy(result)
        nonzero_ok["execution"]["exit_code"] = 7
        invalid_values.append(nonzero_ok)
        failed_with_findings = copy.deepcopy(result)
        failed_with_findings["execution"].update(
            {"status": "tool_error", "exit_code": 2, "error": "failed"}
        )
        invalid_values.append(failed_with_findings)
        extra_execution = copy.deepcopy(result)
        extra_execution["execution"]["invented"] = True
        invalid_values.append(extra_execution)
        extra_case = copy.deepcopy(result)
        extra_case["case"]["invented"] = True
        invalid_values.append(extra_case)
        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_result(value)

    def test_result_bounded_text_rejects_c1_controls(self) -> None:
        from cps_authz_bench import validate_result

        _, result = self._case_and_result()
        c1_tool_name = copy.deepcopy(result)
        c1_tool_name["tool"]["name"] = "left\u0085right"

        c1_execution_error = copy.deepcopy(result)
        c1_execution_error["execution"] = {
            "status": "launch_error",
            "exit_code": None,
            "findings": None,
            "stdout": {"encoding": "utf-8", "data": ""},
            "stderr": {"encoding": "utf-8", "data": ""},
            "error": "left\u0085right",
        }
        c1_execution_error["comparison"] = None

        for value in (c1_tool_name, c1_execution_error):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "control characters"):
                    validate_result(value)

    def test_output_captures_are_closed_canonical_and_explicit(self) -> None:
        from cps_authz_bench import validate_result

        _, result = self._case_and_result()
        invalid_captures = (
            {"encoding": "base64", "data": "***"},
            {"encoding": "base64", "data": "YQ"},
            {"encoding": "latin-1", "data": "text"},
            {"encoding": "utf-8", "data": "text", "extra": True},
            "plain text",
        )
        for capture in invalid_captures:
            with self.subTest(capture=capture):
                forged = copy.deepcopy(result)
                forged["execution"]["stdout"] = capture
                with self.assertRaisesRegex(ValueError, "capture|encoding/data"):
                    validate_result(forged)

    def test_parse_jsonl_rejects_forged_exact_match(self) -> None:
        from cps_authz_bench import parse_jsonl

        _, result = self._case_and_result()
        result["comparison"]["exact_match"] = True
        with self.assertRaisesRegex(ValueError, "result.comparison"):
            parse_jsonl(json.dumps(result, allow_nan=False) + "\n")

    def test_case_and_ground_truth_envelopes_are_closed(self) -> None:
        from cps_authz_bench import BenchmarkCase

        case, _ = self._case_and_result()
        top_level = case.to_envelope()
        top_level["invented"] = True
        ground_truth = case.to_envelope()
        ground_truth["ground_truth"]["invented"] = True
        for value in (top_level, ground_truth):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "closed|ground_truth"):
                    BenchmarkCase.from_envelope(value)

    def test_corpus_add_binds_case_identity_oracle_and_comparison(self) -> None:
        from cps_authz_bench import FailureCorpus, compare_findings

        case, result = self._case_and_result()
        forged_values = []
        forged_identity = copy.deepcopy(result)
        forged_identity["case"]["mutation"] = "other"
        forged_identity["case"]["id"] = "other-" + case.case_id.rsplit("-", 1)[1]
        forged_values.append(forged_identity)
        forged_seed = copy.deepcopy(result)
        forged_seed["case"]["seed"] += 1
        forged_values.append(forged_seed)
        forged_oracle = copy.deepcopy(result)
        forged_oracle["oracle_findings"] = []
        forged_oracle["comparison"] = compare_findings(
            [], forged_oracle["execution"]["findings"]
        )
        forged_values.append(forged_oracle)

        with tempfile.TemporaryDirectory() as directory:
            corpus = FailureCorpus(directory)
            for value in forged_values:
                with self.subTest(value=value):
                    with self.assertRaisesRegex(ValueError, "recomputed evidence"):
                        corpus.add(case, value)

    def test_corpus_load_rejects_tampered_result_and_case_pair(self) -> None:
        from cps_authz_bench import FailureCorpus, compare_findings

        case, result = self._case_and_result()
        with tempfile.TemporaryDirectory() as directory:
            corpus = FailureCorpus(directory)
            corpus.add(case, result)
            result_path = Path(directory) / f"{case.case_id}.result.json"
            case_path = Path(directory) / f"{case.case_id}.case.json"

            forged = copy.deepcopy(result)
            forged["oracle_findings"] = []
            forged["comparison"] = compare_findings([], forged["execution"]["findings"])
            result_path.write_text(
                json.dumps(forged, allow_nan=False, sort_keys=True), encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "result.oracle_findings"):
                corpus.load(case.case_id)

            corpus.add(case, result)
            case_value = json.loads(case_path.read_text(encoding="utf-8"))
            case_value["ground_truth"]["invented"] = True
            case_path.write_text(
                json.dumps(case_value, allow_nan=False, sort_keys=True), encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "ground_truth"):
                corpus.load(case.case_id)


if __name__ == "__main__":
    unittest.main()
