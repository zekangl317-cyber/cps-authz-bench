from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))


class BenchmarkIntegrityTests(unittest.TestCase):
    def test_cli_run_rejects_tampered_ground_truth_as_input_error(self) -> None:
        from cps_authz_bench import apply_mutation, generate_graph
        from cps_authz_bench.cli import INPUT_ERROR_EXIT, main

        case = apply_mutation(
            generate_graph(seed=137), "privilege_expansion", seed=139
        )
        envelope = case.to_envelope()
        envelope["ground_truth"]["findings"] = []

        with tempfile.TemporaryDirectory() as directory:
            case_path = Path(directory) / "tampered.case.json"
            case_path.write_text(json.dumps(envelope), encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(
                    [
                        "run",
                        "--case",
                        str(case_path),
                        "--tool-name",
                        "always-empty",
                        "--",
                        sys.executable,
                        str(REPO_ROOT / "examples" / "tools" / "always_empty.py"),
                    ]
                )

        self.assertEqual(INPUT_ERROR_EXIT, exit_code)
        self.assertEqual("", stdout.getvalue())
        self.assertEqual(
            "cps-authz-bench: input error: benchmark case "
            "ground_truth.findings do not match decoded payload oracle\n",
            stderr.getvalue(),
        )

    def test_cli_run_rejects_tampered_case_id_as_input_error(self) -> None:
        from cps_authz_bench import apply_mutation, generate_graph
        from cps_authz_bench.cli import INPUT_ERROR_EXIT, main

        case = apply_mutation(generate_graph(seed=149), "stale_version", seed=151)
        envelope = case.to_envelope()
        envelope["case_id"] = "stale_version-0000000000000000"

        with tempfile.TemporaryDirectory() as directory:
            case_path = Path(directory) / "tampered.case.json"
            case_path.write_text(json.dumps(envelope), encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(
                    [
                        "run",
                        "--case",
                        str(case_path),
                        "--tool-name",
                        "always-empty",
                        "--",
                        sys.executable,
                        str(REPO_ROOT / "examples" / "tools" / "always_empty.py"),
                    ]
                )

        self.assertEqual(INPUT_ERROR_EXIT, exit_code)
        self.assertEqual("", stdout.getvalue())
        self.assertEqual(
            "cps-authz-bench: input error: benchmark case case_id does not match "
            "mutation and payload\n",
            stderr.getvalue(),
        )

    def test_build_result_rejects_forged_expected_findings(self) -> None:
        from cps_authz_bench import (
            BenchmarkCase,
            ToolExecution,
            apply_mutation,
            build_result,
            generate_graph,
        )

        case = apply_mutation(
            generate_graph(seed=157), "confused_deputy", seed=163
        )
        forged = BenchmarkCase(
            case_id=case.case_id,
            mutation=case.mutation,
            seed=case.seed,
            payload=case.payload,
            expected_findings=tuple(),
        )
        execution = ToolExecution("ok", 0, tuple(), '{"findings":[]}', "")

        with self.assertRaisesRegex(
            ValueError,
            "^benchmark case ground_truth.findings do not match decoded payload oracle$",
        ):
            build_result(forged, "forged-analyzer", execution)

    def test_build_result_rejects_forged_case_id(self) -> None:
        from cps_authz_bench import (
            BenchmarkCase,
            ToolExecution,
            apply_mutation,
            build_result,
            generate_graph,
        )

        case = apply_mutation(generate_graph(seed=167), "orphan_effect", seed=173)
        forged = BenchmarkCase(
            case_id="orphan_effect-0000000000000000",
            mutation=case.mutation,
            seed=case.seed,
            payload=case.payload,
            expected_findings=case.expected_findings,
        )
        execution = ToolExecution(
            "ok", 0, case.expected_findings, '{"findings":[]}', ""
        )

        with self.assertRaisesRegex(
            ValueError,
            "^benchmark case case_id does not match mutation and payload$",
        ):
            build_result(forged, "forged-analyzer", execution)

    def test_result_findings_are_derived_from_analyzer_stdout(self) -> None:
        from cps_authz_bench import (
            ToolExecution,
            apply_mutation,
            build_result,
            generate_graph,
            validate_result,
        )

        case = apply_mutation(
            generate_graph(seed=211), "privilege_expansion", seed=223
        )
        for stdout in ("not JSON", '{"findings":[]}'):
            with self.subTest(stdout=stdout):
                forged = ToolExecution(
                    "ok", 0, case.expected_findings, stdout, ""
                )
                with self.assertRaisesRegex(ValueError, "stdout"):
                    build_result(case, "forged-analyzer", forged)

        valid_stdout = json.dumps({"findings": list(case.expected_findings)})
        result = build_result(
            case,
            "bound-analyzer",
            ToolExecution("ok", 0, case.expected_findings, valid_stdout, ""),
        )
        result["execution"]["stdout"] = {
            "encoding": "utf-8",
            "data": '{"findings":[]}',
        }
        with self.assertRaisesRegex(ValueError, "derived from stdout"):
            validate_result(result)

    def test_envelope_rejects_non_string_finding_identity(self) -> None:
        from cps_authz_bench import BenchmarkCase, apply_mutation, generate_graph

        case = apply_mutation(
            generate_graph(seed=179), "privilege_expansion", seed=181
        )

        for field, malformed_value in (("rule_id", 7), ("subject", None)):
            with self.subTest(field=field):
                envelope = case.to_envelope()
                envelope["ground_truth"]["findings"][0][field] = malformed_value

                with self.assertRaisesRegex(
                    ValueError,
                    r"^benchmark case ground_truth.findings\[0\] needs string "
                    r"rule_id and subject$",
                ):
                    BenchmarkCase.from_envelope(envelope)

    def test_envelope_requires_ground_truth_finding_array(self) -> None:
        from cps_authz_bench import BenchmarkCase, apply_mutation, generate_graph

        case = apply_mutation(generate_graph(seed=197), "stale_version", seed=199)
        envelope = case.to_envelope()
        envelope["ground_truth"]["findings"] = tuple(
            envelope["ground_truth"]["findings"]
        )

        with self.assertRaisesRegex(
            ValueError,
            "^benchmark case ground_truth.findings must be an array of objects$",
        ):
            BenchmarkCase.from_envelope(envelope)

    def test_parser_corruption_round_trip_uses_raw_payload_oracle(self) -> None:
        from cps_authz_bench import (
            BenchmarkCase,
            ToolExecution,
            apply_mutation,
            build_result,
            generate_graph,
        )

        case = apply_mutation(
            generate_graph(seed=191), "parser_corruption", seed=193
        )
        loaded = BenchmarkCase.from_envelope(case.to_envelope())
        execution = ToolExecution(
            "ok",
            0,
            loaded.expected_findings,
            json.dumps({"findings": list(loaded.expected_findings)}),
            "",
        )

        result = build_result(loaded, "parser-aware-analyzer", execution)

        self.assertEqual(case, loaded)
        self.assertEqual(
            ["PARSER_CORRUPTION"],
            [finding["rule_id"] for finding in result["oracle_findings"]],
        )
        self.assertTrue(result["comparison"]["exact_match"])


if __name__ == "__main__":
    unittest.main()
