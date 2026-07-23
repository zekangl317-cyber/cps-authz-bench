from __future__ import annotations

import json
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))


class StrictJSONBoundaryTests(unittest.TestCase):
    def test_shared_decoder_rejects_duplicate_members_and_nonstandard_numbers(self) -> None:
        from cps_authz_bench.json_boundary import strict_json_loads

        for document in (
            '{"x":1,"x":2}',
            '{"x":NaN}',
            '{"x":Infinity}',
            '{"x":1e400}',
        ):
            with self.subTest(document=document):
                with self.assertRaises(ValueError):
                    strict_json_loads(document)

    def test_finding_text_rejects_every_escaped_and_literal_c1_control(self) -> None:
        from cps_authz_bench.json_boundary import parse_analyzer_output

        for codepoint in range(0x80, 0xA0):
            control = chr(codepoint)
            findings = {
                "subject": {
                    "rule_id": "X",
                    "subject": f"left{control}right",
                },
                "message": {
                    "rule_id": "X",
                    "subject": "subject",
                    "message": f"left{control}right",
                },
                "detail key": {
                    "rule_id": "X",
                    "subject": "subject",
                    "details": {f"left{control}right": "value"},
                },
                "detail string value": {
                    "rule_id": "X",
                    "subject": "subject",
                    "details": {"key": f"left{control}right"},
                },
            }
            for field, finding in findings.items():
                literal = json.dumps(
                    {"findings": [finding]},
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                documents = {
                    "literal": literal,
                    "escaped": literal.replace(
                        control, f"\\u{codepoint:04x}"
                    ),
                }
                for representation, document in documents.items():
                    try:
                        parse_analyzer_output(document.encode("utf-8"))
                    except ValueError as error:
                        self.assertIn("control characters", str(error))
                    else:
                        self.fail(
                            f"accepted {representation} U+{codepoint:04X} "
                            f"in finding {field}"
                        )

    def test_finding_text_allows_unicode_format_controls_by_policy(self) -> None:
        from cps_authz_bench.json_boundary import parse_analyzer_output

        document = json.dumps(
            {
                "findings": [
                    {
                        "rule_id": "X",
                        "subject": "emoji\u200dsequence",
                        "message": "format\u200dcontrol",
                        "details": {"format\u200dkey": "format\u200dvalue"},
                    }
                ]
            },
            ensure_ascii=False,
        )

        findings = parse_analyzer_output(document.encode("utf-8"))

        self.assertEqual("emoji\u200dsequence", findings[0]["subject"])
        self.assertEqual("format\u200dcontrol", findings[0]["message"])
        self.assertEqual(
            {"format\u200dkey": "format\u200dvalue"},
            findings[0]["details"],
        )

    def test_graph_json_rejects_escaped_lone_surrogates_in_values_and_keys(self) -> None:
        from cps_authz_bench import evaluate_oracle, generate_graph
        from cps_authz_bench.json_boundary import strict_json_loads

        graph = generate_graph(seed=233)
        malformed_documents = []
        for surrogate in ("\ud800", "\udc00"):
            malformed_value = deepcopy(graph)
            malformed_value["services"][0]["zone"] = surrogate
            malformed_documents.append(("value", surrogate, json.dumps(malformed_value)))

            malformed_key = deepcopy(graph)
            malformed_key["services"][0][surrogate] = "unexpected"
            malformed_documents.append(("key", surrogate, json.dumps(malformed_key)))

        for location, surrogate, document in malformed_documents:
            with self.subTest(location=location, surrogate=ascii(surrogate)):
                with self.assertRaisesRegex(ValueError, "Unicode scalar"):
                    strict_json_loads(document)
                self.assertEqual(
                    ["PARSER_CORRUPTION"],
                    [finding["rule_id"] for finding in evaluate_oracle(document)],
                )

    def test_require_graph_rejects_surrogates_with_input_mode_parity(self) -> None:
        from cps_authz_bench import evaluate_oracle, generate_graph
        from cps_authz_bench.oracle import require_graph

        graph = generate_graph(seed=239)
        diagnostic = (
            r"^graph must be a well-formed, schema-valid "
            r"cps-authz-graph/v1 document$"
        )
        for surrogate in ("\ud800", "\udc00"):
            for location in ("value", "key"):
                malformed = deepcopy(graph)
                if location == "value":
                    malformed["services"][0]["zone"] = surrogate
                else:
                    malformed["services"][0][surrogate] = "unexpected"
                text = json.dumps(malformed)
                inputs = {
                    "bytes": text.encode("utf-8"),
                    "text": text,
                    "mapping": malformed,
                }

                for input_mode, value in inputs.items():
                    with self.subTest(
                        input_mode=input_mode,
                        location=location,
                        surrogate=ascii(surrogate),
                    ):
                        with self.assertRaisesRegex(ValueError, diagnostic):
                            require_graph(value)
                        self.assertEqual(
                            ["PARSER_CORRUPTION"],
                            [
                                finding["rule_id"]
                                for finding in evaluate_oracle(value)
                            ],
                        )

    def test_direct_mutation_mapping_rejects_surrogates_stably(self) -> None:
        from cps_authz_bench import apply_mutation, generate_graph

        graph = generate_graph(seed=241)
        diagnostic = (
            r"^mutation input must be a well-formed, schema-valid "
            r"cps-authz-graph/v1 document$"
        )
        for surrogate in ("\ud800", "\udc00"):
            for location in ("value", "key"):
                malformed = deepcopy(graph)
                if location == "value":
                    malformed["effects"][0]["resource"] = surrogate
                else:
                    malformed["effects"][0][surrogate] = "unexpected"

                with self.subTest(location=location, surrogate=ascii(surrogate)):
                    with self.assertRaisesRegex(ValueError, diagnostic):
                        apply_mutation(malformed, "stale_version", seed=251)

    def test_jsonl_result_boundary_rejects_duplicate_and_nonfinite_values(self) -> None:
        from cps_authz_bench import parse_jsonl

        for document in (
            '{"schema_version":"cps-authz-result/v2",'
            '"schema_version":"cps-authz-result/v2"}\n',
            '{"score":NaN}\n',
        ):
            with self.subTest(document=document):
                with self.assertRaisesRegex(ValueError, "invalid JSONL"):
                    parse_jsonl(document)

    def test_jsonl_literal_unicode_line_separators_round_trip(self) -> None:
        from cps_authz_bench import (
            ToolExecution,
            apply_mutation,
            build_result,
            generate_graph,
            parse_jsonl,
            render_jsonl,
        )

        case = apply_mutation(generate_graph(seed=193), "stale_version", seed=197)
        execution = ToolExecution(
            "ok",
            0,
            case.expected_findings,
            json.dumps({"findings": list(case.expected_findings)}),
            "",
        )
        for separator in ("\u2028", "\u2029"):
            with self.subTest(codepoint=f"U+{ord(separator):04X}"):
                tool_name = f"left{separator}right"
                result = build_result(case, tool_name, execution)

                rendered = render_jsonl([result])
                records = parse_jsonl(rendered)

                self.assertIn(separator, rendered)
                self.assertEqual([result], records)
                self.assertEqual(tool_name, records[0]["tool"]["name"])

    def test_jsonl_uses_only_lf_as_a_record_boundary(self) -> None:
        from cps_authz_bench import (
            ToolExecution,
            apply_mutation,
            build_result,
            generate_graph,
            parse_jsonl,
            render_jsonl,
        )

        case = apply_mutation(generate_graph(seed=199), "stale_version", seed=211)
        execution = ToolExecution(
            "ok",
            0,
            case.expected_findings,
            json.dumps({"findings": list(case.expected_findings)}),
            "",
        )
        first = build_result(case, "first", execution)
        second = build_result(case, "second", execution)
        rendered = render_jsonl([first, second])

        self.assertEqual([first, second], parse_jsonl(rendered.replace("\n", "\r\n")))
        with self.assertRaisesRegex(ValueError, r"invalid JSONL at line 1"):
            parse_jsonl(rendered.replace("\n", "\r"))

    def test_failure_corpus_load_uses_the_strict_decoder(self) -> None:
        from cps_authz_bench import (
            FailureCorpus,
            ToolExecution,
            apply_mutation,
            build_result,
            generate_graph,
        )

        case = apply_mutation(generate_graph(seed=211), "stale_version", seed=223)
        execution = ToolExecution("ok", 0, tuple(), '{"findings":[]}', "")
        result = build_result(case, "strict-boundary", execution)
        with tempfile.TemporaryDirectory() as directory:
            corpus = FailureCorpus(directory)
            corpus.add(case, result)
            result_path = Path(directory) / f"{case.case_id}.result.json"
            result_path.write_text(
                '{"schema_version":"cps-authz-result/v2",'
                '"schema_version":"cps-authz-result/v2"}',
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                corpus.load(case.case_id)

    def test_cli_case_and_diff_boundaries_reject_ambiguous_json(self) -> None:
        from cps_authz_bench.cli import INPUT_ERROR_EXIT, main

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ambiguous = root / "ambiguous.json"
            ambiguous.write_text('{"findings":[],"findings":[]}', encoding="utf-8")
            diff_code = main(["diff", "--tool", f"x={ambiguous}"])

            graph = root / "graph.json"
            case = root / "case.json"
            self.assertEqual(
                0,
                main(["generate", "--seed", "227", "--output", str(graph)]),
            )
            self.assertEqual(
                0,
                main(
                    [
                        "mutate",
                        "--input",
                        str(graph),
                        "--mutation",
                        "stale_version",
                        "--output",
                        str(case),
                    ]
                ),
            )
            envelope = case.read_text(encoding="utf-8")
            case.write_text(
                '{"schema_version":"cps-authz-case/v1",' + envelope.lstrip()[1:],
                encoding="utf-8",
            )
            oracle_code = main(["oracle", "--case", str(case)])

            self.assertEqual(INPUT_ERROR_EXIT, diff_code)
            self.assertEqual(INPUT_ERROR_EXIT, oracle_code)

    def test_cli_run_classifies_ambiguous_analyzer_output_without_render_failure(self) -> None:
        from cps_authz_bench import parse_jsonl
        from cps_authz_bench.cli import TOOL_FAILURE_EXIT, main

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graph = root / "graph.json"
            case = root / "case.json"
            result_path = root / "result.jsonl"
            self.assertEqual(0, main(["generate", "--seed", "229", "--output", str(graph)]))
            self.assertEqual(
                0,
                main(
                    [
                        "mutate",
                        "--input",
                        str(graph),
                        "--mutation",
                        "confused_deputy",
                        "--output",
                        str(case),
                    ]
                ),
            )
            document = (
                '{"findings":[],"findings":['
                '{"rule_id":"CONFUSED_DEPUTY","subject":"request-confused-000"}]}'
            )
            code = main(
                [
                    "run",
                    "--case",
                    str(case),
                    "--tool-name",
                    "ambiguous",
                    "--result",
                    str(result_path),
                    "--",
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.write(sys.argv[1])",
                    document,
                ]
            )
            records = parse_jsonl(result_path.read_text(encoding="utf-8"))
            self.assertEqual(TOOL_FAILURE_EXIT, code)
            self.assertEqual("malformed_output", records[0]["execution"]["status"])
            self.assertIsNone(records[0]["execution"]["findings"])


if __name__ == "__main__":
    unittest.main()
