from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))


class CliTests(unittest.TestCase):
    _MUTATION_RECORD_FIELDS = {
        "privilege_expansion": ("approved_grants", "principal"),
        "confused_deputy": ("effects", "owner"),
        "stale_version": ("requests", "service_version"),
        "orphan_effect": ("services", "id"),
        "parser_corruption": ("effects", "id"),
    }
    _INVALID_MUTATION_INPUT_DIAGNOSTIC = (
        "cps-authz-bench: input error: mutation input must be a "
        "well-formed, schema-valid cps-authz-graph/v1 document\n"
    )

    def assertMutationInputError(  # noqa: N802
        self,
        graph: dict[str, object],
        mutation: str,
        root: Path,
        label: str,
    ) -> None:
        from cps_authz_bench.cli import INPUT_ERROR_EXIT, main

        graph_path = root / f"{mutation}-{label}.json"
        case_path = root / f"{mutation}-{label}-case.json"
        graph_path.write_text(json.dumps(graph), encoding="utf-8")
        stdout = io.StringIO()
        stderr = io.StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = main(
                [
                    "mutate",
                    "--input",
                    str(graph_path),
                    "--mutation",
                    mutation,
                    "--output",
                    str(case_path),
                ]
            )

        self.assertEqual(INPUT_ERROR_EXIT, exit_code)
        self.assertEqual("", stdout.getvalue())
        self.assertEqual(
            self._INVALID_MUTATION_INPUT_DIAGNOSTIC,
            stderr.getvalue(),
        )
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertFalse(case_path.exists())

    def test_generate_then_mutate_produces_valid_case_envelope(self) -> None:
        from cps_authz_bench import BenchmarkCase, validate_mutation
        from cps_authz_bench.cli import main

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graph_path = root / "graph.json"
            case_path = root / "case.json"

            generate_code = main(
                [
                    "generate",
                    "--seed",
                    "127",
                    "--services",
                    "5",
                    "--effects",
                    "8",
                    "--requests",
                    "10",
                    "--output",
                    str(graph_path),
                ]
            )
            mutate_code = main(
                [
                    "mutate",
                    "--input",
                    str(graph_path),
                    "--mutation",
                    "orphan_effect",
                    "--seed",
                    "131",
                    "--output",
                    str(case_path),
                ]
            )

            case = BenchmarkCase.from_envelope(
                json.loads(case_path.read_text(encoding="utf-8"))
            )
            self.assertEqual(0, generate_code)
            self.assertEqual(0, mutate_code)
            self.assertTrue(validate_mutation(case))

    def test_invalid_seed_commands_do_not_create_output(self) -> None:
        from cps_authz_bench.cli import INPUT_ERROR_EXIT, main

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graph_path = root / "graph.json"
            self.assertEqual(
                0,
                main(["generate", "--seed", "1", "--output", str(graph_path)]),
            )

            for seed in (-(2**63) - 1, 2**63):
                commands = (
                    (
                        "generate",
                        [
                            "generate",
                            "--seed",
                            str(seed),
                            "--output",
                            str(root / f"invalid-generate-{seed}.json"),
                        ],
                    ),
                    (
                        "mutate",
                        [
                            "mutate",
                            "--input",
                            str(graph_path),
                            "--mutation",
                            "stale_version",
                            "--seed",
                            str(seed),
                            "--output",
                            str(root / f"invalid-mutate-{seed}.json"),
                        ],
                    ),
                )
                for command_name, command in commands:
                    with self.subTest(command=command_name, seed=seed):
                        output_path = Path(command[-1])
                        stdout = io.StringIO()
                        stderr = io.StringIO()
                        with redirect_stdout(stdout), redirect_stderr(stderr):
                            exit_code = main(command)

                        self.assertEqual(INPUT_ERROR_EXIT, exit_code)
                        self.assertEqual("", stdout.getvalue())
                        self.assertIn("signed 64-bit integer", stderr.getvalue())
                        self.assertFalse(output_path.exists())

    def test_mutate_rejects_missing_approved_grants_as_input_error(self) -> None:
        from cps_authz_bench import generate_graph

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graph = generate_graph(seed=137)
            graph.pop("approved_grants")
            self.assertMutationInputError(
                graph,
                "privilege_expansion",
                root,
                "missing-approved-grants",
            )

    def test_mutate_rejects_missing_nested_fields_for_every_mutation(self) -> None:
        from cps_authz_bench import generate_graph

        graph = generate_graph(seed=139)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for mutation, (collection, field) in self._MUTATION_RECORD_FIELDS.items():
                with self.subTest(mutation=mutation, field=f"{collection}.{field}"):
                    malformed = deepcopy(graph)
                    malformed[collection][0].pop(field)
                    self.assertMutationInputError(
                        malformed,
                        mutation,
                        root,
                        f"missing-{collection}-{field}",
                    )

    def test_mutate_rejects_wrong_typed_nested_fields_for_every_mutation(self) -> None:
        from cps_authz_bench import generate_graph

        graph = generate_graph(seed=149)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for mutation, (collection, field) in self._MUTATION_RECORD_FIELDS.items():
                with self.subTest(mutation=mutation, field=f"{collection}.{field}"):
                    malformed = deepcopy(graph)
                    malformed[collection][0][field] = []
                    self.assertMutationInputError(
                        malformed,
                        mutation,
                        root,
                        f"wrong-type-{collection}-{field}",
                    )

    def test_mutate_rechecks_exact_postcondition_before_writing(self) -> None:
        from cps_authz_bench import BenchmarkCase, generate_graph
        from cps_authz_bench.cli import INPUT_ERROR_EXIT, main
        from cps_authz_bench.model import _canonical_case_id

        graph = generate_graph(
            seed=157,
            service_count=1,
            effect_count=1,
            request_count=0,
        )
        payload_graph = deepcopy(graph)
        payload_graph.pop("ground_truth")
        payload = (
            json.dumps(
                payload_graph,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        mislabeled = BenchmarkCase(
            case_id=_canonical_case_id("orphan_effect", payload),
            mutation="orphan_effect",
            seed=0,
            payload=payload,
            expected_findings=(),
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graph_path = root / "graph.json"
            case_path = root / "case.json"
            graph_path.write_text(json.dumps(graph), encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with patch(
                "cps_authz_bench.cli.apply_mutation",
                return_value=mislabeled,
            ), redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(
                    [
                        "mutate",
                        "--input",
                        str(graph_path),
                        "--mutation",
                        "orphan_effect",
                        "--seed",
                        "0",
                        "--output",
                        str(case_path),
                    ]
                )

            self.assertEqual(INPUT_ERROR_EXIT, exit_code)
            self.assertEqual("", stdout.getvalue())
            self.assertIn(
                "orphan_effect mutation must produce exactly one "
                "ORPHAN_EFFECT finding",
                stderr.getvalue(),
            )
            self.assertFalse(case_path.exists())


if __name__ == "__main__":
    unittest.main()
