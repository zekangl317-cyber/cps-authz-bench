from __future__ import annotations

import math
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class SubprocessAdapterTests(unittest.TestCase):
    def test_limits_reject_booleans_non_numeric_and_non_finite_values(self) -> None:
        from cps_authz_bench import run_tool

        command = [sys.executable, "-c", "print('{\"findings\": []}')"]
        invalid_timeout_values = (True, False, "1", None, math.nan, math.inf, -math.inf)
        invalid_output_values = (
            True,
            False,
            "4096",
            None,
            4096.0,
            math.nan,
            math.inf,
            -math.inf,
        )

        for value in invalid_timeout_values:
            with self.subTest(limit="timeout_seconds", value=value):
                with self.assertRaises(ValueError):
                    run_tool(command, b"{}\n", timeout_seconds=value)  # type: ignore[arg-type]
        for value in invalid_output_values:
            with self.subTest(limit="max_output_bytes", value=value):
                with self.assertRaises(ValueError):
                    run_tool(command, b"{}\n", max_output_bytes=value)  # type: ignore[arg-type]

    def test_limits_have_documented_finite_upper_bounds(self) -> None:
        from cps_authz_bench import run_tool

        command = [sys.executable, "-c", "print('{\"findings\": []}')"]
        with self.assertRaisesRegex(ValueError, "timeout_seconds must be at most 300"):
            run_tool(command, b"{}\n", timeout_seconds=300.000001)
        with self.assertRaisesRegex(
            ValueError, "max_output_bytes must be at most 16777216"
        ):
            run_tool(command, b"{}\n", max_output_bytes=16_777_217)

    def test_tool_timeout_is_bounded_and_classified(self) -> None:
        from cps_authz_bench import run_tool

        result = run_tool(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            b"{}\n",
            timeout_seconds=0.05,
            max_output_bytes=4096,
        )

        self.assertEqual("timeout", result.status)
        self.assertIsNone(result.findings)

    def test_malformed_tool_output_is_classified(self) -> None:
        from cps_authz_bench import run_tool

        result = run_tool(
            [sys.executable, "-c", "print('not-json')"],
            b"{}\n",
            timeout_seconds=1.0,
            max_output_bytes=4096,
        )

        self.assertEqual("malformed_output", result.status)
        self.assertIsNone(result.findings)

    def test_invalid_utf8_output_is_retained_losslessly(self) -> None:
        import base64

        from cps_authz_bench import run_tool

        encoded_outputs = []
        for raw in (b"\xff\x80", b"\xff\x81"):
            result = run_tool(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))",
                    raw.hex(),
                ],
                b"{}",
            )
            self.assertEqual("malformed_output", result.status)
            prefix = "invalid-utf8-base64:"
            self.assertTrue(result.stdout.startswith(prefix))
            self.assertEqual(raw, base64.b64decode(result.stdout[len(prefix) :]))
            capture = result.to_dict()["stdout"]
            self.assertEqual("base64", capture["encoding"])
            self.assertEqual(raw, base64.b64decode(capture["data"], validate=True))
            encoded_outputs.append(capture)
        self.assertNotEqual(encoded_outputs[0], encoded_outputs[1])

        invalid = run_tool(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'\\xff')"],
            b"{}",
        )
        reserved_text = "invalid-utf8-base64:/w=="
        valid = run_tool(
            [sys.executable, "-c", "import sys; sys.stdout.write(sys.argv[1])", reserved_text],
            b"{}",
        )
        self.assertEqual(invalid.stdout, valid.stdout)
        self.assertNotEqual(invalid.to_dict()["stdout"], valid.to_dict()["stdout"])
        self.assertEqual(
            {"encoding": "utf-8", "data": reserved_text},
            valid.to_dict()["stdout"],
        )

    def test_ambiguous_and_nonstandard_json_output_is_rejected(self) -> None:
        from cps_authz_bench import run_tool

        documents = (
            '{"findings":[],"findings":[{"rule_id":"X","subject":"s"}]}',
            '{"findings":[{"rule_id":"X","subject":"s","confidence":NaN}]}',
            '{"findings":[{"rule_id":"X","subject":"s"}],"extra":true}',
        )
        for document in documents:
            with self.subTest(document=document):
                result = run_tool(
                    [
                        sys.executable,
                        "-c",
                        "import sys; sys.stdout.write(sys.argv[1])",
                        document,
                    ],
                    b"{}\n",
                    timeout_seconds=1.0,
                    max_output_bytes=4096,
                )
                self.assertEqual("malformed_output", result.status)
                self.assertIsNone(result.findings)

    def test_finding_schema_is_closed_bounded_and_preserves_supported_metadata(self) -> None:
        from cps_authz_bench import run_tool

        valid = (
            '{"findings":[{"rule_id":"CONFUSED_DEPUTY","subject":"request-1",'
            '"message":"denied","details":{"attempt":1,"cached":false},'
            '"confidence":0.75}]}'
        )
        execution = run_tool(
            [sys.executable, "-c", "import sys; sys.stdout.write(sys.argv[1])", valid],
            b"{}\n",
            timeout_seconds=1.0,
            max_output_bytes=4096,
        )
        self.assertEqual("ok", execution.status)
        self.assertEqual(0.75, execution.findings[0]["confidence"])

        invalid_documents = (
            '{"findings":[{"rule_id":"X","subject":"s","unknown":1}]}',
            '{"findings":[{"rule_id":"X","subject":"s","details":{"x":[]}}]}',
            '{"findings":[{"rule_id":"X","subject":"s","confidence":true}]}',
        )
        for document in invalid_documents:
            with self.subTest(document=document):
                rejected = run_tool(
                    [
                        sys.executable,
                        "-c",
                        "import sys; sys.stdout.write(sys.argv[1])",
                        document,
                    ],
                    b"{}\n",
                    timeout_seconds=1.0,
                    max_output_bytes=4096,
                )
                self.assertEqual("malformed_output", rejected.status)

    def test_oversized_tool_output_is_stopped(self) -> None:
        from cps_authz_bench import run_tool

        result = run_tool(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 20000)"],
            b"{}\n",
            timeout_seconds=1.0,
            max_output_bytes=512,
        )

        self.assertEqual("output_limit", result.status)
        self.assertLessEqual(len(result.stdout.encode("utf-8")), 512)

    def test_timeout_terminates_a_hanging_child_process(self) -> None:
        from cps_authz_bench import run_tool

        child = (
            "import pathlib,sys,time; time.sleep(0.8); "
            "pathlib.Path(sys.argv[1]).write_text('escaped', encoding='utf-8')"
        )
        parent = (
            "import subprocess,sys,time; "
            "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]]); "
            "time.sleep(30)"
        )
        with tempfile.TemporaryDirectory() as directory:
            sentinel = Path(directory) / "child-survived.txt"
            started = time.monotonic()
            result = run_tool(
                [sys.executable, "-c", parent, child, str(sentinel)],
                b"{}\n",
                timeout_seconds=0.1,
                max_output_bytes=4096,
            )
            elapsed = time.monotonic() - started
            time.sleep(1.0)

            self.assertEqual("timeout", result.status)
            self.assertLess(elapsed, 2.0)
            self.assertFalse(sentinel.exists(), "descendant escaped timeout cleanup")

    @unittest.skipUnless(sys.platform == "win32", "requires Windows Job Objects")
    def test_windows_suspended_launch_contains_an_immediate_child(self) -> None:
        from cps_authz_bench import run_tool
        from cps_authz_bench.adapter import _WindowsJob

        child = (
            "import pathlib,sys,time; "
            "pathlib.Path(sys.argv[1]).write_text('started', encoding='utf-8'); "
            "time.sleep(0.7); "
            "pathlib.Path(sys.argv[2]).write_text('escaped', encoding='utf-8')"
        )
        parent = (
            "import subprocess,sys,time; "
            "subprocess.Popen("
            "[sys.executable, '-c', sys.argv[1], sys.argv[2], sys.argv[3]]"
            "); "
            "time.sleep(30)"
        )
        original_attach = _WindowsJob.attach

        with tempfile.TemporaryDirectory() as directory:
            child_started = Path(directory) / "immediate-child-started.txt"
            sentinel = Path(directory) / "immediate-child-survived.txt"

            def adversarial_attach(process):
                deadline = time.monotonic() + 1.5
                while (
                    time.monotonic() < deadline
                    and not child_started.exists()
                ):
                    time.sleep(0.005)
                return original_attach(process)

            with patch.object(_WindowsJob, "attach", side_effect=adversarial_attach):
                result = run_tool(
                    [
                        sys.executable,
                        "-c",
                        parent,
                        child,
                        str(child_started),
                        str(sentinel),
                    ],
                    b"{}\n",
                    timeout_seconds=0.05,
                    max_output_bytes=4096,
                )
            time.sleep(0.9)

            self.assertEqual("timeout", result.status)
            self.assertFalse(
                sentinel.exists(),
                "immediate child ran before Windows Job assignment",
            )

    @unittest.skipUnless(sys.platform == "win32", "requires Windows Job Objects")
    def test_windows_containment_failure_is_a_closed_launch_error(self) -> None:
        from cps_authz_bench import run_tool
        from cps_authz_bench.adapter import _WindowsJob

        with tempfile.TemporaryDirectory() as directory:
            sentinel = Path(directory) / "analyzer-ran.txt"
            analyzer = (
                "import pathlib,sys; "
                "pathlib.Path(sys.argv[1]).write_text('ran', encoding='utf-8'); "
                "print('{\"findings\": []}')"
            )
            with patch.object(_WindowsJob, "attach", return_value=None):
                result = run_tool(
                    [sys.executable, "-c", analyzer, str(sentinel)],
                    b"{}\n",
                    timeout_seconds=1.0,
                    max_output_bytes=4096,
                )

            self.assertEqual("launch_error", result.status)
            self.assertIsNone(result.exit_code)
            self.assertIsNone(result.findings)
            self.assertEqual("", result.stdout)
            self.assertEqual("", result.stderr)
            self.assertRegex(
                result.error or "",
                r"^failed to establish Windows process containment",
            )
            self.assertFalse(sentinel.exists(), "uncontained analyzer was allowed to run")

    def test_timeout_terminates_child_after_launcher_has_exited(self) -> None:
        from cps_authz_bench import run_tool

        child = (
            "import pathlib,sys,time; time.sleep(0.8); "
            "pathlib.Path(sys.argv[1]).write_text('escaped', encoding='utf-8')"
        )
        launcher = (
            "import subprocess,sys; "
            "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]])"
        )
        with tempfile.TemporaryDirectory() as directory:
            sentinel = Path(directory) / "child-survived.txt"
            result = run_tool(
                [sys.executable, "-c", launcher, child, str(sentinel)],
                b"{}\n",
                timeout_seconds=0.1,
                max_output_bytes=4096,
            )
            time.sleep(1.0)

            self.assertEqual("timeout", result.status)
            self.assertFalse(sentinel.exists(), "orphan descendant escaped cleanup")

    def test_output_limit_terminates_a_hanging_child_process(self) -> None:
        from cps_authz_bench import run_tool

        child = (
            "import pathlib,sys,time; time.sleep(0.8); "
            "pathlib.Path(sys.argv[1]).write_text('escaped', encoding='utf-8')"
        )
        parent = (
            "import subprocess,sys,time; "
            "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]]); "
            "sys.stdout.write('x' * 20000); sys.stdout.flush(); time.sleep(30)"
        )
        with tempfile.TemporaryDirectory() as directory:
            sentinel = Path(directory) / "child-survived.txt"
            started = time.monotonic()
            result = run_tool(
                [sys.executable, "-c", parent, child, str(sentinel)],
                b"{}\n",
                timeout_seconds=3.0,
                max_output_bytes=512,
            )
            elapsed = time.monotonic() - started
            time.sleep(1.0)

            self.assertEqual("output_limit", result.status)
            self.assertLess(elapsed, 2.0)
            self.assertFalse(sentinel.exists(), "descendant escaped output-limit cleanup")


if __name__ == "__main__":
    unittest.main()
