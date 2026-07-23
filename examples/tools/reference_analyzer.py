"""Example analyzer that delegates to the benchmark's reference oracle."""

from __future__ import annotations

import json
import sys

from cps_authz_bench import evaluate_oracle


payload = sys.stdin.buffer.read()
result = {"findings": evaluate_oracle(payload)}
sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")

