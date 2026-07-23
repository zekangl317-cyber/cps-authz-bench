"""Intentionally incomplete analyzer used to demonstrate failure capture."""

from __future__ import annotations

import json
import sys


sys.stdin.buffer.read()
sys.stdout.write(json.dumps({"findings": []}, sort_keys=True) + "\n")

