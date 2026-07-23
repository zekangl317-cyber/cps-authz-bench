# Contributing

Changes should preserve deterministic benchmark semantics and the ability to run
on stock Python 3.11+ on Windows.

## Development setup

```powershell
$env:PYTHONPATH = "src"
$env:PYTHONDONTWRITEBYTECODE = "1"
python -B -m unittest discover -s tests -v
python -B -m cps_authz_bench --help
```

An optional editable install is:

```powershell
python -m pip install --no-build-isolation -e .
```

## Change expectations

- Test observable public API or CLI behavior, including a negative path.
- Never read global random state; pass an explicit seed.
- Keep graph, case, result, and finding ordering deterministic.
- Preserve existing mutation names and rule IDs or version the affected schema.
- Do not add timestamps or measured duration to deterministic result records.
- Keep the subprocess adapter on `shell=False` and retain timeout/output bounds.
- Document oracle-semantic changes and add fixture coverage.
- Update the changelog for user-visible behavior.

Do not commit caches, wheels, editable-install metadata, temporary graphs,
results, or locally accumulated failure corpora.

