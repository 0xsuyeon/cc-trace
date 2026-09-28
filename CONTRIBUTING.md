# Contributing

1. Create a branch for the change.
2. Keep source-analysis, semantic-mapping, and TARA-method changes separate when possible.
3. Add or update regression tests for behavior changes.
4. Run the full test suite and canonical validation before opening a pull request.

```bash
python -m pytest -q
python -m cc_trace_kb validate
```

Changes to canonical TARA data should include an explicit provenance update and matching validation evidence.
