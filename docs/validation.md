# Validation

CC-TRACE includes automated checks for the canonical TARA, source analysis, projection logic, provider adapters, and CLI behavior.

## Regression tests

Run:

```bash
python -m pytest -q
```

The test suite covers:

- command/query and telemetry separation
- same-name methods in different classes
- test/example-only source evidence
- keyword and f-string HTTP URLs
- vehicle-state guards in attributes and dictionary access
- DIRECT-architecture connection validation
- unreachable target-controller handling
- function-scoped state projection
- source/manual decision provenance
- LLM evidence-gate behavior
- provider request/response handling
- hidden API-key input
- Gemini batching and timeout handling

The current repository passes 80 regression tests.

## Canonical TARA validation

Run:

```bash
python -m cc_trace_kb validate
```

The validator checks:

- canonical cardinalities and referential integrity
- Attack Potential scores
- Attack Feasibility mappings
- threat-level aggregate feasibility
- S/F/O/P impact vectors
- S/F/O/P risk values and final risk
- treatment decisions
- Goal / Claim coverage
- CAL values
- mapping-KB references
- Item / Operational Environment boundary semantics

## Report alignment

The canonical knowledge base was checked against the project integrated TARA report with 283 alignment checks.

The source report itself is not distributed in this repository. Its identifier and SHA-256 are recorded in `provenance.json`, and the alignment utility is retained under `tools/` so the check can be reproduced when the source document is available.

## Canonical hash

`canonical_tara.sha256` pins the canonical TARA payload. The validation command verifies the stored hash before completing the remaining consistency checks.
