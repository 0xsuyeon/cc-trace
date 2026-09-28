# Methodology

CC-TRACE uses a fixed connected-car reference TARA and projects only the portions supported by the current Item evidence.

## 1. Item Definition

The interactive workflow collects four types of Item facts:

1. supported remote vehicle functions (`IF-01`~`IF-07`)
2. architecture basis (`REFERENCE` or `DIRECT`)
3. command result/status availability
4. vehicle-state use in command acceptance

DIRECT architecture input is validated for component identity, connection endpoints, and reachability before architecture-derived contexts are activated.

## 2. Canonical reference TARA

The domain knowledge currently contains:

- 7 Item Functions
- 13 Assets
- 17 Damage Scenarios
- 43 Threat Scenarios
- 16 Attack Paths
- 43 Risk records
- 42 `REDUCE` decisions
- 1 `RETAIN` decision
- 10 Cybersecurity Goals
- 1 Cybersecurity Claim

The canonical data is stored under:

```text
cc_trace_kb/knowledge/domain/connected_car_remote_command_v1/
```

## 3. Deterministic calculation chain

CC-TRACE recomputes the stored values using the method knowledge under:

```text
cc_trace_kb/knowledge/method/tara_method_v1/
```

The validation chain covers:

```text
Attack Potential
    -> Attack Feasibility
    -> Impact aggregation
    -> S/F/O/P Risk
    -> Final Risk
    -> Treatment
    -> Goal / Claim
    -> CAL
```

## 4. Applicability projection

Projection does not rewrite the canonical TARA. It narrows applicability according to confirmed Item Functions and contexts.

Examples:

- function-specific Damage Scenarios are limited to active functions
- state-related Asset/Threat branches are scoped to functions that use vehicle state during command acceptance
- DIRECT architecture contexts are activated only when the corresponding graph relation is reachable

The projection keeps canonical reference values separate from target-product values. Product-specific Risk, Treatment, and CAL remain unassessed until product-specific inputs are established.

## 5. Method sources

The knowledge base was structured from:

- ISO/SAE 21434:2021
- the Korean ISO/SAE 21434-based TARA guidance used by the project
- the project's integrated connected-car reference TARA report

Source-document identifiers and SHA-256 values are recorded in `provenance.json`.
