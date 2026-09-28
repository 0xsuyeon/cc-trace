from __future__ import annotations
from typing import Iterable

IMPACT_ORDER = {"NEGLIGIBLE": 0, "MODERATE": 1, "MAJOR": 2, "SEVERE": 3}
FEASIBILITY_ORDER = {"VERY_LOW": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}

def attack_path_score(ap: dict) -> int:
    p = ap["attack_potential"]
    return (
        int(p["elapsed_time"])
        + int(p["specialist_expertise"])
        + int(p["knowledge_of_item"])
        + int(p["window_of_opportunity"])
        + int(p["equipment"])
    )

def score_to_feasibility(score: int, method: dict) -> str:
    for band in method["attack_potential"]["score_to_feasibility"]:
        lo, hi = int(band["min"]), band["max"]
        if score >= lo and (hi is None or score <= int(hi)):
            return band["rating"]
    raise ValueError(f"score outside configured feasibility mapping: {score}")

def aggregate_feasibility(ratings: Iterable[str]) -> str:
    ratings=list(ratings)
    if not ratings:
        raise ValueError("no attack feasibility ratings")
    return max(ratings, key=lambda x: FEASIBILITY_ORDER[x])

def aggregate_impacts(damage_records: Iterable[dict]) -> dict[str, str]:
    records=list(damage_records)
    if not records:
        raise ValueError("no damage records")
    out={}
    for dim in ("safety","financial","operational","privacy"):
        out[dim]=max(
            (r["impact"][dim] for r in records),
            key=lambda x: IMPACT_ORDER[x],
        )
    return out

def risk_by_dimension(impact_vector: dict[str,str], feasibility: str, method: dict) -> dict[str,int]:
    matrix=method["risk_matrix"]["matrix"]
    return {dim:int(matrix[impact][feasibility]) for dim,impact in impact_vector.items()}

def final_risk(risks: dict[str,int]) -> int:
    if not risks:
        raise ValueError("no risk dimensions")
    return max(int(v) for v in risks.values())

def treatment_for_risk(risk: int, method: dict) -> str:
    rules=method["treatment_policy"]["rules"]
    matches=[
        r for r in rules
        if int(r["min_risk"]) <= int(risk) <= int(r["max_risk"])
    ]
    if len(matches) != 1:
        raise ValueError(f"risk {risk} matched {len(matches)} treatment rules")
    return matches[0]["decision"]

def cal_for(max_impact: str, attack_vector: str, method: dict) -> str | None:
    return method["cal_matrix"]["matrix"][max_impact][attack_vector]
