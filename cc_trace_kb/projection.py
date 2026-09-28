from __future__ import annotations
from .loader import load_canonical, load_mapping

def _index(items):
    return {x["id"]:x for x in items}

def project(
    function_ids: list[str],
    contexts: list[str] | None = None,
    state_function_ids: list[str] | None = None,
) -> dict:
    """Project canonical reference TARA applicability onto a target scope.

    This projection deliberately does NOT recompute target/product risk.
    It narrows functional damage applicability while preserving canonical
    reference risk/treatment as background reference values.
    """
    c=load_canonical()
    mp=load_mapping()
    contexts=set(contexts or [])

    functions=_index(c["functions"])
    assets=_index(c["assets"])
    damages=_index(c["damage_scenarios"])
    threats=_index(c["threat_scenarios"])
    paths=_index(c["attack_paths"])
    risks={x["threat_id"]:x for x in c["risk_records"]}
    treatments={x["threat_id"]:x for x in c["treatments"]}

    bad_functions=set(function_ids)-set(functions)
    if bad_functions:
        raise ValueError(f"unknown functions: {sorted(bad_functions)}")

    context_rules={x["context"]:x for x in mp["context_rules"]["contexts"]}
    bad_contexts=contexts-set(context_rules)
    if bad_contexts:
        raise ValueError(f"unknown contexts: {sorted(bad_contexts)}")

    # Domain relations come from canonical knowledge, not Python constants.
    function_asset={x["function_id"]:x["asset_id"] for x in c["function_asset_links"]}
    function_damage={x["function_id"]:set(x["damage_ids"]) for x in c["function_damage_links"]}

    active_function_damage=set()
    state_scope=state_function_ids if state_function_ids is not None else function_ids
    bad_state_functions=set(state_scope)-set(function_ids)
    if bad_state_functions:
        raise ValueError(f"state functions must be active functions: {sorted(bad_state_functions)}")
    state_function_damage=set()
    for fid in state_scope:
        state_function_damage |= function_damage[fid]

    selected_assets=set()
    selected_threats=set()
    asset_annotations={}
    threat_annotations={}

    for fid in function_ids:
        active_function_damage |= function_damage[fid]
        aid=function_asset[fid]
        selected_assets.add(aid)
        asset_annotations[aid]={
            "applicability":"CONFIRMED",
            "evidence_basis":"DERIVED",
            "reason":f"Active function {fid}"
        }
        for t in c["threat_scenarios"]:
            if t["asset_id"]==aid:
                selected_threats.add(t["id"])
                threat_annotations[t["id"]]={
                    "applicability":"APPLICABLE",
                    "evidence_basis":"REFERENCE",
                    "reason":f"Canonical function branch for {fid}"
                }

    for context in sorted(contexts):
        rule=context_rules[context]
        for aid in rule["assets"]:
            selected_assets.add(aid)
            asset_annotations[aid]={
                "applicability":rule["status"],
                "evidence_basis":"REFERENCE",
                "reason":context
            }
        for tid in rule["threats"]:
            selected_threats.add(tid)
            threat_annotations[tid]={
                "applicability":rule["status"],
                "evidence_basis":"REFERENCE",
                "reason":context
            }

    result_damage_ids={"DS-16","DS-17"}
    projected_damage_union=set()
    selected_paths=set()
    projected_threats=[]

    function_assets={function_asset[f] for f in function_ids}
    for tid in sorted(selected_threats):
        t=threats[tid]
        rr=risks[tid]
        aid=t["asset_id"]
        canonical_damage_ids=list(rr["risk_damage_ids"])

        if aid in function_assets:
            applicable_damage_ids=canonical_damage_ids
        elif aid=="AS-10":
            applicable_damage_ids=[d for d in canonical_damage_ids if d in result_damage_ids]
        elif aid=="AS-13":
            applicable_damage_ids=[d for d in canonical_damage_ids if d in state_function_damage]
        elif aid in {"AS-08","AS-09","AS-11","AS-12"}:
            applicable_damage_ids=[d for d in canonical_damage_ids if d in active_function_damage]
        else:
            applicable_damage_ids=canonical_damage_ids

        projected_damage_union.update(applicable_damage_ids)
        selected_paths.update(t["attack_path_ids"])

        projected_threats.append({
            **t,
            "applicability":threat_annotations.get(tid,{"applicability":"UNKNOWN","evidence_basis":"UNKNOWN"}),
            "canonical_damage_ids":canonical_damage_ids,
            "applicable_damage_ids":applicable_damage_ids,
            "canonical_reference_risk":rr["expected_final_risk"],
            "canonical_reference_treatment":treatments[tid]["decision"],
            "target_product_risk":None,
            "target_product_risk_status":"UNASSESSED",
            "target_product_treatment":None,
            "target_product_treatment_status":"UNASSESSED"
        })

    selected_threat_ids={x["id"] for x in projected_threats}

    projected_goals=[]
    for g in c["cybersecurity_goals"]:
        applicable=[t for t in g["threat_ids"] if t in selected_threat_ids]
        if not applicable:
            continue
        projected_goals.append({
            **g,
            "canonical_threat_ids":g["threat_ids"],
            "applicable_threat_ids":applicable,
            "canonical_asset_ids":g["asset_ids"],
            "applicable_asset_ids":sorted({threats[t]["asset_id"] for t in applicable}),
            "canonical_cal":g["expected_cal"],
            "target_product_cal":None,
            "target_product_cal_status":"UNASSESSED"
        })

    projected_claims=[]
    for cl in c["cybersecurity_claims"]:
        applicable=[t for t in cl["threat_ids"] if t in selected_threat_ids]
        if applicable:
            projected_claims.append({
                **cl,
                "canonical_threat_ids":cl["threat_ids"],
                "applicable_threat_ids":applicable,
                "target_product_claim":None,
                "target_product_claim_status":"UNASSESSED",
            })

    return {
        "schema_version":"cc-trace-reference-projection-1.1",
        "scope":"Canonical reference TARA applicability projection; not a product-specific/compliance TARA.",
        "active_functions":sorted(function_ids),
        "contexts":sorted(contexts),
        "assets":[
            {**assets[aid],"applicability":asset_annotations.get(aid)}
            for aid in sorted(selected_assets)
        ],
        "damage_scenarios":[damages[d] for d in sorted(projected_damage_union)],
        "threat_scenarios":projected_threats,
        "attack_paths":[paths[a] for a in sorted(selected_paths)],
        "cybersecurity_goals":projected_goals,
        "cybersecurity_claims":projected_claims,
        "risk_semantics":{
            "canonical_reference_risk":"Stored risk from the complete generic/reference Item in the final TARA report.",
            "target_product_risk":"Not inferred by applicability projection. Requires target-specific damage impact and attack-feasibility evidence.",
            "no_projected_risk_reason":"Narrowing function applicability alone is insufficient to claim a new product/reference risk treatment without explicitly re-performing the corresponding TARA inputs."
        },
        "note":"Canonical reference formal/test evidence is not copied as target-product verification evidence."
    }
