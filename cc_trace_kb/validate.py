from __future__ import annotations
import json
from collections import Counter
from pathlib import Path

from .loader import (
    load_canonical, load_method, load_mapping,
    canonical_sha256, expected_canonical_sha256, DOMAIN_ROOT
)
from .method import (
    attack_path_score, score_to_feasibility, aggregate_feasibility,
    aggregate_impacts, risk_by_dimension, final_risk, treatment_for_risk, cal_for
)

class ValidationError(RuntimeError):
    pass

def _index(items):
    return {x["id"]:x for x in items}

def _normalize_attack_method(method: dict) -> dict:
    """Normalize Method KB scoring tables to comparable score dictionaries."""
    ap=method["attack_potential"]
    out={}
    for key in ("ET","SE","KoIC","WoO","Eq"):
        out[key]=[int(x["score"]) for x in ap["factors"][key]["values"]]
    return {
        "ET":out["ET"],
        "SE":out["SE"],
        "KoIC":out["KoIC"],
        "WoO":out["WoO"],
        "Eq":out["Eq"],
        "score_to_feasibility":ap["score_to_feasibility"],
    }

def validate_canonical(raise_on_error: bool = True) -> dict:
    c=load_canonical()
    m=load_method()
    mapping=load_mapping()
    errors=[]
    checks=[]

    def check(name, ok, detail):
        ok=bool(ok)
        checks.append({"check":name,"pass":ok,"detail":detail})
        if not ok:
            errors.append(f"{name}: {detail}")

    # Hash integrity.
    actual=canonical_sha256()
    expected=expected_canonical_sha256()
    check("canonical_sha256",actual==expected,f"actual={actual}, expected={expected}")

    # Optional JSON Schema validation when jsonschema is available.
    try:
        import jsonschema
        schema=json.loads((DOMAIN_ROOT/"canonical_tara.schema.json").read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(c)
        check("json_schema_validation",True,"Draft 2020-12 schema PASS")
    except ImportError:
        check("json_schema_validation",False,"jsonschema runtime dependency is unavailable")
    except Exception as exc:
        check("json_schema_validation",False,str(exc))

    exp=c["expected_cardinality"]
    count_specs=[
        ("functions","functions"),("assets","assets"),("damage_scenarios","damage_scenarios"),
        ("threat_scenarios","threat_scenarios"),("attack_paths","attack_paths"),
        ("cybersecurity_goals","cybersecurity_goals"),("cybersecurity_claims","cybersecurity_claims")
    ]
    for exp_key, field in count_specs:
        check(f"count_{exp_key}",len(c[field])==exp[exp_key],len(c[field]))
    check("impact_cells",len(c["damage_scenarios"])*4==exp["impact_ratings"],len(c["damage_scenarios"])*4)
    check("risk_record_count",len(c["risk_records"])==exp["risk_values"],len(c["risk_records"]))
    check("treatment_count",len(c["treatments"])==exp["risk_values"],len(c["treatments"]))

    assets=_index(c["assets"])
    damages=_index(c["damage_scenarios"])
    threats=_index(c["threat_scenarios"])
    aps=_index(c["attack_paths"])
    risk={x["threat_id"]:x for x in c["risk_records"]}
    treatments={x["threat_id"]:x for x in c["treatments"]}
    functions=_index(c["functions"])
    goals=_index(c["cybersecurity_goals"])
    claims=_index(c["cybersecurity_claims"])

    # ID uniqueness.
    for label,items in [
        ("function",c["functions"]),("asset",c["assets"]),("damage",c["damage_scenarios"]),
        ("threat",c["threat_scenarios"]),("attack_path",c["attack_paths"]),
        ("goal",c["cybersecurity_goals"]),("claim",c["cybersecurity_claims"])
    ]:
        ids=[x["id"] for x in items]
        dup=[k for k,v in Counter(ids).items() if v>1]
        check(f"unique_{label}_ids",not dup,str(dup))

    # Referential integrity.
    check("threat_asset_refs",
          all(t["asset_id"] in assets for t in threats.values()),
          "all 43 threat asset references resolve")
    check("threat_properties_nonempty",
          all(bool(t["compromised_properties"]) for t in threats.values()),
          "all threats have >=1 compromised property")
    check("threat_attack_path_refs",
          all(t.get("attack_path_ids") and all(a in aps for a in t["attack_path_ids"]) for t in threats.values()),
          "all threats have >=1 valid attack path")
    check("risk_damage_refs",
          all(rr["risk_damage_ids"] and all(d in damages for d in rr["risk_damage_ids"]) for rr in risk.values()),
          "all 43 risk damage scopes resolve")
    check("threat_damage_vs_risk_damage",
          all(set(threats[tid]["damage_scope_expanded"])==set(rr["risk_damage_ids"]) for tid,rr in risk.items()),
          "threat table damage scope matches risk table damage scope 43/43")
    check("af_table_ap_links_match",
          all(set(t["attack_path_ids"])==set(t["attack_path_ids_from_af_table"]) for t in threats.values()),
          "Threat→AP mapping tables agree 43/43")

    # Function relations are canonical data, not code.
    fa=c["function_asset_links"]
    fd=c["function_damage_links"]
    check("function_asset_link_count",len(fa)==7 and len({x["function_id"] for x in fa})==7,"7/7")
    check("function_asset_link_refs",
          all(x["function_id"] in functions and x["asset_id"] in assets for x in fa),
          "all function→asset refs resolve")
    check("function_damage_link_count",len(fd)==7 and len({x["function_id"] for x in fd})==7,"7/7")
    check("function_damage_link_refs",
          all(x["function_id"] in functions and all(d in damages for d in x["damage_ids"]) for x in fd),
          "all function→damage refs resolve")

    # Conditional damage scope semantics.
    cross={"AS-08","AS-09","AS-11","AS-12"}
    check("cross_asset_damage_scope_typed",
          all(assets[a]["damage_scope"]["type"]=="FUNCTION_CONDITIONAL_SUBSET" for a in cross),
          "AS-08/09/11/12 are conditional subsets")
    check("state_asset_damage_scope_typed",
          assets["AS-13"]["damage_scope"]["type"]=="STATE_CONDITIONAL_SUBSET",
          "AS-13 is state-conditional")

    # Reference architecture graph.
    graph=c["reference_architecture"]
    node_ids={n["id"] for n in graph["nodes"]}
    check("architecture_node_count",len(node_ids)==14,"ITEM + 8 OE + 5 components")
    check("architecture_edge_refs",
          all(e["source"] in node_ids and e["target"] in node_ids for e in graph["edges"]),
          f"{len(graph['edges'])} edges resolve")
    oe_nodes={n["id"] for n in graph["nodes"] if n["type"]=="OPERATIONAL_ENVIRONMENT"}
    check("operational_environment_outside_item",
          all(next(n for n in graph["nodes"] if n["id"]==x)["boundary"]=="OUTSIDE_ITEM" for x in oe_nodes),
          "all OE nodes outside Item")
    component_nodes={n["id"] for n in graph["nodes"] if n["type"]=="LOGICAL_COMPONENT"}
    check("logical_components_inside_item",
          all(next(n for n in graph["nodes"] if n["id"]==x)["boundary"]=="ITEM_INTERNAL" for x in component_nodes),
          "all C-01..C-05 inside Item")

    # Attack path structured steps, score, AF.
    check("attack_path_steps_structured",
          all(len(ap["steps"])>=2 and all(s.lstrip()[0].isdigit() for s in ap["steps"]) for ap in aps.values()),
          "16/16 APs have multiple numbered steps")
    ap_score_ok=ap_af_ok=True
    for ap in aps.values():
        score=attack_path_score(ap)
        ap_score_ok &= score==ap["expected_score"]
        ap_af_ok &= score_to_feasibility(score,m)==ap["expected_feasibility"]
    check("ap_score_recompute",ap_score_ok,"16/16")
    check("ap_feasibility_recompute",ap_af_ok,"16/16")

    # Threat AF.
    threat_af_ok=True
    for t in threats.values():
        calc=aggregate_feasibility(aps[a]["expected_feasibility"] for a in t["attack_path_ids"])
        threat_af_ok &= calc==t["expected_attack_feasibility"]==risk[t["id"]]["attack_feasibility"]
    check("threat_af_recompute",threat_af_ok,"43/43")

    # Risk chain.
    impact_ok=risk_dim_ok=final_ok=True
    for tid,t in threats.items():
        rr=risk[tid]
        calc_imp=aggregate_impacts(damages[d] for d in rr["risk_damage_ids"])
        impact_ok &= calc_imp==rr["impact_vector"]
        calc_dims=risk_by_dimension(calc_imp,rr["attack_feasibility"],m)
        risk_dim_ok &= calc_dims==rr["risk_by_dimension"]
        final_ok &= final_risk(calc_dims)==rr["expected_final_risk"]
    check("impact_vector_recompute",impact_ok,"43/43")
    check("risk_dimension_recompute",risk_dim_ok,"43/43 × 4 dimensions")
    check("final_risk_recompute",final_ok,"43/43")

    # Treatment from JSON policy, not hardcoded.
    tr_ok=True
    for tid,rr in risk.items():
        calc=treatment_for_risk(rr["expected_final_risk"],m)
        tr=treatments[tid]
        tr_ok &= calc==tr["decision"] and tr["risk"]==rr["expected_final_risk"]
    check("treatment_recompute",tr_ok,"43/43 from treatment_policy.json")
    reduce={tid for tid,x in treatments.items() if x["decision"]=="REDUCE"}
    retain={tid for tid,x in treatments.items() if x["decision"]=="RETAIN"}
    check("reduce_count",len(reduce)==exp["reduce"],len(reduce))
    check("retain_count",len(retain)==exp["retain"],len(retain))

    # Goal/claim exactness.
    goal_threat_list=[t for g in c["cybersecurity_goals"] for t in g["threat_ids"]]
    goal_threats=set(goal_threat_list)
    check("reduce_goal_coverage",goal_threats==reduce,f"goal={len(goal_threats)}, reduce={len(reduce)}")
    check("goal_threat_no_duplicates",len(goal_threat_list)==len(goal_threats),f"{len(goal_threat_list)} memberships")
    goal_assets_ok=True
    goal_maxrisk_ok=True
    goal_cal_ok=True
    for g in c["cybersecurity_goals"]:
        expected_assets={threats[t]["asset_id"] for t in g["threat_ids"]}
        goal_assets_ok &= expected_assets==set(g["asset_ids"])
        goal_maxrisk_ok &= max(risk[t]["expected_final_risk"] for t in g["threat_ids"])==g["expected_max_risk"]
        goal_cal_ok &= cal_for(g["max_impact"],g["representative_attack_vector"],m)==g["expected_cal"]
    check("goal_asset_union",goal_assets_ok,"10/10")
    check("goal_max_risk",goal_maxrisk_ok,"10/10")
    check("goal_cal_recompute",goal_cal_ok,"10/10")

    claim_threat_list=[t for cl in c["cybersecurity_claims"] for t in cl["threat_ids"]]
    claim_threats=set(claim_threat_list)
    check("retain_claim_coverage",claim_threats==retain,f"claim={claim_threats}, retain={retain}")
    check("goal_claim_no_overlap",not(goal_threats & claim_threats),"no threat appears in both Goal and Claim")

    # Method KB ↔ final report snapshots.
    mr=c["method_reference_from_report"]
    check("method_risk_matrix_matches_report",
          m["risk_matrix"]["matrix"]=={k:v for k,v in mr["risk_matrix"].items() if k!="source"},
          "Method KB == final report Table 24")
    check("method_cal_matrix_matches_report",
          m["cal_matrix"]["matrix"]==mr["cal_matrix"],
          "Method KB == final report Table 28")
    method_policy=[
        {"min_risk":int(x["min_risk"]),"max_risk":int(x["max_risk"]),"decision":x["decision"]}
        for x in m["treatment_policy"]["rules"]
    ]
    report_policy=[
        {"min_risk":int(x["min_risk"]),"max_risk":int(x["max_risk"]),"decision":x["decision"]}
        for x in mr["treatment_policy"]["rules"]
    ]
    check("method_treatment_policy_matches_report",method_policy==report_policy,"Method KB == study-adopted report policy")

    ma=_normalize_attack_method(m)
    report_ap=mr["attack_potential"]
    report_scores={
        "ET":list(report_ap["factor_scores"]["ET"].values()),
        "SE":list(report_ap["factor_scores"]["SE"].values()),
        "KoIC":list(report_ap["factor_scores"]["KoIC"].values()),
        "WoO":list(report_ap["factor_scores"]["WoO"].values()),
        "Eq":list(report_ap["factor_scores"]["Eq"].values()),
        "score_to_feasibility":report_ap["score_to_feasibility"],
    }
    check("method_attack_potential_matches_report",ma==report_scores,"Method KB == final report Table 20")

    # Method selection is explicit: implement only the branches actually used by the final reference TARA.
    check(
        "selected_attack_feasibility_method",
        m["attack_potential"].get("selected_method")=="ATTACK_POTENTIAL"
        and m["attack_potential"].get("selected_by_reference_tara") is True,
        str(m["attack_potential"].get("selected_method"))
    )
    check(
        "selected_risk_method",
        m["risk_matrix"].get("selected_method")=="RISK_MATRIX"
        and m["risk_matrix"].get("selected_by_reference_tara") is True,
        str(m["risk_matrix"].get("selected_method"))
    )
    check(
        "unused_manual_alternatives_not_falsely_implemented",
        all(x.get("implemented") is False for x in m["attack_potential"].get("manual_alternatives",[]))
        and all(x.get("implemented") is False for x in m["risk_matrix"].get("manual_alternatives",[])),
        "CVSS/attack-vector/risk-formula alternatives are documented but not claimed as implemented"
    )

    # Impact-rating criteria knowledge from Korean manual Table 11.
    impact_method=m["impact_scale"]
    expected_levels={"NEGLIGIBLE","MODERATE","MAJOR","SEVERE"}
    expected_dims={"SAFETY","FINANCIAL","OPERATIONAL","PRIVACY"}
    criteria=impact_method.get("criteria",{})
    check(
        "impact_criteria_complete",
        set(criteria)==expected_levels
        and all(set(criteria[level])==expected_dims for level in expected_levels),
        "4 impact levels × 4 S/F/O/P criteria"
    )
    check(
        "impact_criteria_source_marked",
        impact_method.get("criteria_source",{}).get("table")=="표 11 영향 등급 평가 기준",
        str(impact_method.get("criteria_source"))
    )

    # Mapping KB references.
    taxonomy=mapping["taxonomy"]["intents"]
    function_rules=mapping["function_rules"]["rules"]
    contexts=mapping["context_rules"]["contexts"]
    check("mapping_function_refs",
          all(r["activate_function"] in functions for r in function_rules),
          "all semantic function mappings resolve")
    check("mapping_taxonomy_function_refs",
          all(x["function_id"] is None or x["function_id"] in functions for x in taxonomy),
          "taxonomy refs resolve")
    check("mapping_context_refs",
          all(all(a in assets for a in r["assets"]) and all(t in threats for t in r["threats"]) for r in contexts),
          "all context asset/threat refs resolve")
    state_rule=next(x for x in contexts if x["context"]=="STATE_USED_IN_COMMAND_ACCEPTANCE")
    telemetry_rule=next(x for x in contexts if x["context"]=="STATE_TELEMETRY_ONLY")
    check("state_activation_guard",
          state_rule["threats"]==["TS-41","TS-42","TS-43"] and telemetry_rule["threats"]==[],
          "telemetry-only does not activate state threats")

    # Workflow phase correctness.
    workflow=m["workflow"]["steps"]
    core=[x["id"] for x in workflow if x["phase"]=="CORE_TARA"]
    check("core_tara_ends_at_treatment",
          core[-1]=="RISK_TREATMENT_DECISION" and "CAL_DETERMINATION" not in core,
          f"core={core}")
    extension=[x["id"] for x in workflow if x["phase"]=="CONCEPT_EXTENSION"]
    check("concept_extension_contains_cal_goal_claim",
          extension==["CAL_DETERMINATION","CYBERSECURITY_GOAL_OR_CLAIM"],
          str(extension))

    # Verification coverage remains exactly 43.
    cov=[x["threat_id"] for x in c["verification_extension"]["threat_coverage"]]
    check("verification_coverage_43",
          len(cov)==43 and len(set(cov))==43 and set(cov)==set(threats),
          f"{len(cov)} rows")

    # Do not invent a defense/control catalog not present in source.
    sc=c["security_control_catalog"]
    check("no_invented_control_catalog",
          sc["status"]=="NOT_DEFINED_AS_COMPLETE_FIRST_CLASS_CATALOG_IN_CANONICAL_TARA_REPORT" and sc["controls"]==[],
          "control catalog intentionally empty/source-limited")

    result={"pass":not errors,"checks":checks,"errors":errors}
    if errors and raise_on_error:
        raise ValidationError("\n".join(errors))
    return result
