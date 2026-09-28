from cc_trace_kb.loader import load_method, load_canonical
from cc_trace_kb.method import treatment_for_risk, attack_path_score, score_to_feasibility

def test_treatment_is_data_driven():
    m=load_method()
    assert treatment_for_risk(1,m)=="RETAIN"
    assert treatment_for_risk(2,m)=="REDUCE"
    assert treatment_for_risk(5,m)=="REDUCE"

def test_ap03_recomputes_to_medium():
    c=load_canonical(); m=load_method()
    ap=next(x for x in c["attack_paths"] if x["id"]=="AP-03")
    assert attack_path_score(ap)==17
    assert score_to_feasibility(17,m)=="MEDIUM"

def test_manual_equipment_discrepancy_is_documented():
    m=load_method()
    assert "use 9" in m["attack_potential"]["source_note"] or "use 9" in m["attack_potential"]["source_note"].lower()


def test_impact_criteria_are_complete_and_source_grounded():
    m=load_method()
    imp=m["impact_scale"]
    assert imp["criteria_source"]["table"]=="표 11 영향 등급 평가 기준"
    assert set(imp["criteria"])=={"NEGLIGIBLE","MODERATE","MAJOR","SEVERE"}
    for row in imp["criteria"].values():
        assert set(row)=={"SAFETY","FINANCIAL","OPERATIONAL","PRIVACY"}
    assert imp["criteria"]["SEVERE"]["SAFETY"]=="치명적 상해 (생존 불확실)"
    assert imp["criteria"]["NEGLIGIBLE"]["PRIVACY"]=="무시 가능 (신원 특정 가능성 희박, 비민감정보)"

def test_selected_methods_match_reference_tara():
    m=load_method()
    assert m["attack_potential"]["selected_method"]=="ATTACK_POTENTIAL"
    assert m["attack_potential"]["selected_by_reference_tara"] is True
    assert m["risk_matrix"]["selected_method"]=="RISK_MATRIX"
    assert m["risk_matrix"]["selected_by_reference_tara"] is True
    assert all(x["implemented"] is False for x in m["attack_potential"]["manual_alternatives"])
    assert all(x["implemented"] is False for x in m["risk_matrix"]["manual_alternatives"])
