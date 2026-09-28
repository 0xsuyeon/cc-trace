from cc_trace_kb.projection import project

def _ids(rows):
    return {x["id"] for x in rows}

def test_charging_projection_damage_scope_is_narrowed():
    p=project(["IF-05"],["REMOTE_COMMAND_PRESENT"])
    tids=_ids(p["threat_scenarios"])
    assert {"TS-13","TS-14","TS-15","TS-22","TS-23","TS-24","TS-25","TS-26","TS-27","TS-28","TS-29"} <= tids

    # Charging-only target must not emit access/propulsion/etc. damage scenarios.
    assert _ids(p["damage_scenarios"]) == {"DS-10","DS-11"}

    ts22=next(x for x in p["threat_scenarios"] if x["id"]=="TS-22")
    assert set(ts22["canonical_damage_ids"]) == {f"DS-{i:02d}" for i in range(1,16)}
    assert set(ts22["applicable_damage_ids"]) == {"DS-10","DS-11"}
    assert ts22["canonical_reference_risk"]==5
    assert ts22["target_product_risk"] is None
    assert "projected_reference_risk" not in ts22

def test_charging_result_projection_adds_only_result_damage():
    p=project(["IF-05"],["REMOTE_COMMAND_PRESENT","RESULT_STATUS_PRESENT"])
    assert _ids(p["damage_scenarios"]) == {"DS-10","DS-11","DS-16","DS-17"}
    assert {"TS-30","TS-31","TS-32","TS-33","TS-34"} <= _ids(p["threat_scenarios"])

def test_claim_projection_preserves_ts34_csc01():
    p=project(["IF-05"],["RESULT_STATUS_PRESENT"])
    assert len(p["cybersecurity_claims"])==1
    cl=p["cybersecurity_claims"][0]
    assert cl["id"]=="CSC-01"
    assert cl["applicable_threat_ids"]==["TS-34"]

def test_goal_projection_narrows_threat_membership():
    p=project(["IF-05"],["REMOTE_COMMAND_PRESENT"])
    csg1=next(x for x in p["cybersecurity_goals"] if x["id"]=="CSG-01")
    assert set(csg1["canonical_threat_ids"]) == {"TS-01","TS-04","TS-07","TS-10","TS-13","TS-16","TS-19","TS-25","TS-26"}
    assert set(csg1["applicable_threat_ids"]) == {"TS-13","TS-25","TS-26"}
    assert set(csg1["applicable_asset_ids"]) == {"AS-05","AS-09"}
    assert csg1["target_product_cal"] is None

def test_state_only_with_acceptance_context():
    p1=project(["IF-01"],["STATE_TELEMETRY_ONLY"])
    p2=project(["IF-01"],["STATE_USED_IN_COMMAND_ACCEPTANCE"])
    assert not {"TS-41","TS-42","TS-43"} & _ids(p1["threat_scenarios"])
    assert {"TS-41","TS-42","TS-43"} <= _ids(p2["threat_scenarios"])
    # State threat damage projection is limited to active access-control function.
    for tid in ("TS-41","TS-42"):
        row=next(x for x in p2["threat_scenarios"] if x["id"]==tid)
        assert set(row["applicable_damage_ids"])=={"DS-01","DS-02"}

def test_internal_reference_does_not_create_product_risk():
    p=project(["IF-03"],["INTERNAL_COMMAND_CHANNEL_OBSERVED","TARGET_CONTROLLER_OR_FW_OBSERVED"])
    assert {"TS-35","TS-36","TS-37","TS-38","TS-39","TS-40"} <= _ids(p["threat_scenarios"])
    assert all(x["target_product_risk_status"]=="UNASSESSED" for x in p["threat_scenarios"])

def test_unknown_function_rejected():
    import pytest
    with pytest.raises(ValueError):
        project(["IF-99"],[])

def test_unknown_context_rejected():
    import pytest
    with pytest.raises(ValueError):
        project(["IF-01"],["MAGIC_CONTEXT"])

def test_state_damage_scope_uses_only_state_dependent_functions():
    p=project(
        ["IF-01","IF-02"],
        ["STATE_USED_IN_COMMAND_ACCEPTANCE"],
        state_function_ids=["IF-02"],
    )
    for tid in ("TS-41","TS-42"):
        row=next(x for x in p["threat_scenarios"] if x["id"]==tid)
        assert set(row["applicable_damage_ids"])=={"DS-03","DS-04"}
