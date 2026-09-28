from cc_trace_kb.validate import validate_canonical
from cc_trace_kb.loader import load_canonical, load_method

def test_full_validation():
    r=validate_canonical()
    assert r["pass"] is True
    assert all(x["pass"] for x in r["checks"])

def test_cardinality():
    c=load_canonical()
    assert len(c["functions"])==7
    assert len(c["assets"])==13
    assert len(c["damage_scenarios"])==17
    assert len(c["threat_scenarios"])==43
    assert len(c["attack_paths"])==16
    assert len(c["cybersecurity_goals"])==10
    assert len(c["cybersecurity_claims"])==1

def test_ts34_exact_property_and_claim():
    c=load_canonical()
    t=next(x for x in c["threat_scenarios"] if x["id"]=="TS-34")
    assert set(t["compromised_properties"])=={"INTEGRITY","AVAILABILITY"}
    cl=c["cybersecurity_claims"][0]
    assert cl["id"]=="CSC-01" and cl["threat_ids"]==["TS-34"]

def test_attack_path_steps_are_structured():
    c=load_canonical()
    for ap in c["attack_paths"]:
        assert len(ap["steps"]) >= 2
        assert all(step.split(")",1)[0].isdigit() for step in ap["steps"])

def test_item_boundary_ontology():
    m=load_method()
    es=m["entity_schema"]["entities"]
    assert "OperationalEnvironment" not in es["Item"]["contains"]
    assert "OperationalEnvironment" in es["Item"]["interacts_with"]
    assert "LogicalComponent" in es["Item"]["contains"]

def test_workflow_phase_boundary():
    m=load_method()
    core=[x["id"] for x in m["workflow"]["steps"] if x["phase"]=="CORE_TARA"]
    ext=[x["id"] for x in m["workflow"]["steps"] if x["phase"]=="CONCEPT_EXTENSION"]
    assert core[-1]=="RISK_TREATMENT_DECISION"
    assert ext==["CAL_DETERMINATION","CYBERSECURITY_GOAL_OR_CLAIM"]

def test_no_invented_control_catalog():
    c=load_canonical()
    assert c["security_control_catalog"]["controls"] == []
    assert "NOT_DEFINED" in c["security_control_catalog"]["status"]
