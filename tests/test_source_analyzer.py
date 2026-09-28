from __future__ import annotations

import json
import zipfile

import pytest

from cc_trace_kb.analyze import run_analysis
from cc_trace_kb.item_definition import collect_item_definition
from cc_trace_kb.source_analyzer import analyze_source, classify_function_semantics

class Feeder:
    def __init__(self, answers):
        self.answers=iter(answers)
    def __call__(self, prompt=""):
        return next(self.answers)

def test_conservative_semantic_mapping():
    assert classify_function_semantics("unlock")==["IF-01"]
    assert classify_function_semantics("start_charge")==["IF-05"]
    assert classify_function_semantics("start_climate")==["IF-04"]
    assert classify_function_semantics("remote_start")==["IF-02"]
    assert classify_function_semantics("open_trunk")==["IF-03"]
    assert classify_function_semantics("honk_horn")==["IF-06"]
    assert classify_function_semantics("enable_valet")==["IF-07"]
    assert classify_function_semantics("start")==[]
    assert classify_function_semantics("execute_action")==[]

def test_python_source_analysis_does_not_execute_target(tmp_path):
    sentinel=tmp_path/"SHOULD_NOT_EXIST"
    src=tmp_path/"client.py"
    code=(
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('executed')\n\n"
        "def unlock(vehicle_id):\n"
        "    status = 'pending'\n"
        "    return api.post('/unlock')\n\n"
        "def start_charge(vehicle_id):\n"
        "    return api.post('/charge/start')\n\n"
        "def start_climate(vehicle_id):\n"
        "    if vehicle.speed == 0:\n"
        "        return api.post('/climate/start')\n"
    )
    src.write_text(code,encoding="utf-8")

    ev=analyze_source(str(tmp_path))
    assert not sentinel.exists()
    ids={x["function_id"] for x in ev["function_candidates"]}
    assert {"IF-01","IF-04","IF-05"} <= ids
    assert ev["result_status_candidate"]["status"]=="CANDIDATE"
    assert ev["state_acceptance_candidate"]["status"]=="CANDIDATE"
    assert ev["scan_policy"]["target_code_executed"] is False
    assert ev["scan_policy"]["target_code_imported"] is False

def test_openapi_json_mapping(tmp_path):
    spec={
        "openapi":"3.0.0",
        "paths":{
            "/vehicle/{id}/lock":{
                "post":{"operationId":"lockVehicle","summary":"Lock vehicle"}
            },
            "/vehicle/{id}/charge":{
                "post":{"operationId":"startCharging","summary":"Start charging"}
            },
            "/vehicle/{id}/horn":{
                "post":{"operationId":"honkHorn","summary":"Horn"}
            }
        }
    }
    p=tmp_path/"openapi.json"
    p.write_text(json.dumps(spec),encoding="utf-8")
    ev=analyze_source(str(p))
    assert {x["function_id"] for x in ev["function_candidates"]}=={"IF-01","IF-05","IF-06"}

def test_openapi_yaml_mapping_without_yaml_dependency(tmp_path):
    p=tmp_path/"openapi.yaml"
    p.write_text(
        "openapi: 3.0.0\n"
        "paths:\n"
        "  /vehicle/{id}/climate:\n"
        "    post:\n"
        "      operationId: startClimate\n"
        "      summary: Start climate\n"
        "  /vehicle/{id}/trunk:\n"
        "    post:\n"
        "      operationId: openTrunk\n"
        "      summary: Open trunk\n",
        encoding="utf-8",
    )
    ev=analyze_source(str(p))
    assert {x["function_id"] for x in ev["function_candidates"]}=={"IF-03","IF-04"}

def test_zip_path_traversal_rejected(tmp_path):
    z=tmp_path/"bad.zip"
    with zipfile.ZipFile(z,"w") as zf:
        zf.writestr("../evil.py","def unlock(): pass")
    with pytest.raises(ValueError,match="Unsafe ZIP path"):
        analyze_source(str(z))

def test_source_suggestions_require_analyst_confirmation(tmp_path):
    (tmp_path/"client.py").write_text(
        "def unlock(vehicle_id):\n"
        "    status = 'pending'\n\n"
        "def start_charge(vehicle_id):\n"
        "    pass\n",
        encoding="utf-8",
    )
    ev=analyze_source(str(tmp_path))

    feed=Feeder([
        "",      # item name
        "y",     # use source function suggestions
        "1",     # reference architecture
        "n",     # result/status explicitly rejected
        "",      # state acceptance unknown
    ])
    item=collect_item_definition(
        source_evidence=ev,
        input_fn=feed,
        output_fn=lambda _:None,
    )
    assert item["item"]["function_ids"]==["IF-01","IF-05"]
    assert item["behavior"]["command_result_status"]["status"]=="NO"
    assert item["behavior"]["state_used_in_command_acceptance"]["status"]=="UNKNOWN"
    assert "RESULT_STATUS_PRESENT" not in item["derived_contexts"]

def test_source_analysis_writes_evidence_artifact(tmp_path):
    src=tmp_path/"src"
    src.mkdir()
    (src/"client.py").write_text("def unlock(vehicle_id):\n    pass\n",encoding="utf-8")
    ev=analyze_source(str(src))

    out=tmp_path/"out"
    feed=Feeder([
        "",      # name
        "y",     # accept proposed IF
        "1",     # reference
        "n",     # result
        "n",     # state
    ])
    result=run_analysis(
        output_dir=out,
        source_evidence=ev,
        input_fn=feed,
        output_fn=lambda _:None,
    )
    assert (out/"item_definition.json").is_file()
    assert (out/"tara.json").is_file()
    assert (out/"report.md").is_file()
    assert (out/"source_evidence.json").is_file()
    assert result["source_evidence"]==str(out/"source_evidence.json")
    report=(out/"report.md").read_text(encoding="utf-8")
    assert "Source Evidence" in report

def test_query_and_telemetry_do_not_activate_item_functions(tmp_path):
    (tmp_path/"client.py").write_text(
        "def get_charge_limit(vehicle_id):\n"
        "    return api.get('/vehicle/charge/limit')\n",
        encoding="utf-8",
    )
    ev=analyze_source(str(tmp_path))
    assert ev["function_candidates"]==[]
    assert ev["ambiguous_semantic_candidates"]==[]
    suppressed=ev["non_activating_semantic_evidence"]
    assert any(x["operation_role"]=="QUERY" and "IF-05" in x["semantic_hints"] for x in suppressed)


def test_openapi_get_status_is_query_not_command(tmp_path):
    spec={
        "openapi":"3.0.0",
        "paths":{
            "/vehicle/{id}/lock/status":{
                "get":{"operationId":"getLockStatus","summary":"Read lock status"}
            }
        },
    }
    p=tmp_path/"openapi.json"
    p.write_text(json.dumps(spec),encoding="utf-8")
    ev=analyze_source(str(p))
    assert ev["function_candidates"]==[]
    assert ev["ambiguous_semantic_candidates"]==[]
    assert ev["non_activating_semantic_evidence"][0]["reason"]=="NON_COMMAND_OPERATION"


def test_same_method_name_in_different_classes_does_not_merge_calls(tmp_path):
    (tmp_path/"client.py").write_text(
        "class A:\n"
        "    def execute_action(self, vehicle_id):\n"
        "        return helper()\n\n"
        "class B:\n"
        "    def execute_action(self, vehicle_id):\n"
        "        return start_charge(vehicle_id)\n",
        encoding="utf-8",
    )
    ev=analyze_source(str(tmp_path))
    cand=next(x for x in ev["function_candidates"] if x["function_id"]=="IF-05")
    names={x.get("qualified_name") for x in cand["evidence"]}
    assert names=={"B.execute_action"}


def test_test_and_example_sources_are_supporting_only(tmp_path):
    tests=tmp_path/"tests"
    tests.mkdir()
    (tests/"test_vehicle.py").write_text("def unlock(vehicle_id):\n    pass\n",encoding="utf-8")
    examples=tmp_path/"examples"
    examples.mkdir()
    (examples/"demo.py").write_text("def start_charge(vehicle_id):\n    pass\n",encoding="utf-8")
    ev=analyze_source(str(tmp_path))
    assert ev["function_candidates"]==[]
    assert ev["summary"]["supporting_files"]==2
    assert {x["reason"] for x in ev["non_activating_semantic_evidence"]}=={"SUPPORTING_SOURCE_ONLY"}


def test_keyword_fstring_http_url_and_state_subscript_are_observed(tmp_path):
    (tmp_path/"client.py").write_text(
        "import requests\n"
        "def remote_start(vehicle_id, state):\n"
        "    if state['speed'] == 0 and state.get('gear') == 'P':\n"
        "        return requests.post(url=f'/vehicle/{vehicle_id}/engine/start')\n",
        encoding="utf-8",
    )
    ev=analyze_source(str(tmp_path))
    cand=next(x for x in ev["function_candidates"] if x["function_id"]=="IF-02")
    assert any("/vehicle/{VAR}/engine/start" in x for x in next(
        f for f in ev["http_evidence"] if f.get("caller")=="remote_start"
    )["literal_args"])
    state=ev["state_acceptance_candidate"]
    assert state["status"]=="CANDIDATE"
    assert set(state["evidence"][0]["state_tokens"])=={"gear","speed"}


def test_manual_function_selection_is_not_recorded_as_source_accepted(tmp_path):
    (tmp_path/"client.py").write_text("def unlock(vehicle_id):\n    pass\n",encoding="utf-8")
    ev=analyze_source(str(tmp_path))
    feed=Feeder([
        "",
        "n",   # reject source proposal
        "5",   # manually select charging
        "1",   # reference architecture
        "n",
        "n",
    ])
    item=collect_item_definition(source_evidence=ev,input_fn=feed,output_fn=lambda _:None)
    assert item["item"]["function_ids"]==["IF-05"]
    assert item["source_evidence"]["accepted_function_ids"]==[]
    assert {x["decision"] for x in item["source_evidence"]["function_decisions"]}=={
        "REJECTED_SOURCE","MANUALLY_SELECTED"
    }
