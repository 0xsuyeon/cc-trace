from __future__ import annotations

import json

from cc_trace_kb.analyze import analyze_item_definition, run_analysis
from cc_trace_kb.item_definition import collect_item_definition, contexts_from_item_definition

class Feeder:
    def __init__(self, answers):
        self.answers=iter(answers)
    def __call__(self, prompt=""):
        return next(self.answers)

def test_reference_architecture_interactive_item_definition():
    # Item name, functions, architecture mode, result/status, state acceptance
    feed=Feeder([
        "",          # default item name
        "1,4,5",     # IF-01, IF-04, IF-05
        "1",         # reference architecture
        "y",         # result/status present
        "",          # state acceptance unknown
    ])
    out=[]
    item=collect_item_definition(input_fn=feed,output_fn=out.append)

    assert item["item"]["function_ids"]==["IF-01","IF-04","IF-05"]
    assert item["architecture"]["mode"]=="REFERENCE"
    assert len(item["architecture"]["components"])==5
    assert item["behavior"]["command_result_status"]["status"]=="YES"
    assert item["behavior"]["state_used_in_command_acceptance"]["status"]=="UNKNOWN"
    # Unknown state-acceptance must not appear as a confirmed reference interaction.
    assert all(x.get("id")!="OE-06" for x in item["architecture"]["external_interfaces"])
    assert not any(
        e.get("source")=="OE-06" and e.get("target")=="C-03"
        for e in item["architecture"]["connections"]
    )
    # Charging is selected, so charging environment remains relevant.
    assert any(x.get("id")=="OE-08" for x in item["architecture"]["external_interfaces"])

    contexts=contexts_from_item_definition(item)
    assert "REMOTE_COMMAND_PRESENT" in contexts
    assert "INTERNAL_COMMAND_CHANNEL_OBSERVED" in contexts
    assert "TARGET_CONTROLLER_OR_FW_OBSERVED" in contexts
    assert "RESULT_STATUS_PRESENT" in contexts
    assert "STATE_USED_IN_COMMAND_ACCEPTANCE" not in contexts

def test_direct_architecture_interactive_item_definition():
    feed=Feeder([
        "My Remote Item",
        "1,5",       # IF-01, IF-05
        "2",         # direct architecture

        "3",         # component count
        "TCU", "external command receiver", "1",
        "Gateway", "internal routing", "4",
        "BCM", "door target controller", "5",

        "2",         # connection count
        "1", "2", "Ethernet", "accepted command",
        "2", "3", "CAN", "door command",

        "1",         # external interface count
        "Backend", "1", "Cellular/HTTPS",

        "n",         # no command result/status
        "y",         # state used
        "speed,gear",
        "1,2",       # state applies to both selected functions
        "Vehicle State ECU",
        "Gateway",
    ])
    item=collect_item_definition(input_fn=feed,output_fn=lambda _:None)

    assert item["architecture"]["mode"]=="DIRECT"
    assert len(item["architecture"]["components"])==3
    assert len(item["architecture"]["connections"])==2
    assert len(item["architecture"]["external_interfaces"])==1
    assert item["behavior"]["state_used_in_command_acceptance"]["states"]==["speed","gear"]

    contexts=contexts_from_item_definition(item)
    assert set(contexts)=={
        "REMOTE_COMMAND_PRESENT",
        "INTERNAL_COMMAND_CHANNEL_OBSERVED",
        "TARGET_CONTROLLER_OR_FW_OBSERVED",
        "STATE_USED_IN_COMMAND_ACCEPTANCE",
    }

def test_unknown_facts_remain_unknown_and_do_not_activate_contexts():
    feed=Feeder([
        "",
        "1",
        "2",
        "1",
        "TCU", "", "1",
        "0",         # no known internal connections
        "0",         # no known external interfaces
        "",          # result unknown
        "",          # state unknown
    ])
    item=collect_item_definition(input_fn=feed,output_fn=lambda _:None)
    contexts=contexts_from_item_definition(item)

    assert contexts==["REMOTE_COMMAND_PRESENT"]
    assert len(item["unknowns"])==4

def test_analyze_item_definition_calls_existing_projection():
    feed=Feeder([
        "",
        "5",         # charging
        "1",         # reference
        "y",         # result
        "n",         # state not used
    ])
    item=collect_item_definition(input_fn=feed,output_fn=lambda _:None)
    normalized,tara=analyze_item_definition(item)

    assert normalized["item"]["function_ids"]==["IF-05"]
    # Function damage plus result/status damages.
    assert {x["id"] for x in tara["damage_scenarios"]}=={"DS-10","DS-11","DS-16","DS-17"}
    assert any(x["id"]=="CSC-01" for x in tara["cybersecurity_claims"])
    assert all(x["target_product_risk_status"]=="UNASSESSED" for x in tara["threat_scenarios"])

def test_run_analysis_writes_only_three_primary_outputs(tmp_path):
    feed=Feeder([
        "Demo",
        "1",
        "1",
        "n",
        "n",
    ])
    result=run_analysis(
        output_dir=tmp_path,
        input_fn=feed,
        output_fn=lambda _:None,
    )

    assert (tmp_path/"item_definition.json").is_file()
    assert (tmp_path/"tara.json").is_file()
    assert (tmp_path/"report.md").is_file()
    assert sorted(p.name for p in tmp_path.iterdir())==[
        "item_definition.json","report.md","tara.json"
    ]
    report=(tmp_path/"report.md").read_text(encoding="utf-8")
    assert "Reference TARA Applicability" in report or "applicability draft" in report
    assert "target_product_risk" in report

def test_rederived_contexts_ignore_manually_injected_context():
    feed=Feeder([
        "",
        "1",
        "2",
        "1",
        "TCU", "", "1",
        "0",
        "0",
        "n",
        "n",
    ])
    item=collect_item_definition(input_fn=feed,output_fn=lambda _:None)
    item["derived_contexts"]=["STATE_USED_IN_COMMAND_ACCEPTANCE","MAGIC"]
    contexts=contexts_from_item_definition(item)
    assert contexts==["REMOTE_COMMAND_PRESENT"]


def test_reference_architecture_filters_unselected_charging_environment():
    feed=Feeder([
        "",
        "1",         # access only
        "1",         # reference
        "n",
        "n",
    ])
    item=collect_item_definition(input_fn=feed,output_fn=lambda _:None)
    assert all(x.get("id")!="OE-08" for x in item["architecture"]["external_interfaces"])
    assert not any(e.get("source")=="OE-08" for e in item["architecture"]["connections"])

def test_direct_unreachable_target_does_not_activate_target_context():
    item={
        "schema_version":"cc-trace-item-definition-1.0",
        "item":{"function_ids":["IF-01"]},
        "architecture":{
            "mode":"DIRECT",
            "components":[
                {"id":"UC-01","component_type":"OTHER"},
                {"id":"UC-02","component_type":"TARGET_CONTROLLER"},
            ],
            "connections":[{"id":"CONN-01","source":"UC-01","target":"UC-01"}],
            "external_interfaces":[],
        },
        "behavior":{
            "command_result_status":{"status":"NO"},
            "state_used_in_command_acceptance":{"status":"NO","function_ids":[]},
        },
    }
    contexts=contexts_from_item_definition(item)
    assert contexts==["REMOTE_COMMAND_PRESENT"]


def test_direct_dangling_connection_is_rejected():
    import pytest
    from cc_trace_kb.item_definition import validate_item_definition
    item={
        "schema_version":"cc-trace-item-definition-1.0",
        "item":{"function_ids":["IF-01"]},
        "architecture":{
            "mode":"DIRECT",
            "components":[{"id":"UC-01","component_type":"EXTERNAL_COMM_ENDPOINT"}],
            "connections":[{"id":"CONN-01","source":"BAD","target":"UC-01"}],
            "external_interfaces":[],
        },
        "behavior":{
            "command_result_status":{"status":"NO"},
            "state_used_in_command_acceptance":{"status":"NO","function_ids":[]},
        },
    }
    with pytest.raises(ValueError,match="source/target"):
        validate_item_definition(item)

class FakeInteractiveClient:
    provider="fake"
    model="fake-input-assist-1"

    def __init__(self):
        self.calls=[]

    def interpret(self,task,user_text,context=None):
        self.calls.append((task,user_text,context or {}))
        if task=="FUNCTION_SELECTION":
            return {
                "status":"YES",
                "function_ids":["IF-01","IF-02"],
                "states":[],
                "reason":"문 잠금과 원격 시동 기능이 명시되었습니다.",
            }
        if task=="RESULT_STATUS":
            return {
                "status":"YES",
                "function_ids":[],
                "states":[],
                "reason":"action id와 후속 상태 조회가 명시되었습니다.",
            }
        if task=="STATE_ACCEPTANCE":
            return {
                "status":"YES",
                "function_ids":["IF-02"],
                "states":["speed","gear"],
                "reason":"원격 시동 수락 전에 속도와 기어 조건을 확인한다고 설명했습니다.",
            }
        raise AssertionError(task)


def test_interactive_llm_assists_natural_language_without_generating_tara_facts():
    client=FakeInteractiveClient()
    feed=Feeder([
        "",  # default item name
        "문 잠금하고 원격 시동을 지원해요", "",  # function description + accept interpretation
        "1",  # reference architecture
        "명령을 보내면 action id가 나오고 나중에 상태를 조회할 수 있어요", "",  # result + accept
        "원격 시동은 속도 0이고 기어 P인지 확인한 뒤 허용해요", "",  # state + accept
    ])
    out=[]
    item=collect_item_definition(
        interactive_client=client,
        input_fn=feed,
        output_fn=out.append,
    )

    assert item["item"]["function_ids"]==["IF-01","IF-02"]
    assert item["behavior"]["command_result_status"]["status"]=="YES"
    state=item["behavior"]["state_used_in_command_acceptance"]
    assert state["status"]=="YES"
    assert state["states"]==["speed","gear"]
    assert state["function_ids"]==["IF-02"]
    assert len(item["input_assistance"]["interpretations"])==3
    assert [x[0] for x in client.calls]==[
        "FUNCTION_SELECTION","RESULT_STATUS","STATE_ACCEPTANCE"
    ]
    joined="\n".join(out)
    assert "분석할 시스템 정보를 순서대로 입력해 주세요." in joined
    assert "Asset/Threat/Risk는 직접 입력하지 않습니다" not in joined
    assert "분석 범위:" not in joined
    assert "원격명령을 보낸 뒤 성공·실패·처리 중 등의 결과" in joined


def test_direct_yes_no_answers_do_not_call_interactive_llm():
    client=FakeInteractiveClient()
    feed=Feeder([
        "",
        "1",
        "1",
        "y",
        "n",
    ])
    item=collect_item_definition(
        interactive_client=client,
        input_fn=feed,
        output_fn=lambda _:None,
    )
    assert item["behavior"]["command_result_status"]["status"]=="YES"
    assert item["behavior"]["state_used_in_command_acceptance"]["status"]=="NO"
    assert client.calls==[]
    assert item["input_assistance"]["interpretations"]==[]
