from __future__ import annotations

import json

import pytest

from cc_trace_kb.semantic_mapper import (
    AnthropicMessagesSemanticClient,
    GeminiGenerateContentSemanticClient,
    GroqResponsesSemanticClient,
    OpenAIResponsesSemanticClient,
    SemanticMappingError,
    build_semantic_client,
    enrich_source_evidence_with_llm,
    normalize_provider,
    resolve_model,
    validate_semantic_output,
)
from cc_trace_kb.source_analyzer import analyze_source

class FakeSemanticClient:
    provider="fake"
    model="fake-semantic-1"

    def __init__(self,mapping):
        self.mapping=mapping
        self.calls=0

    def classify(self,candidates,taxonomy):
        self.calls+=1
        assert taxonomy
        return {
            "mappings":[
                {
                    "candidate_id":c["candidate_id"],
                    "function_id":self.mapping.get(c["candidate_id"],"UNKNOWN"),
                    "reason":"Bound only to supplied candidate metadata.",
                }
                for c in candidates
            ]
        }

def _ambiguous_fixture(tmp_path):
    p=tmp_path/"client.py"
    p.write_text(
        "def execute_action(vehicle_id):\n"
        "    return api.post('/api/v1/rcstrt')\n\n"
        "def helper_format(value):\n"
        "    return str(value)\n",
        encoding="utf-8",
    )
    return analyze_source(str(tmp_path))

def test_source_analyzer_emits_only_action_like_ambiguous_candidates(tmp_path):
    ev=_ambiguous_fixture(tmp_path)
    assert ev["summary"]["ambiguous_semantic_candidates"]==1
    cand=ev["ambiguous_semantic_candidates"][0]
    assert cand["symbol"]=="execute_action"
    assert cand["source_fact_id"].startswith("SF-")
    assert "helper_format" not in json.dumps(ev["ambiguous_semantic_candidates"])

def test_llm_fallback_maps_ambiguous_candidate_without_creating_tara(tmp_path):
    ev=_ambiguous_fixture(tmp_path)
    cid=ev["ambiguous_semantic_candidates"][0]["candidate_id"]
    client=FakeSemanticClient({cid:"IF-02"})
    enriched,artifact=enrich_source_evidence_with_llm(ev,client)

    assert client.calls==1
    assert artifact["status"]=="COMPLETED"
    assert artifact["policy"]["creates_tara_entities"] is False
    assert artifact["policy"]["requires_analyst_confirmation"] is True
    assert artifact["policy"]["source_bodies_sent"] is False

    row=next(x for x in enriched["function_candidates"] if x["function_id"]=="IF-02")
    assert "LLM" in row["mapping_methods"]
    assert row["status"]=="CANDIDATE"

def test_unknown_llm_mapping_does_not_activate_function(tmp_path):
    ev=_ambiguous_fixture(tmp_path)
    cid=ev["ambiguous_semantic_candidates"][0]["candidate_id"]
    client=FakeSemanticClient({cid:"UNKNOWN"})
    enriched,artifact=enrich_source_evidence_with_llm(ev,client)

    assert all("LLM" not in x.get("mapping_methods",[]) for x in enriched["function_candidates"])
    assert artifact["mappings"][0]["function_id"]=="UNKNOWN"
    assert enriched["summary"]["llm_unknown_candidates"]==1

def test_llm_not_called_when_no_ambiguous_candidates(tmp_path):
    (tmp_path/"client.py").write_text(
        "def unlock(vehicle_id):\n"
        "    return api.post('/unlock')\n",
        encoding="utf-8",
    )
    ev=analyze_source(str(tmp_path))
    assert ev["ambiguous_semantic_candidates"]==[]

    client=FakeSemanticClient({})
    enriched,artifact=enrich_source_evidence_with_llm(ev,client)
    assert client.calls==0
    assert artifact["status"]=="NO_AMBIGUOUS_CANDIDATES"
    assert enriched["function_candidates"][0]["mapping_methods"]==["DETERMINISTIC"]

def test_evidence_gate_rejects_fabricated_candidate_id(tmp_path):
    ev=_ambiguous_fixture(tmp_path)
    raw={
        "mappings":[
            {"candidate_id":"AMB-99999","function_id":"IF-01","reason":"invented"}
        ]
    }
    accepted,rejected=validate_semantic_output(raw,ev["ambiguous_semantic_candidates"])
    assert accepted==[]
    reasons={x["reason"] for x in rejected}
    assert "UNKNOWN_CANDIDATE_ID" in reasons
    assert "MISSING_FROM_LLM_OUTPUT" in reasons

def test_evidence_gate_rejects_outside_taxonomy(tmp_path):
    ev=_ambiguous_fixture(tmp_path)
    cid=ev["ambiguous_semantic_candidates"][0]["candidate_id"]
    raw={
        "mappings":[
            {"candidate_id":cid,"function_id":"IF-99","reason":"invalid"}
        ]
    }
    accepted,rejected=validate_semantic_output(raw,ev["ambiguous_semantic_candidates"])
    assert accepted==[]
    assert any(x["reason"]=="OUTSIDE_ALLOWED_TAXONOMY" for x in rejected)

def test_openai_client_uses_responses_structured_output_without_network(tmp_path):
    ev=_ambiguous_fixture(tmp_path)
    candidates=ev["ambiguous_semantic_candidates"]

    captured={}
    def transport(payload,headers,timeout):
        captured["payload"]=payload
        captured["headers"]=headers
        captured["timeout"]=timeout
        cid=candidates[0]["candidate_id"]
        result={
            "mappings":[
                {"candidate_id":cid,"function_id":"IF-02","reason":"remote-start semantic context"}
            ]
        }
        return {
            "output":[
                {
                    "type":"message",
                    "content":[
                        {"type":"output_text","text":json.dumps(result)}
                    ]
                }
            ]
        }

    client=OpenAIResponsesSemanticClient(
        model="test-model",
        api_key="not-real",
        timeout=7,
        transport=transport,
    )
    raw=client.classify(candidates,[
        {"function_id":"IF-02","intent":"PROPULSION_MOBILITY","description":"Remote propulsion."}
    ])

    assert raw["mappings"][0]["function_id"]=="IF-02"
    fmt=captured["payload"]["text"]["format"]
    assert fmt["type"]=="json_schema"
    assert fmt["strict"] is True
    assert captured["payload"]["model"]=="test-model"
    assert captured["timeout"]==7

    # Raw source bodies must not be present in the LLM request.
    request_text=json.dumps(captured["payload"],ensure_ascii=False)
    assert "return api.post" not in request_text

def test_openai_requires_api_key_when_real_transport_is_used(tmp_path,monkeypatch):
    ev=_ambiguous_fixture(tmp_path)
    monkeypatch.delenv("OPENAI_API_KEY",raising=False)
    client=OpenAIResponsesSemanticClient(model="test-model",api_key=None)
    with pytest.raises(SemanticMappingError,match="OPENAI_API_KEY"):
        client.classify(ev["ambiguous_semantic_candidates"],[])


def test_llm_candidate_count_is_bounded():
    candidates=[
        {
            "candidate_id":f"AMB-{i:05d}",
            "source_fact_id":f"SF-{i:05d}",
            "fact_type":"FUNCTION",
            "symbol":f"execute_action_{i}",
            "parameters":["vehicle_id"],
            "callees":[],
            "http_literals":["/action"],
            "file":"client.py",
            "line":i,
        }
        for i in range(1,102)
    ]
    source={
        "ambiguous_semantic_candidates":candidates,
        "function_candidates":[],
        "summary":{
            "function_candidates":0,
            "ambiguous_semantic_candidates":101,
        },
    }
    client=FakeSemanticClient({})
    enriched,artifact=enrich_source_evidence_with_llm(source,client)
    assert client.calls==1
    assert len(artifact["mappings"])==100
    assert any(
        x.get("candidate_id")=="AMB-00101" and x["reason"]=="LLM_CANDIDATE_LIMIT"
        for x in artifact["rejections"]
    )


def test_result_and_state_clues_survive_ambiguous_function_selection(tmp_path):
    (tmp_path/"client.py").write_text(
        "def execute_action(vehicle_id):\n"
        "    status = 'pending'\n"
        "    if vehicle.speed == 0:\n"
        "        return api.post('/api/v1/rcstrt')\n",
        encoding="utf-8",
    )
    ev=analyze_source(str(tmp_path))
    assert ev["summary"]["ambiguous_semantic_candidates"]==1
    assert ev["result_status_candidate"]["status"]=="CANDIDATE"
    assert ev["state_acceptance_candidate"]["status"]=="CANDIDATE"


def test_llm_enriched_analysis_writes_semantic_mapping_artifact(tmp_path):
    from cc_trace_kb.analyze import run_analysis

    ev=_ambiguous_fixture(tmp_path)
    cid=ev["ambiguous_semantic_candidates"][0]["candidate_id"]
    client=FakeSemanticClient({cid:"IF-02"})
    enriched,artifact=enrich_source_evidence_with_llm(ev,client)

    class Feeder:
        def __init__(self,answers):
            self.answers=iter(answers)
        def __call__(self,prompt=""):
            return next(self.answers)

    out=tmp_path/"analysis"
    feed=Feeder([
        "",      # item name
        "y",     # accept LLM-proposed IF-02
        "1",     # reference architecture
        "n",     # result/status
        "n",     # state acceptance
    ])
    result=run_analysis(
        output_dir=out,
        source_evidence=enriched,
        input_fn=feed,
        output_fn=lambda _:None,
    )

    assert (out/"semantic_mapping.json").is_file()
    stored=json.loads((out/"semantic_mapping.json").read_text(encoding="utf-8"))
    assert stored["model"]=="fake-semantic-1"
    assert stored["mappings"][0]["function_id"]=="IF-02"

    item=json.loads((out/"item_definition.json").read_text(encoding="utf-8"))
    assert item["source_evidence"]["semantic_mapping"]["status"]=="COMPLETED"
    assert result["semantic_mapping"]==str(out/"semantic_mapping.json")


def test_provider_aliases_and_default_models(monkeypatch):
    for key in (
        "CC_TRACE_LLM_MODEL","OPENAI_MODEL","ANTHROPIC_MODEL","GROQ_MODEL","GEMINI_MODEL"
    ):
        monkeypatch.delenv(key,raising=False)

    assert normalize_provider("gpt")=="openai"
    assert normalize_provider("openai")=="openai"
    assert normalize_provider("claude")=="anthropic"
    assert normalize_provider("anthropic")=="anthropic"
    assert normalize_provider("groq")=="groq"
    assert normalize_provider("gemini")=="gemini"
    assert normalize_provider("google")=="gemini"

    assert resolve_model("gpt")=="gpt-5.6-luna"
    assert resolve_model("claude")=="claude-sonnet-5"
    assert resolve_model("groq")=="openai/gpt-oss-20b"
    assert resolve_model("gemini")=="gemini-3.8-flash"

def test_provider_specific_model_env(monkeypatch):
    monkeypatch.delenv("CC_TRACE_LLM_MODEL",raising=False)
    monkeypatch.setenv("OPENAI_MODEL","gpt-test")
    monkeypatch.setenv("ANTHROPIC_MODEL","claude-test")
    monkeypatch.setenv("GROQ_MODEL","groq-test")
    monkeypatch.setenv("GEMINI_MODEL","gemini-test")
    assert resolve_model("openai")=="gpt-test"
    assert resolve_model("anthropic")=="claude-test"
    assert resolve_model("groq")=="groq-test"
    assert resolve_model("gemini")=="gemini-test"

def test_build_semantic_client_by_provider(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY","x")
    monkeypatch.setenv("ANTHROPIC_API_KEY","x")
    monkeypatch.setenv("GROQ_API_KEY","x")
    monkeypatch.setenv("GEMINI_API_KEY","x")

    assert build_semantic_client("gpt",model="m1").provider=="openai"
    assert build_semantic_client("claude",model="m2").provider=="anthropic"
    assert build_semantic_client("groq",model="m3").provider=="groq"
    assert build_semantic_client("gemini",model="m4").provider=="gemini"
    assert build_semantic_client("google",model="m5").provider=="gemini"

def test_anthropic_client_uses_messages_structured_output_without_network(tmp_path):
    ev=_ambiguous_fixture(tmp_path)
    candidates=ev["ambiguous_semantic_candidates"]

    captured={}
    def transport(payload,headers,timeout):
        captured["payload"]=payload
        captured["headers"]=headers
        captured["timeout"]=timeout
        cid=candidates[0]["candidate_id"]
        result={
            "mappings":[
                {"candidate_id":cid,"function_id":"IF-02","reason":"remote-start semantic context"}
            ]
        }
        return {
            "id":"msg_test",
            "type":"message",
            "content":[{"type":"text","text":json.dumps(result)}],
        }

    client=AnthropicMessagesSemanticClient(
        model="claude-test",
        api_key="not-real",
        timeout=9,
        transport=transport,
    )
    raw=client.classify(candidates,[
        {"function_id":"IF-02","intent":"PROPULSION_MOBILITY","description":"Remote propulsion."}
    ])

    assert raw["mappings"][0]["function_id"]=="IF-02"
    assert captured["payload"]["model"]=="claude-test"
    assert captured["payload"]["output_config"]["format"]["type"]=="json_schema"
    assert captured["headers"]["x-api-key"]=="not-real"
    assert captured["headers"]["anthropic-version"]=="2023-06-01"
    assert captured["timeout"]==9
    request_text=json.dumps(captured["payload"],ensure_ascii=False)
    assert "return api.post" not in request_text

def test_anthropic_requires_api_key_when_real_transport_is_used(tmp_path,monkeypatch):
    ev=_ambiguous_fixture(tmp_path)
    monkeypatch.delenv("ANTHROPIC_API_KEY",raising=False)
    client=AnthropicMessagesSemanticClient(model="claude-test",api_key=None)
    with pytest.raises(SemanticMappingError,match="ANTHROPIC_API_KEY"):
        client.classify(ev["ambiguous_semantic_candidates"],[])

def test_groq_client_uses_responses_structured_output_without_network(tmp_path):
    ev=_ambiguous_fixture(tmp_path)
    candidates=ev["ambiguous_semantic_candidates"]

    captured={}
    def transport(payload,headers,timeout):
        captured["payload"]=payload
        captured["headers"]=headers
        captured["timeout"]=timeout
        cid=candidates[0]["candidate_id"]
        result={
            "mappings":[
                {"candidate_id":cid,"function_id":"IF-02","reason":"remote-start semantic context"}
            ]
        }
        return {
            "output":[
                {
                    "type":"message",
                    "content":[{"type":"output_text","text":json.dumps(result)}],
                }
            ]
        }

    client=GroqResponsesSemanticClient(
        model="openai/gpt-oss-20b",
        api_key="not-real",
        timeout=11,
        transport=transport,
    )
    raw=client.classify(candidates,[
        {"function_id":"IF-02","intent":"PROPULSION_MOBILITY","description":"Remote propulsion."}
    ])

    assert raw["mappings"][0]["function_id"]=="IF-02"
    fmt=captured["payload"]["text"]["format"]
    assert fmt["type"]=="json_schema"
    assert fmt["strict"] is True
    assert captured["payload"]["model"]=="openai/gpt-oss-20b"
    assert captured["headers"]["Authorization"]=="Bearer not-real"
    assert captured["timeout"]==11
    request_text=json.dumps(captured["payload"],ensure_ascii=False)
    assert "return api.post" not in request_text

def test_groq_requires_api_key_when_real_transport_is_used(tmp_path,monkeypatch):
    ev=_ambiguous_fixture(tmp_path)
    monkeypatch.delenv("GROQ_API_KEY",raising=False)
    client=GroqResponsesSemanticClient(model="openai/gpt-oss-20b",api_key=None)
    with pytest.raises(SemanticMappingError,match="GROQ_API_KEY"):
        client.classify(ev["ambiguous_semantic_candidates"],[])

def test_invalid_duplicate_row_does_not_suppress_later_valid_mapping():
    from cc_trace_kb.semantic_mapper import validate_semantic_output
    candidates=[{
        "candidate_id":"AMB-00001",
        "source_fact_id":"SF-00001",
        "fact_type":"FUNCTION",
        "symbol":"execute_action",
    }]
    raw={"mappings":[
        {"candidate_id":"AMB-00001","function_id":"IF-99","reason":"bad"},
        {"candidate_id":"AMB-00001","function_id":"IF-01","reason":"valid mapping"},
    ]}
    accepted,rejected=validate_semantic_output(raw,candidates)
    assert [x["function_id"] for x in accepted]==["IF-01"]
    assert any(x["reason"]=="OUTSIDE_ALLOWED_TAXONOMY" for x in rejected)


def test_openai_client_interprets_interactive_text_with_structured_output():
    captured={}
    def transport(payload,headers,timeout):
        captured["payload"]=payload
        result={
            "status":"YES",
            "function_ids":["IF-02"],
            "states":["speed","gear"],
            "reason":"The user explicitly ties speed and gear to remote-start acceptance.",
        }
        return {"output_text":json.dumps(result)}

    client=OpenAIResponsesSemanticClient(
        model="test-model",
        api_key="not-real",
        transport=transport,
    )
    result=client.interpret(
        "STATE_ACCEPTANCE",
        "원격 시동 전에 speed 0, gear P인지 확인합니다.",
        {"allowed_function_ids":["IF-01","IF-02"]},
    )
    assert result["status"]=="YES"
    assert result["function_ids"]==["IF-02"]
    assert result["states"]==["speed","gear"]
    fmt=captured["payload"]["text"]["format"]
    assert fmt["type"]=="json_schema"
    assert fmt["strict"] is True


def test_anthropic_client_interprets_interactive_text_with_structured_output():
    captured={}
    def transport(payload,headers,timeout):
        captured["payload"]=payload
        result={
            "status":"YES",
            "function_ids":[],
            "states":[],
            "reason":"The command returns a transaction status.",
        }
        return {"content":[{"type":"text","text":json.dumps(result)}]}

    client=AnthropicMessagesSemanticClient(
        model="test-model",
        api_key="not-real",
        transport=transport,
    )
    result=client.interpret(
        "RESULT_STATUS",
        "명령 뒤 transaction status를 확인할 수 있습니다.",
        {},
    )
    assert result["status"]=="YES"
    assert captured["payload"]["output_config"]["format"]["type"]=="json_schema"


def test_groq_client_interprets_interactive_text_with_structured_output():
    captured={}
    def transport(payload,headers,timeout):
        captured["payload"]=payload
        result={
            "status":"YES",
            "function_ids":["IF-01","IF-05"],
            "states":[],
            "reason":"Door access and charging controls are explicit.",
        }
        return {"output_text":json.dumps(result)}

    client=GroqResponsesSemanticClient(
        model="test-model",
        api_key="not-real",
        transport=transport,
    )
    result=client.interpret(
        "FUNCTION_SELECTION",
        "문 잠금/해제와 충전 시작/중지를 지원합니다.",
        {"allowed_function_ids":["IF-01","IF-05"]},
    )
    assert result["function_ids"]==["IF-01","IF-05"]
    assert captured["payload"]["text"]["format"]["strict"] is True


def test_gemini_client_uses_generate_content_structured_output_without_network(tmp_path):
    ev=_ambiguous_fixture(tmp_path)
    candidates=ev["ambiguous_semantic_candidates"]

    captured={}
    def transport(payload,headers,timeout):
        captured["payload"]=payload
        captured["headers"]=headers
        captured["timeout"]=timeout
        cid=candidates[0]["candidate_id"]
        result={
            "mappings":[
                {"candidate_id":cid,"function_id":"IF-02","reason":"remote-start semantic context"}
            ]
        }
        return {
            "candidates":[{
                "content":{"parts":[{"text":json.dumps(result)}]}
            }]
        }

    client=GeminiGenerateContentSemanticClient(
        model="gemini-test",
        api_key="not-real",
        timeout=13,
        transport=transport,
    )
    raw=client.classify(candidates,[
        {"function_id":"IF-02","intent":"PROPULSION_MOBILITY","description":"Remote propulsion."}
    ])

    assert raw["mappings"][0]["function_id"]=="IF-02"
    assert client.endpoint.endswith("/gemini-test:generateContent")
    cfg=captured["payload"]["generationConfig"]
    assert cfg["responseMimeType"]=="application/json"
    assert cfg["responseJsonSchema"]["type"]=="object"
    assert captured["headers"]["x-goog-api-key"]=="not-real"
    assert captured["timeout"]==13
    request_text=json.dumps(captured["payload"],ensure_ascii=False)
    assert "return api.post" not in request_text


def test_gemini_requires_api_key_when_real_transport_is_used(tmp_path,monkeypatch):
    ev=_ambiguous_fixture(tmp_path)
    monkeypatch.delenv("GEMINI_API_KEY",raising=False)
    client=GeminiGenerateContentSemanticClient(model="gemini-test",api_key=None)
    with pytest.raises(SemanticMappingError,match="GEMINI_API_KEY"):
        client.classify(ev["ambiguous_semantic_candidates"],[])


def test_gemini_client_interprets_interactive_text_with_structured_output():
    captured={}
    def transport(payload,headers,timeout):
        captured["payload"]=payload
        result={
            "status":"YES",
            "function_ids":["IF-02"],
            "states":["speed","gear"],
            "reason":"The user explicitly ties speed and gear to remote-start acceptance.",
        }
        return {
            "candidates":[{
                "content":{"parts":[{"text":json.dumps(result)}]}
            }]
        }

    client=GeminiGenerateContentSemanticClient(
        model="gemini-test",
        api_key="not-real",
        transport=transport,
    )
    result=client.interpret(
        "STATE_ACCEPTANCE",
        "원격 시동 전에 speed 0, gear P인지 확인합니다.",
        {"allowed_function_ids":["IF-01","IF-02"]},
    )
    assert result["status"]=="YES"
    assert result["function_ids"]==["IF-02"]
    assert result["states"]==["speed","gear"]
    cfg=captured["payload"]["generationConfig"]
    assert cfg["responseMimeType"]=="application/json"
    # Gemini structured-output subset does not advertise uniqueItems; local validation still deduplicates.
    assert "uniqueItems" not in json.dumps(cfg["responseJsonSchema"])


def test_gemini_batches_large_candidate_sets_and_uses_low_thinking():
    candidates=[{
        "candidate_id":f"AMB-{i:05d}",
        "source_fact_id":f"SF-{i:05d}",
        "fact_type":"FUNCTION",
        "symbol":f"execute_action_{i}",
        "parameters":[],
        "callees":[],
        "http_literals":[],
        "file":"client.py",
        "line":i,
    } for i in range(1,26)]
    calls=[]
    def transport(payload,headers,timeout):
        calls.append(payload)
        prompt=json.loads(payload["contents"][0]["parts"][0]["text"])
        rows=[{
            "candidate_id":c["candidate_id"],
            "function_id":"UNKNOWN",
            "reason":"Insufficient evidence.",
        } for c in prompt["candidates"]]
        return {"candidates":[{"content":{"parts":[{"text":json.dumps({"mappings":rows})}]}}]}

    client=GeminiGenerateContentSemanticClient(
        model="gemini-3.8-flash",
        api_key="not-real",
        timeout=60,
        transport=transport,
    )
    raw=client.classify(candidates,[])
    assert len(calls)==3
    assert [len(json.loads(x["contents"][0]["parts"][0]["text"])["candidates"]) for x in calls]==[12,12,1]
    assert all(x["generationConfig"]["thinkingConfig"]["thinkingLevel"]=="low" for x in calls)
    assert len(raw["mappings"])==25
