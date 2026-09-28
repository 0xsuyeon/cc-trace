from __future__ import annotations

from copy import deepcopy
from typing import Callable

from .loader import load_canonical
from .semantic_mapper import SemanticMappingError

YES = {"y","yes","예","네","ㅇ","1"}
NO = {"n","no","아니오","아니요","아니","2"}
UNKNOWN = {"u","unknown","모름","모르겠음","3",""}

COMPONENT_TYPES = {
    "1": "EXTERNAL_COMM_ENDPOINT",
    "2": "COMMAND_HANDLER",
    "3": "COMMAND_DECISION",
    "4": "GATEWAY_ROUTER",
    "5": "TARGET_CONTROLLER",
    "6": "OTHER",
}

def _ask_choice(
    prompt: str,
    allowed: set[str],
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> str:
    while True:
        value=input_fn(prompt).strip()
        if value in allowed:
            return value
        output_fn(f"잘못된 입력입니다. 가능한 값: {', '.join(sorted(allowed))}")

def _ask_yes_no_unknown(
    prompt: str,
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> str:
    while True:
        raw=input_fn(prompt).strip().lower()
        if raw in YES:
            return "YES"
        if raw in NO:
            return "NO"
        if raw in UNKNOWN:
            return "UNKNOWN"
        output_fn("예(y) / 아니오(n) / 모름(Enter 또는 u) 중 하나를 입력해 주세요.")

def _confirm_default_yes(
    prompt: str = "이대로 적용할까요? [Y/n]: ",
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> bool:
    while True:
        raw=input_fn(prompt).strip().lower()
        if raw in {"", "y", "yes", "예", "네", "ㅇ", "1"}:
            return True
        if raw in {"n", "no", "아니오", "아니요", "아니", "2"}:
            return False
        output_fn("예(y) 또는 아니오(n)를 입력해 주세요.")

def _interpret_user_description(
    client,
    *,
    task: str,
    text: str,
    context: dict | None,
    input_fn: Callable[[str], str],
    output_fn: Callable[[str], None],
) -> dict | None:
    try:
        result=client.interpret(task,text,context or {})
    except (SemanticMappingError,AttributeError) as exc:
        output_fn(f"입력 내용을 해석하지 못했습니다: {exc}")
        return None

    output_fn("입력 내용을 다음과 같이 해석했습니다.")
    if task=="FUNCTION_SELECTION":
        fids=result.get("function_ids") or []
        output_fn("  → 기능: " + (", ".join(fids) if fids else "확인 필요"))
    elif task=="RESULT_STATUS":
        labels={"YES":"예","NO":"아니오","UNKNOWN":"모름"}
        output_fn(f"  → 명령 처리 결과 확인: {labels.get(result.get('status'),'모름')}")
    elif task=="STATE_ACCEPTANCE":
        labels={"YES":"예","NO":"아니오","UNKNOWN":"모름"}
        output_fn(f"  → 차량 상태를 수락/거부 판단에 사용: {labels.get(result.get('status'),'모름')}")
        if result.get("states"):
            output_fn("  → 상태: " + ", ".join(result["states"]))
        if result.get("function_ids"):
            output_fn("  → 적용 기능: " + ", ".join(result["function_ids"]))
    if result.get("reason"):
        output_fn(f"  근거: {result['reason']}")
    if not _confirm_default_yes(input_fn=input_fn,output_fn=output_fn):
        return None
    return result

def _ask_yes_no_unknown_with_assist(
    prompt: str,
    *,
    task: str,
    interactive_client=None,
    context: dict | None = None,
    assistance_records: list[dict] | None = None,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> tuple[str,dict | None]:
    while True:
        raw=input_fn(prompt).strip()
        lowered=raw.lower()
        if lowered in YES:
            return "YES",None
        if lowered in NO:
            return "NO",None
        if lowered in UNKNOWN:
            return "UNKNOWN",None
        if interactive_client is None:
            output_fn("예(y) / 아니오(n) / 모름(Enter 또는 u) 중 하나를 입력해 주세요.")
            continue
        interpreted=_interpret_user_description(
            interactive_client,
            task=task,
            text=raw,
            context=context,
            input_fn=input_fn,
            output_fn=output_fn,
        )
        if interpreted is None:
            continue
        if assistance_records is not None:
            assistance_records.append({
                "task":task,
                "status":interpreted.get("status"),
                "function_ids":interpreted.get("function_ids") or [],
                "states":interpreted.get("states") or [],
                "reason":interpreted.get("reason"),
                "accepted":True,
            })
        return interpreted["status"],interpreted

def _ask_positive_int(
    prompt: str,
    *,
    min_value: int = 0,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> int:
    while True:
        raw=input_fn(prompt).strip()
        try:
            value=int(raw)
        except ValueError:
            output_fn("정수를 입력해 주세요.")
            continue
        if value < min_value:
            output_fn(f"{min_value} 이상의 값을 입력해 주세요.")
            continue
        return value

def _select_functions(
    *,
    source_evidence: dict | None = None,
    interactive_client=None,
    assistance_records: list[dict] | None = None,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> tuple[list[str], list[dict]]:
    c=load_canonical()
    functions=c["functions"]
    by_id={x["id"]:x for x in functions}

    proposed=[]
    if source_evidence:
        proposed=sorted(
            x["function_id"] for x in source_evidence.get("function_candidates",[])
            if x["function_id"] in by_id
        )
        if proposed:
            output_fn("")
            output_fn("[Source Analyzer] 코드/API에서 다음 원격 기능 후보를 찾았습니다.")
            for fid in proposed:
                rec=next(x for x in source_evidence["function_candidates"] if x["function_id"]==fid)
                sample=rec["evidence"][0] if rec.get("evidence") else {}
                label=by_id[fid]["name_ko"]
                where=sample.get("qualified_name") or sample.get("name") or sample.get("operation_id") or sample.get("path") or "evidence"
                methods="/".join(rec.get("mapping_methods") or ["UNKNOWN"])
                output_fn(
                    f"  - {fid} {label}: {where} "
                    f"({rec['evidence_count']} evidence, {methods})"
                )
            use=_ask_yes_no_unknown(
                "이 기능 후보를 그대로 사용합니까? 예(y) / 아니오(n): ",
                input_fn=input_fn,
                output_fn=output_fn,
            )
            if use=="YES":
                return proposed, [
                    {"function_id":fid,"source_proposed":True,"decision":"ACCEPTED_SOURCE"}
                    for fid in proposed
                ]

    output_fn("")
    output_fn("[1/4] 분석 대상이 지원하는 원격 차량 기능을 선택하세요.")
    for idx,f in enumerate(functions, start=1):
        output_fn(f"  {idx}. {f['name_ko']} ({f['id']})")

    while True:
        prompt=(
            "선택 (예: 1,4,5) 또는 지원 기능을 자연어로 설명: "
            if interactive_client is not None
            else "선택 (예: 1,4,5): "
        )
        raw=input_fn(prompt).strip()
        nums=None
        try:
            parsed=sorted({int(x.strip()) for x in raw.split(",") if x.strip()})
            if parsed and all(1 <= n <= len(functions) for n in parsed):
                nums=parsed
        except ValueError:
            nums=None

        decision_kind="MANUALLY_SELECTED"
        if nums is not None:
            selected=[functions[n-1]["id"] for n in nums]
        elif interactive_client is not None and raw:
            taxonomy=[
                {
                    "function_id":f["id"],
                    "name_ko":f["name_ko"],
                    "name_en":f["name_en"],
                    "description":f.get("description") or f.get("description_ko") or "",
                }
                for f in functions
            ]
            interpreted=_interpret_user_description(
                interactive_client,
                task="FUNCTION_SELECTION",
                text=raw,
                context={"taxonomy":taxonomy,"allowed_function_ids":[f["id"] for f in functions]},
                input_fn=input_fn,
                output_fn=output_fn,
            )
            if interpreted is None or not interpreted.get("function_ids"):
                output_fn("기능을 특정하기 어렵습니다. 번호로 선택하거나 조금 더 구체적으로 설명해 주세요.")
                continue
            selected=interpreted["function_ids"]
            decision_kind="LLM_INTERPRETED_USER_INPUT"
            if assistance_records is not None:
                assistance_records.append({
                    "task":"FUNCTION_SELECTION",
                    "status":interpreted.get("status"),
                    "function_ids":selected,
                    "states":[],
                    "reason":interpreted.get("reason"),
                    "accepted":True,
                })
        else:
            output_fn(f"1~{len(functions)} 범위에서 하나 이상 선택해 주세요.")
            continue

        decisions=[]
        if source_evidence and proposed:
            decisions.extend(
                {"function_id":fid,"source_proposed":True,"decision":"REJECTED_SOURCE"}
                for fid in proposed
            )
        decisions.extend(
            {
                "function_id":fid,
                "source_proposed":fid in proposed,
                "decision":decision_kind,
            }
            for fid in selected
        )
        return selected, decisions

def _reference_architecture() -> dict:
    c=load_canonical()
    graph=deepcopy(c["reference_architecture"])
    components=[
        {
            "id":x["id"],
            "name":x["name_en"],
            "name_ko":x["name_ko"],
            "role":x["role"],
            "component_type":{
                "C-01":"EXTERNAL_COMM_ENDPOINT",
                "C-02":"COMMAND_HANDLER",
                "C-03":"COMMAND_DECISION",
                "C-04":"GATEWAY_ROUTER",
                "C-05":"TARGET_CONTROLLER",
            }[x["id"]],
            "basis":"REFERENCE",
        }
        for x in c["logical_components"]
    ]
    return {
        "mode":"REFERENCE",
        "basis":"CC_TRACE_CANONICAL_REFERENCE",
        "components":components,
        "connections":deepcopy(graph["edges"]),
        "external_interfaces":deepcopy(c["operational_environment"]),
        "note":"Logical reference architecture. Not an OEM-specific ECU/network topology.",
    }

def _collect_direct_architecture(
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> dict:
    output_fn("")
    output_fn("직접 입력은 TARA 결과를 쓰는 단계가 아닙니다.")
    output_fn("차량 내부 Component, 연결, 외부 Interface만 입력합니다. 모르는 값은 비워둘 수 있습니다.")

    count=_ask_positive_int(
        "내부 Component 수: ",
        min_value=1,
        input_fn=input_fn,
        output_fn=output_fn,
    )
    components=[]
    for i in range(1,count+1):
        output_fn(f"\nComponent {i}/{count}")
        while True:
            name=input_fn("  이름: ").strip()
            if name:
                break
            output_fn("  Component 이름은 비워둘 수 없습니다.")
        role=input_fn("  역할/설명 (선택): ").strip() or None
        output_fn("  유형: 1) 외부통신 종단  2) 명령수신/처리  3) 수락판단  4) Gateway/Router  5) Target Controller  6) 기타")
        type_key=_ask_choice(
            "  선택: ",
            set(COMPONENT_TYPES),
            input_fn=input_fn,
            output_fn=output_fn,
        )
        components.append({
            "id":f"UC-{i:02d}",
            "name":name,
            "role":role,
            "component_type":COMPONENT_TYPES[type_key],
            "basis":"USER_CONFIRMED",
        })

    by_num={str(i):components[i-1]["id"] for i in range(1,len(components)+1)}
    connections=[]
    conn_count=_ask_positive_int(
        "\n원격명령 경로에 해당하는 내부 Component 간 연결 수 (모르면 0): ",
        min_value=0,
        input_fn=input_fn,
        output_fn=output_fn,
    )
    for i in range(1,conn_count+1):
        output_fn(f"\nConnection {i}/{conn_count}")
        for idx,comp in enumerate(components, start=1):
            output_fn(f"  {idx}. {comp['name']}")
        frm=_ask_choice("  From 번호: ", set(by_num), input_fn=input_fn, output_fn=output_fn)
        to=_ask_choice("  To 번호: ", set(by_num), input_fn=input_fn, output_fn=output_fn)
        protocol=input_fn("  Protocol/Interface (선택, 모르면 Enter): ").strip() or None
        description=input_fn("  설명 (선택): ").strip() or None
        connections.append({
            "id":f"CONN-{i:02d}",
            "source":by_num[frm],
            "target":by_num[to],
            "protocol":protocol,
            "description":description,
            "basis":"USER_CONFIRMED",
        })

    external_interfaces=[]
    ext_count=_ask_positive_int(
        "\n외부 시스템/환경과의 연결 수 (모르면 0): ",
        min_value=0,
        input_fn=input_fn,
        output_fn=output_fn,
    )
    for i in range(1,ext_count+1):
        output_fn(f"\nExternal Interface {i}/{ext_count}")
        external_name=input_fn("  외부 대상 (예: Backend, Mobile App, Cellular Network): ").strip()
        while not external_name:
            output_fn("  외부 대상 이름은 비워둘 수 없습니다.")
            external_name=input_fn("  외부 대상: ").strip()
        for idx,comp in enumerate(components, start=1):
            output_fn(f"  {idx}. {comp['name']}")
        internal=_ask_choice("  연결되는 내부 Component 번호: ", set(by_num), input_fn=input_fn, output_fn=output_fn)
        protocol=input_fn("  Protocol/Interface (선택, 모르면 Enter): ").strip() or None
        external_interfaces.append({
            "id":f"UEX-{i:02d}",
            "external_entity":external_name,
            "internal_component_id":by_num[internal],
            "protocol":protocol,
            "basis":"USER_CONFIRMED",
        })

    return {
        "mode":"DIRECT",
        "basis":"USER_CONFIRMED",
        "components":components,
        "connections":connections,
        "external_interfaces":external_interfaces,
    }

def _direct_reachability(architecture: dict) -> dict:
    components=architecture.get("components") or []
    connections=architecture.get("connections") or []
    external_interfaces=architecture.get("external_interfaces") or []
    component_ids={c.get("id") for c in components}
    roots={
        ext.get("internal_component_id") for ext in external_interfaces
        if ext.get("internal_component_id") in component_ids
    }
    roots.update(
        c.get("id") for c in components
        if c.get("component_type")=="EXTERNAL_COMM_ENDPOINT"
    )
    adjacency={cid:set() for cid in component_ids}
    for edge in connections:
        src=edge.get("source")
        dst=edge.get("target")
        if src in adjacency and dst in component_ids:
            adjacency[src].add(dst)

    reachable=set(roots)
    stack=list(roots)
    while stack:
        cur=stack.pop()
        for nxt in adjacency.get(cur,()):
            if nxt not in reachable:
                reachable.add(nxt)
                stack.append(nxt)

    reachable_edges=[
        edge for edge in connections
        if edge.get("source") in reachable
        and edge.get("target") in reachable
        and edge.get("source") != edge.get("target")
    ]
    targets={
        c.get("id") for c in components
        if c.get("component_type")=="TARGET_CONTROLLER"
    }
    return {
        "entry_component_ids":sorted(x for x in roots if x),
        "reachable_component_ids":sorted(x for x in reachable if x),
        "has_reachable_internal_connection":bool(reachable_edges),
        "reachable_target_controller_ids":sorted(targets & reachable),
    }

def _derive_contexts(item_definition: dict) -> tuple[list[str], dict]:
    contexts=["REMOTE_COMMAND_PRESENT"]
    basis={
        "REMOTE_COMMAND_PRESENT":"DERIVED_FROM_SELECTED_REMOTE_FUNCTIONS"
    }

    arch=item_definition["architecture"]
    if arch["mode"]=="REFERENCE":
        contexts.extend([
            "INTERNAL_COMMAND_CHANNEL_OBSERVED",
            "TARGET_CONTROLLER_OR_FW_OBSERVED",
        ])
        basis["INTERNAL_COMMAND_CHANNEL_OBSERVED"]="REFERENCE_ARCHITECTURE"
        basis["TARGET_CONTROLLER_OR_FW_OBSERVED"]="REFERENCE_ARCHITECTURE"
    else:
        reach=_direct_reachability(arch)
        if reach["has_reachable_internal_connection"]:
            contexts.append("INTERNAL_COMMAND_CHANNEL_OBSERVED")
            basis["INTERNAL_COMMAND_CHANNEL_OBSERVED"]="USER_CONFIRMED_REACHABLE_REMOTE_COMMAND_CONNECTION"
        if reach["reachable_target_controller_ids"]:
            contexts.append("TARGET_CONTROLLER_OR_FW_OBSERVED")
            basis["TARGET_CONTROLLER_OR_FW_OBSERVED"]="USER_CONFIRMED_REACHABLE_TARGET_CONTROLLER"

    result_status=item_definition["behavior"]["command_result_status"]
    if result_status["status"]=="YES":
        contexts.append("RESULT_STATUS_PRESENT")
        basis["RESULT_STATUS_PRESENT"]="USER_CONFIRMED"

    state=item_definition["behavior"]["state_used_in_command_acceptance"]
    if state["status"]=="YES":
        contexts.append("STATE_USED_IN_COMMAND_ACCEPTANCE")
        basis["STATE_USED_IN_COMMAND_ACCEPTANCE"]="USER_CONFIRMED"

    return sorted(set(contexts)), basis

def collect_item_definition(
    *,
    source_evidence: dict | None = None,
    interactive_client=None,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    show_intro: bool = True,
) -> dict:
    c=load_canonical()

    if show_intro:
        output_fn("CC-TRACE Interactive TARA Analysis")
        output_fn("분석할 시스템 정보를 순서대로 입력해 주세요.")
        output_fn("모르는 항목은 Enter를 누르면 됩니다.")
    if interactive_client is not None:
        output_fn(
            f"입력 보조: {getattr(interactive_client,'provider','LLM')} / "
            f"{getattr(interactive_client,'model','')}"
        )

    assistance_records=[]

    name=input_fn(
        "\nItem 이름 (Enter = Connected-Car Remote Vehicle Function Control): "
    ).strip() or "Connected-Car Remote Vehicle Function Control"

    functions,function_decisions=_select_functions(
        source_evidence=source_evidence,
        interactive_client=interactive_client,
        assistance_records=assistance_records,
        input_fn=input_fn,
        output_fn=output_fn,
    )

    output_fn("")
    output_fn("[2/4] 차량 내부 구조 입력 방식")
    output_fn("  1. CC-TRACE Reference Architecture 사용")
    output_fn("  2. 직접 입력")
    mode=_ask_choice("선택: ", {"1","2"}, input_fn=input_fn, output_fn=output_fn)
    architecture = (
        _reference_architecture()
        if mode=="1"
        else _collect_direct_architecture(input_fn=input_fn, output_fn=output_fn)
    )

    output_fn("")
    if source_evidence and source_evidence.get("result_status_candidate",{}).get("status")=="CANDIDATE":
        ev=source_evidence["result_status_candidate"].get("evidence",[])
        output_fn(f"[Source Analyzer] result/status 관련 코드 토큰을 {len(ev)}건 관찰했습니다.")
        output_fn("이것은 후보 근거일 뿐, 차량 측 처리 결과 제공을 자동 확정하지 않습니다.")
    output_fn("[3/4] 원격명령을 보낸 뒤 성공·실패·처리 중 등의 결과를 확인할 수 있습니까?")
    result_prompt=(
        "예(y) / 아니오(n) / 모름(Enter), 또는 상황을 설명: "
        if interactive_client is not None
        else "예(y) / 아니오(n) / 모름(Enter): "
    )
    result_status,result_interpretation=_ask_yes_no_unknown_with_assist(
        result_prompt,
        task="RESULT_STATUS",
        interactive_client=interactive_client,
        context={},
        assistance_records=assistance_records,
        input_fn=input_fn,
        output_fn=output_fn,
    )

    output_fn("")
    if source_evidence and source_evidence.get("state_acceptance_candidate",{}).get("status")=="CANDIDATE":
        ev=source_evidence["state_acceptance_candidate"].get("evidence",[])
        output_fn(f"[Source Analyzer] 상태 조건문 후보를 {len(ev)}건 관찰했습니다.")
        output_fn("소스의 상태 조건만으로 차량 측 command-acceptance를 확정하지 않습니다.")
    output_fn("[4/4] 원격명령을 허용할지 결정할 때 차량 상태(속도, 기어, 점화, 충전 상태 등)를 확인합니까?")
    state_prompt=(
        "예(y) / 아니오(n) / 모름(Enter), 또는 상황을 설명: "
        if interactive_client is not None
        else "예(y) / 아니오(n) / 모름(Enter): "
    )
    state_status,state_interpretation=_ask_yes_no_unknown_with_assist(
        state_prompt,
        task="STATE_ACCEPTANCE",
        interactive_client=interactive_client,
        context={
            "allowed_function_ids":functions,
            "active_functions":[
                {"function_id":x["id"],"name_ko":x["name_ko"],"name_en":x["name_en"]}
                for x in c["functions"] if x["id"] in functions
            ],
        },
        assistance_records=assistance_records,
        input_fn=input_fn,
        output_fn=output_fn,
    )
    state_details={
        "status":state_status,
        "states":list((state_interpretation or {}).get("states") or []),
        "function_ids":list((state_interpretation or {}).get("function_ids") or []),
        "provider_component":None,
        "decision_component":None,
    }
    if state_status=="YES":
        if not state_details["states"]:
            raw_states=input_fn(
                "사용되는 상태 이름 (쉼표 구분, 예: speed,gear / 모르면 Enter): "
            ).strip()
            if raw_states:
                state_details["states"]=[x.strip() for x in raw_states.split(",") if x.strip()]
        if len(functions)==1:
            state_details["function_ids"]=list(functions)
        elif not state_details["function_ids"]:
            output_fn("상태 조건이 실제 수락/거부 판단에 적용되는 기능을 선택하세요.")
            selected_rows=[x for x in c["functions"] if x["id"] in functions]
            by_num={str(i):row["id"] for i,row in enumerate(selected_rows,start=1)}
            for i,row in enumerate(selected_rows,start=1):
                output_fn(f"  {i}. {row['name_ko']} ({row['id']})")
            while True:
                raw=input_fn("선택 (예: 1,2): ").strip()
                try:
                    nums=sorted({int(x.strip()) for x in raw.split(",") if x.strip()})
                except ValueError:
                    output_fn("번호를 쉼표로 구분해 입력해 주세요.")
                    continue
                if not nums or any(str(n) not in by_num for n in nums):
                    output_fn(f"1~{len(selected_rows)} 범위에서 하나 이상 선택해 주세요.")
                    continue
                state_details["function_ids"]=[by_num[str(n)] for n in nums]
                break
        if architecture["mode"]=="DIRECT":
            state_details["provider_component"]=input_fn(
                "상태를 제공하는 Component/외부 Item (선택): "
            ).strip() or None
            state_details["decision_component"]=input_fn(
                "상태를 이용해 수락/거부를 판단하는 Component (선택): "
            ).strip() or None

    # Adapt the generic reference architecture to confirmed Item facts.
    # Do not show state/charging operational-environment edges as if they were target facts
    # when the corresponding condition/function is absent or unknown.
    if architecture["mode"]=="REFERENCE":
        if state_status!="YES":
            architecture["connections"]=[
                e for e in architecture["connections"]
                if not (e.get("source")=="OE-06" and e.get("target")=="C-03")
            ]
            architecture["external_interfaces"]=[
                e for e in architecture["external_interfaces"]
                if e.get("id")!="OE-06"
            ]
        if "IF-05" not in functions:
            architecture["connections"]=[
                e for e in architecture["connections"]
                if not (e.get("source")=="OE-08" and e.get("target")=="ITEM-01")
            ]
            architecture["external_interfaces"]=[
                e for e in architecture["external_interfaces"]
                if e.get("id")!="OE-08"
            ]

    item={
        "schema_version":"cc-trace-item-definition-1.0",
        "item":{
            "name":name,
            "domain":"CONNECTED_CAR_REMOTE_VEHICLE_FUNCTION_CONTROL",
            "boundary":{
                "definition":"Vehicle-side E/E elements that receive, process, route, execute/reject externally requested remote vehicle-function commands.",
                "basis":"CC_TRACE_DOMAIN_FIXED",
            },
            "function_ids":functions,
        },
        "architecture":architecture,
        "operational_environment_basis":"REFERENCE" if architecture["mode"]=="REFERENCE" else "USER_INPUT",
        "behavior":{
            "command_result_status":{"status":result_status},
            "state_used_in_command_acceptance":state_details,
        },
        "assumptions":[],
        "unknowns":[],
        "input_assistance":(
            {
                "provider":getattr(interactive_client,"provider",None),
                "model":getattr(interactive_client,"model",None),
                "interpretations":assistance_records,
            }
            if interactive_client is not None
            else None
        ),
        "source_evidence":{
            "present":bool(source_evidence),
            "manifest":source_evidence.get("manifest") if source_evidence else None,
            "summary":source_evidence.get("summary") if source_evidence else None,
            "semantic_mapping":source_evidence.get("semantic_mapping") if source_evidence else None,
            "function_decisions":function_decisions if source_evidence else [],
            "accepted_function_ids":[
                x["function_id"] for x in function_decisions
                if x.get("decision")=="ACCEPTED_SOURCE"
            ] if source_evidence else [],
        },
    }

    if result_status=="UNKNOWN":
        item["unknowns"].append("Whether command result/status metadata is provided.")
    if state_status=="UNKNOWN":
        item["unknowns"].append("Whether vehicle state/operating conditions affect command acceptance.")
    if architecture["mode"]=="DIRECT":
        if not architecture["connections"]:
            item["unknowns"].append("Internal remote-command path connections were not provided.")
        if not architecture["external_interfaces"]:
            item["unknowns"].append("External interfaces/operational-environment connections were not provided.")

    contexts,context_basis=_derive_contexts(item)
    item["derived_contexts"]=contexts
    item["context_basis"]=context_basis

    return item

def validate_item_definition(item: dict) -> None:
    c=load_canonical()
    valid_functions={x["id"] for x in c["functions"]}

    if item.get("schema_version")!="cc-trace-item-definition-1.0":
        raise ValueError("unsupported item-definition schema")
    functions=item.get("item",{}).get("function_ids",[])
    if not functions or any(x not in valid_functions for x in functions):
        raise ValueError("item.function_ids must contain one or more valid IF-01..IF-07 IDs")
    arch=item.get("architecture",{})
    if arch.get("mode") not in {"REFERENCE","DIRECT"}:
        raise ValueError("architecture.mode must be REFERENCE or DIRECT")
    if arch.get("mode")=="DIRECT":
        components=arch.get("components") or []
        if not components:
            raise ValueError("DIRECT architecture requires at least one component")
        component_ids=[x.get("id") for x in components]
        if any(not x for x in component_ids) or len(component_ids)!=len(set(component_ids)):
            raise ValueError("DIRECT architecture component IDs must be non-empty and unique")
        if any(x.get("component_type") not in set(COMPONENT_TYPES.values()) for x in components):
            raise ValueError("DIRECT architecture contains an unsupported component_type")
        known=set(component_ids)
        connection_ids=[]
        for edge in arch.get("connections") or []:
            if edge.get("id"):
                connection_ids.append(edge["id"])
            if edge.get("source") not in known or edge.get("target") not in known:
                raise ValueError("DIRECT architecture connection source/target must reference existing components")
        if len(connection_ids)!=len(set(connection_ids)):
            raise ValueError("DIRECT architecture connection IDs must be unique")
        for ext in arch.get("external_interfaces") or []:
            if ext.get("internal_component_id") not in known:
                raise ValueError("DIRECT architecture external interface must reference an existing internal component")

    state=item.get("behavior",{}).get("state_used_in_command_acceptance",{})
    if state.get("status")=="YES" and "function_ids" in state:
        state_functions=state.get("function_ids") or []
        if not state_functions:
            raise ValueError("state_used_in_command_acceptance.function_ids is required when status is YES")
        if any(fid not in functions for fid in state_functions):
            raise ValueError("state_used_in_command_acceptance.function_ids must be selected Item Functions")

def derive_contexts_from_item_definition(item: dict) -> tuple[list[str], dict]:
    validate_item_definition(item)
    # Re-derive to prevent a manually edited JSON from smuggling arbitrary contexts.
    return _derive_contexts(item)

def contexts_from_item_definition(item: dict) -> list[str]:
    contexts,_=derive_contexts_from_item_definition(item)
    return contexts
