from __future__ import annotations

import json
from pathlib import Path

from .item_definition import (
    collect_item_definition,
    derive_contexts_from_item_definition,
    validate_item_definition,
)
from .loader import load_canonical
from .projection import project

def _write_json(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

def _function_rows(function_ids: list[str]) -> list[dict]:
    c=load_canonical()
    by_id={x["id"]:x for x in c["functions"]}
    return [by_id[x] for x in function_ids]

def render_report(item: dict, tara: dict) -> str:
    function_rows=_function_rows(item["item"]["function_ids"])
    arch=item["architecture"]
    result_status=item["behavior"]["command_result_status"]["status"]
    state=item["behavior"]["state_used_in_command_acceptance"]

    lines=[]
    lines.append("# CC-TRACE TARA Analysis")
    lines.append("")
    lines.append("> 본 결과는 CC-TRACE Connected-Car Reference TARA 지식베이스에 대한 applicability draft입니다.")
    lines.append("> 특정 OEM/제품의 최종 ISO/SAE 21434 적합성 TARA 또는 제품별 Risk 판정으로 해석하면 안 됩니다.")
    lines.append("")
    lines.append("## 1. Item Definition")
    lines.append("")
    lines.append(f"- **Item**: {item['item']['name']}")
    lines.append("- **Boundary**: 차량 외부에서 요청된 원격 차량 기능을 차량 측 E/E가 수신·판단·전달·실행/거부하는 범위")
    lines.append(f"- **Architecture basis**: `{arch['mode']}` / `{arch['basis']}`")
    lines.append("")

    lines.append("### Item Functions")
    lines.append("")
    for f in function_rows:
        lines.append(f"- `{f['id']}` {f['name_ko']} / {f['name_en']}")
    lines.append("")

    lines.append("### Architecture")
    lines.append("")
    if arch["mode"]=="REFERENCE":
        lines.append("CC-TRACE의 generic/reference logical architecture를 사용했습니다.")
    else:
        lines.append("사용자가 직접 확인한 architecture 정보를 사용했습니다.")
    lines.append("")
    lines.append("| Component | Type | Role | Basis |")
    lines.append("|---|---|---|---|")
    for comp in arch["components"]:
        name=comp.get("name_ko") or comp.get("name")
        role=comp.get("role") or ""
        lines.append(
            f"| {name} | {comp.get('component_type','')} | {role} | {comp.get('basis','')} |"
        )
    lines.append("")

    if arch.get("connections"):
        lines.append("#### Connections")
        lines.append("")
        for conn in arch["connections"]:
            if "relation" in conn:
                detail=conn["relation"]
            else:
                detail=conn.get("protocol") or conn.get("description") or "unspecified"
            lines.append(f"- `{conn['source']} → {conn['target']}` ({detail})")
        lines.append("")

    if arch.get("external_interfaces"):
        lines.append("#### External / Operational Environment")
        lines.append("")
        for ext in arch["external_interfaces"]:
            if "external_entity" in ext:
                lines.append(
                    f"- {ext['external_entity']} → `{ext['internal_component_id']}`"
                    + (f" via {ext['protocol']}" if ext.get("protocol") else "")
                )
            else:
                lines.append(f"- `{ext['id']}` {ext['name_ko']}: {ext['interaction']}")
        lines.append("")

    lines.append("### Behavior Facts")
    lines.append("")
    lines.append(f"- Command result/status: **{result_status}**")
    lines.append(f"- Vehicle state used in command acceptance: **{state['status']}**")
    if state.get("states"):
        lines.append(f"- State inputs: {', '.join(state['states'])}")
    if state.get("function_ids"):
        lines.append(f"- State-dependent functions: {', '.join(state['function_ids'])}")
    lines.append("")

    lines.append("### Derived TARA Contexts")
    lines.append("")
    for ctx in item["derived_contexts"]:
        lines.append(f"- `{ctx}` — {item['context_basis'].get(ctx,'')}")
    if not item["derived_contexts"]:
        lines.append("- 없음")
    lines.append("")

    source_meta=item.get("source_evidence") or {}
    if source_meta.get("present"):
        lines.append("### Source Evidence")
        lines.append("")
        manifest=source_meta.get("manifest") or {}
        summary=source_meta.get("summary") or {}
        lines.append(f"- Source kind: `{manifest.get('kind','UNKNOWN')}`")
        if manifest.get("source"):
            lines.append(f"- Source: `{manifest.get('source')}`")
        if manifest.get("commit"):
            lines.append(f"- Git commit: `{manifest.get('commit')}`")
        lines.append(f"- Supported files scanned: **{summary.get('supported_files',0)}**")
        lines.append(f"- Function candidates: **{summary.get('function_candidates',0)}**")
        lines.append("- Source findings are evidence candidates only; analyst confirmation controls the Item Definition.")
        semantic=source_meta.get("semantic_mapping") or {}
        if semantic:
            lines.append(
                f"- LLM semantic mapper: `{semantic.get('provider','')}` / "
                f"`{semantic.get('model','')}` / `{semantic.get('status','')}`"
            )
        lines.append("")

    if item.get("unknowns"):
        lines.append("### Unknowns")
        lines.append("")
        for u in item["unknowns"]:
            lines.append(f"- {u}")
        lines.append("")

    lines.append("## 2. Reference TARA Projection")
    lines.append("")
    lines.append(
        f"- Assets: **{len(tara['assets'])}**  "
        f"- Damage Scenarios: **{len(tara['damage_scenarios'])}**  "
        f"- Threat Scenarios: **{len(tara['threat_scenarios'])}**  "
        f"- Attack Paths: **{len(tara['attack_paths'])}**"
    )
    lines.append(
        f"- Cybersecurity Goals: **{len(tara['cybersecurity_goals'])}**  "
        f"- Cybersecurity Claims: **{len(tara['cybersecurity_claims'])}**"
    )
    lines.append("")

    lines.append("### Reference-applicable Assets")
    lines.append("")
    for a in tara["assets"]:
        app=a.get("applicability") or {}
        lines.append(
            f"- `{a['id']}` {a['name']} "
            f"— applicability={app.get('applicability','UNKNOWN')}, basis={app.get('evidence_basis','UNKNOWN')}"
        )
    lines.append("")

    lines.append("### Reference-applicable Threat Scenarios")
    lines.append("")
    lines.append("| Threat | Asset | Applicable Damage | Canonical Ref. Risk | Product Risk |")
    lines.append("|---|---|---|---:|---|")
    for t in tara["threat_scenarios"]:
        damages=", ".join(t["applicable_damage_ids"]) if t["applicable_damage_ids"] else "-"
        lines.append(
            f"| {t['id']} | {t['asset_id']} | {damages} | "
            f"{t['canonical_reference_risk']} | {t['target_product_risk_status']} |"
        )
    lines.append("")

    lines.append("### Cybersecurity Goals / Claims")
    lines.append("")
    for g in tara["cybersecurity_goals"]:
        lines.append(
            f"- `{g['id']}` applicable threats: {', '.join(g['applicable_threat_ids'])}; "
            f"canonical CAL={g['canonical_cal']}; target CAL={g['target_product_cal_status']}"
        )
    for cl in tara["cybersecurity_claims"]:
        lines.append(
            f"- `{cl['id']}` applicable threats: {', '.join(cl['applicable_threat_ids'])}; "
            f"target claim={cl.get('target_product_claim_status','UNASSESSED')}"
        )
    if not tara["cybersecurity_goals"] and not tara["cybersecurity_claims"]:
        lines.append("- 없음")
    lines.append("")

    lines.append("## 3. Interpretation Limits")
    lines.append("")
    lines.append("- `canonical_reference_risk`는 최종 generic/reference Item TARA의 값입니다.")
    lines.append("- 본 입력만으로 제품별 Impact/Attack Feasibility가 재평가되지 않으므로 `target_product_risk`는 `UNASSESSED`입니다.")
    lines.append("- Reference Architecture를 선택한 경우 내부 구성과 연결은 실제 OEM topology를 관측한 사실이 아니라 reference assumption입니다.")
    lines.append("- 사용자가 직접 입력하지 않았거나 증거가 없는 사실은 UNKNOWN으로 유지합니다.")
    lines.append("")

    return "\n".join(lines) + "\n"

def analyze_item_definition(item: dict) -> tuple[dict, dict]:
    validate_item_definition(item)
    contexts,context_basis=derive_contexts_from_item_definition(item)
    normalized=dict(item)
    normalized["derived_contexts"]=contexts
    normalized["context_basis"]=context_basis

    state=normalized.get("behavior",{}).get("state_used_in_command_acceptance",{})
    state_function_ids=(
        state.get("function_ids") if "function_ids" in state else None
    ) if state.get("status")=="YES" else []
    tara=project(
        function_ids=normalized["item"]["function_ids"],
        contexts=contexts,
        state_function_ids=state_function_ids,
    )
    tara["analysis_input"]={
        "item_name":normalized["item"]["name"],
        "architecture_mode":normalized["architecture"]["mode"],
        "derived_contexts":contexts,
    }
    return normalized,tara

def run_analysis(
    *,
    output_dir: str | Path,
    item_definition: dict | None = None,
    source_evidence: dict | None = None,
    interactive_client=None,
    input_fn=input,
    output_fn=print,
    show_intro: bool = True,
) -> dict:
    item=(
        item_definition
        if item_definition is not None
        else collect_item_definition(
            source_evidence=source_evidence,
            interactive_client=interactive_client,
            input_fn=input_fn,
            output_fn=output_fn,
            show_intro=show_intro,
        )
    )
    item,tara=analyze_item_definition(item)

    out=Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    item_path=out/"item_definition.json"
    tara_path=out/"tara.json"
    report_path=out/"report.md"
    source_evidence_path=out/"source_evidence.json"
    semantic_mapping_path=out/"semantic_mapping.json"

    _write_json(item_path,item)
    _write_json(tara_path,tara)
    report_path.write_text(render_report(item,tara),encoding="utf-8")
    if source_evidence is not None:
        _write_json(source_evidence_path,source_evidence)
        if source_evidence.get("semantic_mapping") is not None:
            _write_json(semantic_mapping_path,source_evidence["semantic_mapping"])

    return {
        "item_definition":str(item_path),
        "tara":str(tara_path),
        "report":str(report_path),
        "source_evidence":str(source_evidence_path) if source_evidence is not None else None,
        "semantic_mapping":(
            str(semantic_mapping_path)
            if source_evidence is not None and source_evidence.get("semantic_mapping") is not None
            else None
        ),
        "counts":{
            "functions":len(item["item"]["function_ids"]),
            "assets":len(tara["assets"]),
            "damage_scenarios":len(tara["damage_scenarios"]),
            "threat_scenarios":len(tara["threat_scenarios"]),
            "attack_paths":len(tara["attack_paths"]),
            "goals":len(tara["cybersecurity_goals"]),
            "claims":len(tara["cybersecurity_claims"]),
        }
    }

def load_item_definition(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
