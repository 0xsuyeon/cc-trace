from __future__ import annotations
from pathlib import Path
from docx import Document
import argparse, hashlib, json, re, sys

# Allow direct execution from the source checkout without installation.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cc_trace_kb.loader import load_canonical

def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024), b""):
            h.update(b)
    return h.hexdigest()

def table_rows(doc, idx):
    t=doc.tables[idx]
    headers=[c.text.strip() for c in t.rows[0].cells]
    return [dict(zip(headers,[c.text.strip() for c in row.cells])) for row in t.rows[1:]]

def norm_prop(raw):
    out=[]
    if "기밀성" in raw: out.append("CONFIDENTIALITY")
    if "무결성" in raw: out.append("INTEGRITY")
    if "가용성" in raw: out.append("AVAILABILITY")
    return out

def split_ids(s,prefix):
    ids=[]
    for a,b in re.findall(fr'({prefix}-\d+)\s*[~\-]\s*({prefix}-\d+)',s or ""):
        ai=int(a.split("-")[1]); bi=int(b.split("-")[1])
        ids.extend(f"{prefix}-{i:02d}" for i in range(ai,bi+1))
    for x in re.findall(fr'{prefix}-\d+',s or ""):
        if x not in ids: ids.append(x)
    return ids

IMPACT={"심각한":"SEVERE","주요한":"MAJOR","보통의":"MODERATE","무시할 수 있는":"NEGLIGIBLE"}
AF={"높음":"HIGH","중간":"MEDIUM","낮음":"LOW","매우 낮음":"VERY_LOW"}
TREAT={"위험 감소":"REDUCE","위험 유지":"RETAIN","위험 회피":"AVOID","위험 공유":"SHARE"}
ABBR={"N":"NEGLIGIBLE","Mo":"MODERATE","Ma":"MAJOR","S":"SEVERE"}

def audit(report: Path) -> dict:
    doc=Document(report)
    c=load_canonical()
    checks=[]

    def check(name,expected,actual):
        ok=expected==actual
        checks.append({"check":name,"pass":ok,"expected":expected,"actual":actual})
        return ok

    # Raw tables.
    ass=table_rows(doc,2)
    check("assumptions",[(x["id"],x["statement"]) for x in c["assumptions"]],
          [(r["ID"],r["가정"]) for r in ass])

    oe=table_rows(doc,3)
    check("operational_environment",
          [(x["id"],x["name_en"],x["name_ko"],x["interaction"],x["classification"]) for x in c["operational_environment"]],
          [(r["ID"],r["영문명"],r["요소"],r["Item과의 상호작용"],r["구분"]) for r in oe])

    comps=table_rows(doc,4)
    check("logical_components",
          [(x["id"],x["name_en"],x["name_ko"],x["role"]) for x in c["logical_components"]],
          [(r["ID"],r["Logical Component"],r["한글명"],r["역할"]) for r in comps])

    fs=table_rows(doc,6)
    check("functions",
          [(x["id"],x["name_en"],x["name_ko"],x["description"]) for x in c["functions"]],
          [(r["아이템 기능 ID"],r["기능(영문)"],r["기능"],r["설명"]) for r in fs])

    assets={x["id"]:x for x in c["assets"]}
    ar=table_rows(doc,9)
    for r in ar:
        a=assets[r["자산 ID"]]
        props=[]
        if r["기밀성"]=="O": props.append("CONFIDENTIALITY")
        if r["무결성"]=="O": props.append("INTEGRITY")
        if r["가용성"]=="O": props.append("AVAILABILITY")
        check(f"asset_{a['id']}",
              (a["name"],a["properties"],a["damage_scope_raw"]),
              (r["자산"],props,r["연결 피해 시나리오"]))

    damages={x["id"]:x for x in c["damage_scenarios"]}
    for r in table_rows(doc,10):
        d=damages[r["피해 시나리오 ID"]]
        check(f"damage_statement_{d['id']}",d["statement"],r["피해 시나리오"])

    for r in table_rows(doc,15):
        d=damages[r["ID"]]
        actual={
            "safety":IMPACT[r["안전"]],"financial":IMPACT[r["재무"]],
            "operational":IMPACT[r["운영"]],"privacy":IMPACT[r["개인정보"]]
        }
        check(f"damage_impact_{d['id']}",
              {k:d["impact"][k] for k in actual},actual)
        check(f"damage_rationale_{d['id']}",d["rationale"],r["평가 근거"])

    threats={x["id"]:x for x in c["threat_scenarios"]}
    for r in table_rows(doc,12):
        t=threats[r["위협 ID"]]
        check(f"threat_{t['id']}",
              (t["asset_id"],t["compromised_properties"],t["cause"],t["statement"],t["damage_scope_raw"]),
              (r["목표 자산"],norm_prop(r["손상 속성"]),r["손상 원인"],r["위협 시나리오"],r["피해 시나리오"]))

    aps={x["id"]:x for x in c["attack_paths"]}
    for r in table_rows(doc,17):
        a=aps[r["공격 경로 ID"]]
        check(f"attack_path_raw_{a['id']}",(a["name"],a["steps_raw"]),(r["공격 경로"],r["세부 단계"]))

    for r in table_rows(doc,18):
        t=threats[r["위협 ID"]]
        check(f"threat_ap_{t['id']}",t["attack_path_ids"],split_ids(r["공격 경로"],"AP"))

    for r in table_rows(doc,21):
        a=aps[r["AP"]]
        ap=a["attack_potential"]
        check(f"attack_potential_{a['id']}",
              (ap["elapsed_time"],ap["specialist_expertise"],ap["knowledge_of_item"],ap["window_of_opportunity"],ap["equipment"],a["expected_score"],a["expected_feasibility"]),
              (int(r["ET"]),int(r["SE"]),int(r["KoIC"]),int(r["WoO"]),int(r["Eq"]),int(r["합계"]),AF[r["등급"]]))

    risks={x["threat_id"]:x for x in c["risk_records"]}
    for r in table_rows(doc,25):
        rr=risks[r["위협"]]
        vec=r["S/F/O/P 영향"].split("/")
        check(f"risk_record_{rr['threat_id']}",
              (rr["asset_id"],rr["risk_damage_scope_raw"],rr["attack_feasibility"],
               rr["impact_vector"],rr["risk_by_dimension"],rr["expected_final_risk"]),
              (r["자산"],r["피해 시나리오"],AF[r["AF"]],
               {"safety":ABBR[vec[0]],"financial":ABBR[vec[1]],"operational":ABBR[vec[2]],"privacy":ABBR[vec[3]]},
               {"safety":int(r["R_S"]),"financial":int(r["R_F"]),"operational":int(r["R_O"]),"privacy":int(r["R_P"])},
               int(r["최종 위험"])))

    treatments={x["threat_id"]:x for x in c["treatments"]}
    for r in table_rows(doc,27):
        tr=treatments[r["위협"]]
        check(f"treatment_{tr['threat_id']}",
              (tr["asset_id"],tr["risk"],tr["decision"],tr["rationale"]),
              (r["자산"],int(r["위험 값"]),TREAT[r["위험 처리 옵션"]],r["결정 근거"]))

    goals={x["id"]:x for x in c["cybersecurity_goals"]}
    for r in table_rows(doc,31):
        g=goals[r["Goal ID"]]
        check(f"goal_{g['id']}",
              (g["asset_scope_raw"],g["threat_ids"],g["expected_max_risk"],g["treatment_raw"],g["expected_cal"],g["statement"]),
              (r["관련 자산"],split_ids(r["관련 위협"],"TS"),int(r["최대 위험"]),r["위험 처리"],r["CAL"],r["사이버보안 목표"]))

    cl=c["cybersecurity_claims"][0]
    r=table_rows(doc,32)[0]
    check("claim_CSC-01",
          (cl["id"],cl["asset_ids"],cl["threat_ids"],cl["risk"],cl["treatment_raw"],cl["cal"],cl["statement"]),
          (r["Claim ID"],split_ids(r["자산"],"AS"),split_ids(r["위협"],"TS"),int(r["위험 값"]),r["위험 처리"],r["CAL"],r["사이버보안 주장"]))

    result={
        "pass":all(x["pass"] for x in checks),
        "report":{"filename":report.name,"sha256":sha256(report)},
        "check_count":len(checks),
        "failed":[x for x in checks if not x["pass"]],
        "checks":checks
    }
    return result

def main():
    p=argparse.ArgumentParser()
    p.add_argument("report")
    p.add_argument("--output")
    args=p.parse_args()
    result=audit(Path(args.report))
    text=json.dumps(result,ensure_ascii=False,indent=2)
    if args.output:
        Path(args.output).write_text(text+"\n",encoding="utf-8")
    print("PASS" if result["pass"] else "FAIL", f"checks={result['check_count']} failed={len(result['failed'])}")
    if not result["pass"]:
        for x in result["failed"][:20]:
            print(x["check"])
        raise SystemExit(1)

if __name__=="__main__":
    main()
