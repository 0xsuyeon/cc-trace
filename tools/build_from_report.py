"""Rebuild helper for the canonical TARA dataset.

This script intentionally treats the final report as the source document and
extracts table data without inventing missing values. The checked-in canonical
JSON is the release source of truth; this helper is for audit/reconstruction.

Requires: python-docx
"""
from pathlib import Path
from docx import Document
import json, hashlib, sys

TABLES = {
    "assumptions":2,
    "operational_environment":3,
    "logical_components":4,
    "functions":6,
    "assets":9,
    "damage_scenarios":10,
    "threat_scenarios":12,
    "impact_ratings":15,
    "attack_paths":17,
    "threat_attack_paths":18,
    "attack_feasibility":21,
    "threat_af":22,
    "risk_values":25,
    "treatments":27,
    "goal_cal":29,
    "goals":31,
    "claim":32,
}

def table(doc, idx):
    t=doc.tables[idx]
    headers=[c.text.strip() for c in t.rows[0].cells]
    return [dict(zip(headers,[c.text.strip() for c in r.cells])) for r in t.rows[1:]]

def main(path):
    p=Path(path)
    doc=Document(p)
    raw={name:table(doc,idx) for name,idx in TABLES.items()}
    raw["_source"]={"filename":p.name,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
    print(json.dumps(raw,ensure_ascii=False,indent=2))

if __name__=="__main__":
    if len(sys.argv)!=2:
        raise SystemExit("usage: python tools/build_from_report.py FINAL_REPORT.docx")
    main(sys.argv[1])
