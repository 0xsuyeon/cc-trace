from __future__ import annotations
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
METHOD_ROOT = ROOT / "knowledge" / "method" / "tara_method_v1"
DOMAIN_ROOT = ROOT / "knowledge" / "domain" / "connected_car_remote_command_v1"
MAPPING_ROOT = ROOT / "knowledge" / "mapping" / "connected_car_source_mapping_v1"

def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))

def load_canonical() -> dict:
    return load_json(DOMAIN_ROOT / "canonical_tara.json")

def load_method() -> dict:
    names = [
        "workflow", "entity_schema", "impact_scale", "attack_potential", "risk_matrix",
        "treatment_policy", "cal_matrix", "goal_claim_rules", "consistency_rules",
    ]
    return {name: load_json(METHOD_ROOT / f"{name}.json") for name in names}

def load_mapping() -> dict:
    return {
        "taxonomy": load_json(MAPPING_ROOT / "semantic_taxonomy.json"),
        "function_rules": load_json(MAPPING_ROOT / "function_rules.json"),
        "context_rules": load_json(MAPPING_ROOT / "context_rules.json"),
    }

def canonical_sha256() -> str:
    return hashlib.sha256((DOMAIN_ROOT / "canonical_tara.json").read_bytes()).hexdigest()

def expected_canonical_sha256() -> str:
    text=(DOMAIN_ROOT/"canonical_tara.sha256").read_text(encoding="utf-8").strip()
    return text.split()[0]
