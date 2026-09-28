import json
from cc_trace_kb.loader import load_canonical, DOMAIN_ROOT

def test_json_schema_if_available():
    import pytest
    jsonschema=pytest.importorskip("jsonschema")
    schema=json.loads((DOMAIN_ROOT/"canonical_tara.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(load_canonical())

def test_schema_rejects_corrupted_required_root_structures():
    import copy
    import pytest
    import jsonschema
    schema=json.loads((DOMAIN_ROOT/"canonical_tara.schema.json").read_text(encoding="utf-8"))
    validator=jsonschema.Draft202012Validator(schema)
    base=load_canonical()
    for key in (
        "function_asset_links",
        "function_damage_links",
        "reference_architecture",
        "method_reference_from_report",
        "expected_cardinality",
    ):
        obj=copy.deepcopy(base)
        obj[key]="garbage"
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(obj)
