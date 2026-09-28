from __future__ import annotations
import argparse, getpass, json, os
from pathlib import Path

from .analyze import load_item_definition, run_analysis
from .loader import load_canonical, canonical_sha256
from .projection import project
from .source_analyzer import analyze_source
from .semantic_mapper import (
    SemanticMappingError,
    build_semantic_client,
    enrich_source_evidence_with_llm,
    normalize_provider,
)
from .validate import validate_canonical

_PROVIDER_LABELS = {
    "gemini": "Gemini",
    "openai": "GPT / OpenAI",
    "anthropic": "Claude / Anthropic",
    "groq": "Groq",
}

_PROVIDER_KEY_ENV = {
    "gemini": "GEMINI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "groq": "GROQ_API_KEY",
}

def _choose_interactive_provider(*, input_fn=input, output_fn=print) -> str:
    output_fn("")
    output_fn("입력 보조 모델을 사용할까요?")
    output_fn("  1. Gemini")
    output_fn("  2. GPT / OpenAI")
    output_fn("  3. Claude / Anthropic")
    output_fn("  4. Groq")
    output_fn("  5. 사용하지 않음")
    aliases={
        "":"none", "5":"none", "none":"none",
        "1":"gemini", "gemini":"gemini", "google":"gemini",
        "2":"openai", "gpt":"openai", "openai":"openai",
        "3":"anthropic", "claude":"anthropic", "anthropic":"anthropic",
        "4":"groq", "groq":"groq",
    }
    while True:
        raw=input_fn("선택 (Enter = 사용하지 않음): ").strip().lower()
        if raw in aliases:
            return aliases[raw]
        output_fn("1~5 중 하나를 선택해 주세요.")

def _resolve_api_key(
    provider: str,
    *,
    secret_input_fn=getpass.getpass,
    output_fn=print,
) -> str | None:
    normalized=normalize_provider(provider)
    if normalized=="none":
        return None
    env_name=_PROVIDER_KEY_ENV[normalized]
    existing=os.environ.get(env_name)
    if existing:
        return existing
    label=_PROVIDER_LABELS[normalized]
    while True:
        value=secret_input_fn(f"{label} API Key (입력 내용은 표시되지 않습니다): ").strip()
        if value:
            return value
        output_fn("API Key를 입력해 주세요.")

def _resolve_llm_setup(
    provider: str | None,
    *,
    prompt_provider: bool,
    input_fn=input,
    secret_input_fn=getpass.getpass,
    output_fn=print,
) -> tuple[str,str | None]:
    selected=(
        _choose_interactive_provider(input_fn=input_fn,output_fn=output_fn)
        if provider is None and prompt_provider
        else normalize_provider(provider or "none")
    )
    return selected,_resolve_api_key(
        selected,secret_input_fn=secret_input_fn,output_fn=output_fn
    )


def _dump(obj, out=None):
    text=json.dumps(obj,ensure_ascii=False,indent=2)
    if out:
        Path(out).write_text(text+"\n",encoding="utf-8")
        print(out)
    else:
        print(text)

def _llm_enrich(source_evidence: dict, provider: str, model: str | None, timeout: int, api_key: str | None = None) -> dict:
    try:
        normalized=normalize_provider(provider)
        if normalized=="none":
            return source_evidence
        client=build_semantic_client(
            normalized,
            model=model,
            timeout=timeout,
            api_key=api_key,
        )
        enriched,artifact=enrich_source_evidence_with_llm(source_evidence,client)
    except SemanticMappingError as exc:
        raise SystemExit(f"LLM semantic mapping failed: {exc}") from exc

    print(
        "LLM semantic mapping: "
        f"provider={artifact['provider']}, "
        f"status={artifact['status']}, model={artifact['model']}, "
        f"mapped={sum(1 for x in artifact['mappings'] if x['function_id']!='UNKNOWN')}, "
        f"unknown={sum(1 for x in artifact['mappings'] if x['function_id']=='UNKNOWN')}, "
        f"rejections={len(artifact['rejections'])}"
    )
    return enriched

def main(argv=None):
    p=argparse.ArgumentParser(prog="cc-trace")
    sub=p.add_subparsers(dest="cmd",required=True)

    sub.add_parser("validate",help="Recompute and validate the canonical TARA chain.")
    sub.add_parser("summary",help="Show canonical TARA counts and hash.")

    show=sub.add_parser("show",help="Show one canonical entity by ID.")
    show.add_argument("id")

    proj=sub.add_parser("project",help="Create a reference applicability projection.")
    proj.add_argument("--functions",nargs="*",default=[])
    proj.add_argument("--contexts",nargs="*",default=[])
    proj.add_argument("--output")

    analyze=sub.add_parser(
        "analyze",
        help="Interactively build an Item Definition and generate a TARA applicability draft."
    )
    analyze.add_argument(
        "--item-definition",
        help="Use an existing item_definition.json instead of interactive questions."
    )
    analyze.add_argument(
        "--source",
        help="Optional source evidence: directory, Python/OpenAPI file, ZIP, or GitHub repository URL."
    )
    analyze.add_argument(
        "--llm",
        choices=["none","openai","gpt","anthropic","claude","groq","gemini","google"],
        default=None,
        help="Input assistance and ambiguous semantic fallback. If omitted, interactive analyze asks which provider to use."
    )
    analyze.add_argument(
        "--llm-model",
        help="Provider model ID. Defaults by provider or environment variable."
    )
    analyze.add_argument(
        "--llm-timeout",
        type=int,
        default=60,
        help="LLM API timeout in seconds."
    )
    analyze.add_argument(
        "--output-dir",
        default="cc_trace_output",
        help="Directory for analysis artifacts."
    )

    inspect_src=sub.add_parser(
        "inspect-source",
        help="Statically inspect source/OpenAPI evidence without running TARA."
    )
    inspect_src.add_argument("source")
    inspect_src.add_argument("--output")
    inspect_src.add_argument(
        "--llm",
        choices=["none","openai","gpt","anthropic","claude","groq","gemini","google"],
        default="none",
        help="Optionally classify only ambiguous semantic candidates."
    )
    inspect_src.add_argument("--llm-model")
    inspect_src.add_argument("--llm-timeout",type=int,default=60)

    args=p.parse_args(argv)

    if args.cmd=="validate":
        result=validate_canonical()
        print("PASS")
        for c in result["checks"]:
            print(f"[PASS] {c['check']}: {c['detail']}")
        return

    if args.cmd=="inspect-source":
        result=analyze_source(args.source)
        if args.llm!="none":
            provider,api_key=_resolve_llm_setup(
                args.llm,prompt_provider=False
            )
            result=_llm_enrich(
                result,provider,args.llm_model,args.llm_timeout,api_key
            )
        _dump(result,args.output)
        return

    c=load_canonical()

    if args.cmd=="summary":
        _dump({"canonical_sha256":canonical_sha256(),"expected_cardinality":c["expected_cardinality"]})
        return

    if args.cmd=="show":
        for section in [
            "functions","assets","damage_scenarios","threat_scenarios","attack_paths",
            "cybersecurity_goals","cybersecurity_claims"
        ]:
            for x in c[section]:
                if x["id"]==args.id:
                    _dump({"section":section,"entity":x})
                    return
        raise SystemExit(f"not found: {args.id}")

    if args.cmd=="project":
        _dump(project(args.functions,args.contexts),args.output)
        return

    if args.cmd=="analyze":
        if args.item_definition and args.source:
            raise SystemExit("--item-definition and --source cannot be used together.")
        if args.item_definition and args.llm not in (None,"none"):
            raise SystemExit("--llm is not used with --item-definition; use interactive analyze or --source.")
        item=load_item_definition(args.item_definition) if args.item_definition else None
        source_evidence=None
        llm_client=None
        provider="none"
        api_key=None
        if not args.item_definition:
            print("CC-TRACE Interactive TARA Analysis")
            print("분석할 시스템 정보를 순서대로 입력해 주세요.")
            print("모르는 항목은 Enter를 누르면 됩니다.")
            provider,api_key=_resolve_llm_setup(
                args.llm,prompt_provider=(args.llm is None)
            )
        if provider!="none":
            try:
                llm_client=build_semantic_client(
                    provider,
                    model=args.llm_model,
                    timeout=args.llm_timeout,
                    api_key=api_key,
                )
            except SemanticMappingError as exc:
                raise SystemExit(f"LLM setup failed: {exc}") from exc
        if args.source:
            print("Scanning source evidence statically (target code is not executed/imported)...")
            source_evidence=analyze_source(args.source)
            print(
                "Source scan: "
                f"files={source_evidence['summary']['supported_files']}, "
                f"function_candidates={source_evidence['summary']['function_candidates']}, "
                f"ambiguous={source_evidence['summary']['ambiguous_semantic_candidates']}, "
                f"result_tokens={source_evidence['summary']['result_tokens']}, "
                f"state_guards={source_evidence['summary']['state_guards']}"
            )
            if provider!="none":
                try:
                    source_evidence,artifact=enrich_source_evidence_with_llm(
                        source_evidence,llm_client
                    )
                except SemanticMappingError as exc:
                    raise SystemExit(f"LLM semantic mapping failed: {exc}") from exc
                print(
                    "LLM semantic mapping: "
                    f"provider={artifact['provider']}, "
                    f"status={artifact['status']}, model={artifact['model']}, "
                    f"mapped={sum(1 for x in artifact['mappings'] if x['function_id']!='UNKNOWN')}, "
                    f"unknown={sum(1 for x in artifact['mappings'] if x['function_id']=='UNKNOWN')}, "
                    f"rejections={len(artifact['rejections'])}"
                )
        result=run_analysis(
            output_dir=args.output_dir,
            item_definition=item,
            source_evidence=source_evidence,
            interactive_client=llm_client,
            show_intro=False if not args.item_definition else True,
        )
        print("")
        print("Analysis complete.")
        print(f"  Item Definition: {result['item_definition']}")
        print(f"  TARA:            {result['tara']}")
        print(f"  Report:          {result['report']}")
        if result.get("source_evidence"):
            print(f"  Source Evidence: {result['source_evidence']}")
        if result.get("semantic_mapping"):
            print(f"  Semantic Mapping: {result['semantic_mapping']}")
        print(
            "  Counts: "
            + ", ".join(f"{k}={v}" for k,v in result["counts"].items())
        )
        return

if __name__=="__main__":
    main()
