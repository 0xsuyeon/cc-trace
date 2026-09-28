from __future__ import annotations

import ast
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

MAX_FILES = 5000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 50 * 1024 * 1024

SUPPORTED_SUFFIXES = {".py", ".json", ".yaml", ".yml"}

# Conservative vocabulary: only map terms that are reasonably specific.
PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "IF-01": [
        re.compile(r"(^|[_\W])(un)?lock([_\W]|$)", re.I),
        re.compile(r"door[_\W]?(un)?lock", re.I),
    ],
    "IF-02": [
        re.compile(r"remote[_\W]?start", re.I),
        re.compile(r"(start|stop)[_\W]?engine", re.I),
        re.compile(r"engine[_\W]?(start|stop)", re.I),
        re.compile(r"remote[_\W]?(drive|move)", re.I),
    ],
    "IF-03": [
        re.compile(r"(^|[_\W])(window|windows|sunroof|trunk|frunk)([_\W]|$)", re.I),
        re.compile(r"charge[_\W]?port", re.I),
        re.compile(r"tailgate", re.I),
    ],
    "IF-04": [
        re.compile(r"(^|[_\W])(climate|hvac|defrost|defog)([_\W]|$)", re.I),
        re.compile(r"(seat|steering)[_\W]?(heat|heater|warm)", re.I),
        re.compile(r"(start|stop)[_\W]?(climate|hvac)", re.I),
    ],
    "IF-05": [
        re.compile(r"(start|stop)[_\W]?charg(e|ing)", re.I),
        re.compile(r"charg(e|ing)[_\W]?(start|stop|limit|current|schedule)", re.I),
        re.compile(r"set[_\W]?charge[_\W]?(limit|current)", re.I),
    ],
    "IF-06": [
        re.compile(r"(^|[_\W])(horn|hazard|flash|lights?|headlights?)([_\W]|$)", re.I),
        re.compile(r"find[_\W]?vehicle", re.I),
        re.compile(r"vehicle[_\W]?find", re.I),
    ],
    "IF-07": [
        re.compile(r"(^|[_\W])(valet|sentry|immobilizer)([_\W]|$)", re.I),
        re.compile(r"security[_\W]?mode", re.I),
        re.compile(r"(enable|disable)[_\W]?(valet|sentry|security)", re.I),
    ],
}

RESULT_TOKENS = {
    "status", "result", "action_id", "actionid", "transaction_id",
    "transactionid", "request_id", "requestid", "command_id", "commandid",
}
STATE_TOKENS = {
    "speed", "gear", "ignition", "charging_state", "charge_state",
    "vehicle_state", "park", "is_parked", "driving",
}
HTTP_CALL_NAMES = {"get", "post", "put", "patch", "delete", "request"}
HTTP_CLIENT_ROOTS = {"api", "requests", "httpx", "session", "client", "http", "aiohttp", "urllib3"}

# Evidence from tests/examples is useful for review, but it must not by itself
# activate a product/reference function branch.
SUPPORTING_SOURCE_DIRS = {
    "test", "tests", "example", "examples", "fixture", "fixtures", "sample", "samples",
}

QUERY_HINT = re.compile(
    r"(^|[_\W])(get|read|fetch|list|status|state|info|information|query|retrieve|"
    r"telemetry|history|current)([_\W]|$)",
    re.I,
)
COMMAND_HINT = re.compile(
    r"(^|[_\W])(set|start|stop|lock|unlock|open|close|enable|disable|activate|"
    r"deactivate|toggle|honk|horn|flash|command|control|execute|perform|invoke|apply|"
    r"drive|move)([_\W]|$)",
    re.I,
)

# Only unresolved facts with some action/API evidence are eligible for the LLM fallback.
# This avoids sending every helper/utility function to the model.
AMBIGUOUS_ACTION_HINT = re.compile(
    r"(action|command|control|remote|execute|perform|invoke|start|stop|open|close|"
    r"enable|disable|activate|deactivate|toggle|set|request|run|apply)",
    re.I,
)

@dataclass(frozen=True)
class SourceFile:
    path: Path
    relpath: str
    sha256: str
    source_role: str = "PRODUCTION"

def _source_role(relpath: str) -> str:
    path=Path(relpath)
    parts={part.lower() for part in path.parts[:-1]}
    name=path.name.lower()
    if parts & SUPPORTING_SOURCE_DIRS or name.startswith("test_") or name.endswith("_test.py"):
        return "SUPPORTING"
    return "PRODUCTION"

def _static_string(node: ast.AST) -> str | None:
    """Best-effort static string extraction without evaluating target code."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts=[]
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                parts.append("{VAR}")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left=_static_string(node.left)
        right=_static_string(node.right)
        if left is not None and right is not None:
            return left+right
    return None

def classify_operation_role(
    name: str,
    extra: Iterable[str] = (),
    http_methods: Iterable[str] = (),
) -> str:
    """Classify a source fact as COMMAND, QUERY, or UNKNOWN.

    Query/status evidence never activates an Item Function. Explicit command verbs
    can still classify an unusual GET endpoint as COMMAND; otherwise GET is treated
    conservatively as QUERY.
    """
    primary=_symbol_text(name)
    if QUERY_HINT.search(primary):
        return "QUERY"
    if COMMAND_HINT.search(primary):
        return "COMMAND"
    text=_symbol_text("", extra)
    if QUERY_HINT.search(text):
        return "QUERY"
    if COMMAND_HINT.search(text):
        return "COMMAND"
    methods={m.upper() for m in http_methods if m}
    if methods == {"GET"}:
        return "QUERY"
    if methods & {"POST","PUT","PATCH","DELETE"}:
        return "COMMAND"
    return "UNKNOWN"

def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _sha256_file(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _safe_extract_zip(path: Path, target: Path) -> None:
    total=0
    with zipfile.ZipFile(path) as zf:
        infos=zf.infolist()
        if len(infos) > MAX_FILES:
            raise ValueError(f"ZIP has too many entries: {len(infos)} > {MAX_FILES}")
        for info in infos:
            if info.is_dir():
                continue
            if info.file_size > MAX_FILE_BYTES:
                raise ValueError(f"ZIP entry too large: {info.filename}")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise ValueError("ZIP exceeds total extraction size limit")
            dest=(target/info.filename).resolve()
            root=target.resolve()
            if root not in dest.parents and dest != root:
                raise ValueError(f"Unsafe ZIP path: {info.filename}")
        zf.extractall(target)

def acquire_source(source: str) -> tuple[Path, dict]:
    """Acquire a source tree without executing/importing it."""
    p=Path(source)
    if p.exists():
        if p.is_dir():
            return p.resolve(), {"kind":"DIRECTORY","source":str(p.resolve())}
        if p.is_file() and p.suffix.lower()==".zip":
            temp=Path(tempfile.mkdtemp(prefix="cc_trace_src_"))
            _safe_extract_zip(p,temp)
            return temp, {"kind":"ZIP","source":str(p.resolve()),"temporary":str(temp)}
        if p.is_file():
            return p.resolve().parent, {
                "kind":"FILE",
                "source":str(p.resolve()),
                "single_file":p.name,
            }
        raise ValueError(f"Unsupported source path: {source}")

    if re.match(r"^https://github\.com/[^/]+/[^/]+(?:\.git)?/?$", source):
        temp=Path(tempfile.mkdtemp(prefix="cc_trace_git_"))
        repo=temp/"repo"
        try:
            cp=subprocess.run(
                ["git","clone","--depth","1","--no-tags",source,str(repo)],
                text=True,capture_output=True,timeout=60
            )
        except subprocess.TimeoutExpired as exc:
            shutil.rmtree(temp,ignore_errors=True)
            raise ValueError("Git clone timed out") from exc
        if cp.returncode != 0:
            shutil.rmtree(temp,ignore_errors=True)
            raise ValueError(f"Git clone failed: {cp.stderr.strip()[:500]}")
        commit=subprocess.run(
            ["git","-C",str(repo),"rev-parse","HEAD"],
            text=True,capture_output=True,timeout=10
        )
        return repo, {
            "kind":"GITHUB",
            "source":source,
            "temporary":str(temp),
            "commit":commit.stdout.strip() if commit.returncode==0 else None,
        }

    raise ValueError("Source must be a directory, file, ZIP, or GitHub repository URL.")

def _iter_supported_files(root: Path, single_file: str | None = None) -> list[SourceFile]:
    files=[]
    total=0
    candidates=[root/single_file] if single_file else root.rglob("*")
    for p in candidates:
        if p.is_symlink():
            continue
        try:
            rel_parts=p.relative_to(root).parts
        except ValueError:
            continue
        if any(part in {".git",".venv","venv","node_modules","dist","build"} for part in rel_parts):
            continue
        if not p.is_file() or p.suffix.lower() not in SUPPORTED_SUFFIXES:
            continue
        try:
            size=p.stat().st_size
        except OSError:
            continue
        if size > MAX_FILE_BYTES:
            continue
        total += size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("Source exceeds total scan size limit")
        rel=p.relative_to(root).as_posix()
        files.append(SourceFile(p,rel,_sha256_file(p),_source_role(rel)))
        if len(files)>MAX_FILES:
            raise ValueError("Source contains too many supported files")
    return sorted(files,key=lambda x:x.relpath)

def _symbol_text(name: str, extra: Iterable[str] = ()) -> str:
    raw=" ".join([name,*extra]).replace("-", "_")
    # Expose CamelCase token boundaries without changing the original evidence.
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", raw)

def classify_function_semantics(name: str, extra: Iterable[str] = ()) -> list[str]:
    text=_symbol_text(name,extra)
    hits=[]
    for fid,patterns in PATTERNS.items():
        if any(p.search(text) for p in patterns):
            hits.append(fid)
    return hits

class PythonFactVisitor(ast.NodeVisitor):
    def __init__(self, relpath: str, source_role: str):
        self.relpath=relpath
        self.source_role=source_role
        self.functions=[]
        self.calls=[]
        self.http_calls=[]
        self.result_tokens=[]
        self.state_guards=[]
        self._function_stack=[]
        self._class_stack=[]

    def visit_ClassDef(self,node: ast.ClassDef):
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self,node: ast.FunctionDef):
        self._visit_function(node)

    def visit_AsyncFunctionDef(self,node: ast.AsyncFunctionDef):
        self._visit_function(node)

    def _qualified_name(self,name: str) -> str:
        scope=[*self._class_stack]
        if self._function_stack:
            # Preserve nested-function identity without building a full call graph.
            scope.extend(x["name"] for x in self._function_stack)
        return ".".join([*scope,name]) if scope else name

    def _visit_function(self,node):
        params=[a.arg for a in (*node.args.posonlyargs,*node.args.args,*node.args.kwonlyargs)]
        semantic_hints=classify_function_semantics(node.name,params)
        rec={
            "fact_type":"FUNCTION",
            "name":node.name,
            "qualified_name":self._qualified_name(node.name),
            "params":params,
            "file":self.relpath,
            "line":getattr(node,"lineno",None),
            "end_line":getattr(node,"end_lineno",None),
            "source_role":self.source_role,
            "semantic_hints":semantic_hints,
            "function_candidates":[],
        }
        self.functions.append(rec)
        self._function_stack.append(rec)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self,node: ast.Call):
        callee=self._call_name(node.func)
        if callee:
            current=self._function_stack[-1]["qualified_name"] if self._function_stack else None
            self.calls.append({
                "fact_type":"CALL",
                "caller":current,
                "callee":callee,
                "file":self.relpath,
                "line":getattr(node,"lineno",None),
                "source_role":self.source_role,
            })
            last=callee.split(".")[-1].lower()
            literal_args=[]
            for arg in node.args:
                value=_static_string(arg)
                if value is not None:
                    literal_args.append(value)
            for kw in node.keywords:
                if kw.arg in {"url","path","endpoint"}:
                    value=_static_string(kw.value)
                    if value is not None:
                        literal_args.append(value)
            root=callee.split(".")[0].lower()
            looks_like_url=any(x.startswith(("/","http://","https://")) for x in literal_args)
            is_http=last in HTTP_CALL_NAMES and (last!="get" or root in HTTP_CLIENT_ROOTS or looks_like_url)
            if is_http:
                self.http_calls.append({
                    "fact_type":"HTTP_CALL",
                    "caller":current,
                    "callee":callee,
                    "method":last.upper() if last != "request" else None,
                    "literal_args":literal_args[:3],
                    "file":self.relpath,
                    "line":getattr(node,"lineno",None),
                    "source_role":self.source_role,
                })
        self.generic_visit(node)

    def visit_Name(self,node: ast.Name):
        n=node.id.lower()
        if n in RESULT_TOKENS:
            self.result_tokens.append({
                "fact_type":"RESULT_TOKEN","name":node.id,"file":self.relpath,
                "line":getattr(node,"lineno",None),
                "function":self._function_stack[-1]["qualified_name"] if self._function_stack else None,
                "source_role":self.source_role,
            })
        self.generic_visit(node)

    def visit_Attribute(self,node: ast.Attribute):
        n=node.attr.lower()
        if n in RESULT_TOKENS:
            self.result_tokens.append({
                "fact_type":"RESULT_TOKEN","name":node.attr,"file":self.relpath,
                "line":getattr(node,"lineno",None),
                "function":self._function_stack[-1]["qualified_name"] if self._function_stack else None,
                "source_role":self.source_role,
            })
        self.generic_visit(node)

    def visit_If(self,node: ast.If):
        names={n.lower() for n in self._collect_names(node.test)}
        state=sorted(names & STATE_TOKENS)
        if state:
            current=self._function_stack[-1]["qualified_name"] if self._function_stack else None
            self.state_guards.append({
                "fact_type":"STATE_GUARD_CANDIDATE",
                "state_tokens":state,
                "function":current,
                "file":self.relpath,
                "line":getattr(node,"lineno",None),
                "source_role":self.source_role,
            })
        self.generic_visit(node)

    @staticmethod
    def _call_name(node):
        if isinstance(node,ast.Name):
            return node.id
        if isinstance(node,ast.Attribute):
            parts=[]
            cur=node
            while isinstance(cur,ast.Attribute):
                parts.append(cur.attr)
                cur=cur.value
            if isinstance(cur,ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        return None

    @staticmethod
    def _collect_names(node):
        out=[]
        for child in ast.walk(node):
            if isinstance(child,ast.Name):
                out.append(child.id)
            elif isinstance(child,ast.Attribute):
                out.append(child.attr)
            elif isinstance(child,ast.Constant) and isinstance(child.value,str):
                # Covers state["speed"] and state.get("gear") without evaluating code.
                if child.value.lower() in STATE_TOKENS:
                    out.append(child.value)
        return out

def _scan_python(sf: SourceFile) -> dict:
    try:
        text=sf.path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text=sf.path.read_text(encoding="utf-8",errors="replace")
    try:
        tree=ast.parse(text,filename=sf.relpath)
    except SyntaxError as exc:
        return {"parse_error":f"{exc.msg} at line {exc.lineno}"}
    v=PythonFactVisitor(sf.relpath,sf.source_role)
    v.visit(tree)

    calls_by_caller={}
    for call in v.calls:
        if call.get("caller"):
            calls_by_caller.setdefault(call["caller"],[]).append(call)

    http_by_caller={}
    for call in v.http_calls:
        if call.get("caller"):
            http_by_caller.setdefault(call["caller"],[]).append(call)

    mapped_names=set()
    for func in v.functions:
        qname=func["qualified_name"]
        calls=calls_by_caller.get(qname,[])
        http_calls=http_by_caller.get(qname,[])
        derived=set(func.get("semantic_hints",[]))
        for call in calls:
            derived.update(classify_function_semantics(call.get("callee") or ""))
        for call in http_calls:
            derived.update(
                classify_function_semantics(
                    call.get("callee") or "",
                    call.get("literal_args") or [],
                )
            )
        func["callees"]=sorted({call.get("callee") for call in calls if call.get("callee")})
        func["http_literals"]=[
            literal for call in http_calls for literal in (call.get("literal_args") or [])
        ][:10]
        func["http_methods"]=sorted({call.get("method") for call in http_calls if call.get("method")})
        func["has_http_call"]=bool(http_calls)
        role=classify_operation_role(
            func["name"],
            [func["qualified_name"],*func["callees"],*func["http_literals"]],
            func["http_methods"],
        )
        func["operation_role"]=role
        activation_eligible=func.get("source_role")=="PRODUCTION" and role=="COMMAND"
        func["function_candidates"]=sorted(derived) if activation_eligible else []
        func["suppressed_function_candidates"]=sorted(derived) if derived and not activation_eligible else []
        if func["function_candidates"]:
            mapped_names.add(qname)

    # Result/state clues outside a remote-command candidate are too noisy.
    result_tokens=[
        x for x in v.result_tokens
        if x.get("function") in mapped_names
    ]
    state_guards=[
        x for x in v.state_guards
        if x.get("function") in mapped_names
    ]

    return {
        "functions":v.functions,
        "calls":v.calls,
        "http_calls":v.http_calls,
        "result_tokens":result_tokens,
        "state_guards":state_guards,
        "all_result_tokens":v.result_tokens,
        "all_state_guards":v.state_guards,
    }

def _scan_openapi_json(sf: SourceFile) -> list[dict]:
    try:
        obj=json.loads(sf.path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(obj,dict) or "paths" not in obj or not isinstance(obj["paths"],dict):
        return []
    facts=[]
    for path,methods in obj["paths"].items():
        if not isinstance(methods,dict):
            continue
        for method,op in methods.items():
            if method.lower() not in {"get","post","put","patch","delete"} or not isinstance(op,dict):
                continue
            operation_id=str(op.get("operationId") or "")
            summary=str(op.get("summary") or "")
            semantic_hints=classify_function_semantics(operation_id,[summary,path])
            role=classify_operation_role(operation_id,[summary,path],[method])
            activation_eligible=sf.source_role=="PRODUCTION" and role=="COMMAND"
            facts.append({
                "fact_type":"OPENAPI_OPERATION",
                "method":method.upper(),
                "path":path,
                "operation_id":operation_id or None,
                "summary":summary or None,
                "file":sf.relpath,
                "source_role":sf.source_role,
                "operation_role":role,
                "semantic_hints":semantic_hints,
                "function_candidates":semantic_hints if activation_eligible else [],
                "suppressed_function_candidates":semantic_hints if semantic_hints and not activation_eligible else [],
            })
    return facts

def _scan_openapi_yaml(sf: SourceFile) -> list[dict]:
    # Deliberately tiny parser: enough for path/method/operationId/summary discovery.
    text=sf.path.read_text(encoding="utf-8",errors="replace")
    if "openapi:" not in text and "swagger:" not in text:
        return []
    facts=[]
    current_path=None
    current_method=None
    current={"operation_id":None,"summary":None}
    def flush():
        nonlocal current_method,current
        if current_path and current_method:
            semantic_hints=classify_function_semantics(
                current["operation_id"] or "",
                [current["summary"] or "",current_path]
            )
            role=classify_operation_role(
                current["operation_id"] or "",
                [current["summary"] or "",current_path],
                [current_method],
            )
            activation_eligible=sf.source_role=="PRODUCTION" and role=="COMMAND"
            facts.append({
                "fact_type":"OPENAPI_OPERATION",
                "method":current_method.upper(),
                "path":current_path,
                "operation_id":current["operation_id"],
                "summary":current["summary"],
                "file":sf.relpath,
                "source_role":sf.source_role,
                "operation_role":role,
                "semantic_hints":semantic_hints,
                "function_candidates":semantic_hints if activation_eligible else [],
                "suppressed_function_candidates":semantic_hints if semantic_hints and not activation_eligible else [],
            })
        current_method=None
        current={"operation_id":None,"summary":None}

    for line in text.splitlines():
        m=re.match(r"^\s{0,4}(/[^:]+):\s*$",line)
        if m:
            flush()
            current_path=m.group(1).strip()
            continue
        m=re.match(r"^\s+(get|post|put|patch|delete):\s*$",line,re.I)
        if m and current_path:
            flush()
            current_method=m.group(1).lower()
            continue
        if current_method:
            m=re.match(r"^\s+operationId:\s*[\"']?([^\"']+?)[\"']?\s*$",line)
            if m:
                current["operation_id"]=m.group(1).strip()
                continue
            m=re.match(r"^\s+summary:\s*[\"']?([^\"']+?)[\"']?\s*$",line)
            if m:
                current["summary"]=m.group(1).strip()
    flush()
    return facts

def analyze_source(source: str) -> dict:
    root,manifest=acquire_source(source)
    temp_root=manifest.get("temporary")
    try:
        files=_iter_supported_files(root,manifest.get("single_file"))
        functions=[]
        openapi=[]
        result_tokens=[]
        state_guards=[]
        all_result_tokens=[]
        all_state_guards=[]
        http_calls=[]
        parse_errors=[]

        for sf in files:
            if sf.path.suffix.lower()==".py":
                rec=_scan_python(sf)
                if rec.get("parse_error"):
                    parse_errors.append({"file":sf.relpath,"error":rec["parse_error"]})
                    continue
                functions.extend(rec["functions"])
                result_tokens.extend(rec["result_tokens"])
                state_guards.extend(rec["state_guards"])
                all_result_tokens.extend(rec["all_result_tokens"])
                all_state_guards.extend(rec["all_state_guards"])
                http_calls.extend(rec["http_calls"])
            elif sf.path.suffix.lower()==".json":
                openapi.extend(_scan_openapi_json(sf))
            elif sf.path.suffix.lower() in {".yaml",".yml"}:
                openapi.extend(_scan_openapi_yaml(sf))

        # Stable fact IDs make deterministic/LLM mappings auditable and reproducible.
        semantic_records=[*functions,*openapi]
        semantic_records.sort(
            key=lambda r: (
                r.get("file") or "",
                int(r.get("line") or 0),
                r.get("name") or r.get("operation_id") or r.get("path") or "",
                r.get("method") or "",
            )
        )
        for idx,rec in enumerate(semantic_records,start=1):
            rec["fact_id"]=f"SF-{idx:05d}"

        evidence_by_function={f"IF-{i:02d}":[] for i in range(1,8)}
        for rec in semantic_records:
            for fid in rec.get("function_candidates",[]):
                evidence_by_function[fid].append({
                    k:v for k,v in rec.items()
                    if k in {
                        "fact_id","fact_type","name","qualified_name","operation_id","summary",
                        "path","method","file","line","source_role","operation_role"
                    }
                })

        function_candidates=[
            {
                "function_id":fid,
                "evidence":evidence,
                "evidence_count":len(evidence),
                "status":"CANDIDATE",
                "mapping_methods":["DETERMINISTIC"],
            }
            for fid,evidence in evidence_by_function.items()
            if evidence
        ]

        non_activating_semantic_evidence=[]
        for rec in semantic_records:
            suppressed=rec.get("suppressed_function_candidates") or []
            if not suppressed:
                continue
            non_activating_semantic_evidence.append({
                "fact_id":rec.get("fact_id"),
                "fact_type":rec.get("fact_type"),
                "name":rec.get("qualified_name") or rec.get("name"),
                "operation_id":rec.get("operation_id"),
                "path":rec.get("path"),
                "method":rec.get("method"),
                "file":rec.get("file"),
                "line":rec.get("line"),
                "source_role":rec.get("source_role"),
                "operation_role":rec.get("operation_role"),
                "semantic_hints":suppressed,
                "reason":(
                    "SUPPORTING_SOURCE_ONLY"
                    if rec.get("source_role")=="SUPPORTING"
                    else "NON_COMMAND_OPERATION"
                ),
            })

        # LLM receives only unresolved, action-like semantic candidates and never source bodies.
        ambiguous=[]
        for rec in semantic_records:
            if rec.get("function_candidates"):
                continue

            if rec.get("fact_type")=="FUNCTION":
                if rec.get("source_role")!="PRODUCTION" or rec.get("operation_role")=="QUERY":
                    continue
                context_text=" ".join([
                    rec.get("qualified_name") or rec.get("name") or "",
                    " ".join(rec.get("callees") or []),
                    " ".join(rec.get("http_literals") or []),
                ])
                eligible=bool(rec.get("has_http_call")) or bool(AMBIGUOUS_ACTION_HINT.search(context_text))
                if not eligible:
                    continue
                ambiguous.append({
                    "candidate_id":f"AMB-{len(ambiguous)+1:05d}",
                    "source_fact_id":rec["fact_id"],
                    "fact_type":"FUNCTION",
                    "symbol":rec.get("qualified_name") or rec.get("name"),
                    "parameters":rec.get("params") or [],
                    "callees":rec.get("callees") or [],
                    "http_literals":rec.get("http_literals") or [],
                    "file":rec.get("file"),
                    "line":rec.get("line"),
                })
                continue

            if rec.get("fact_type")=="OPENAPI_OPERATION":
                if rec.get("source_role")!="PRODUCTION" or rec.get("operation_role")=="QUERY":
                    continue
                context_text=" ".join([
                    rec.get("operation_id") or "",
                    rec.get("summary") or "",
                    rec.get("path") or "",
                ])
                eligible=(
                    (rec.get("method") or "").upper() in {"POST","PUT","PATCH","DELETE"}
                    or bool(AMBIGUOUS_ACTION_HINT.search(context_text))
                )
                if not eligible:
                    continue
                ambiguous.append({
                    "candidate_id":f"AMB-{len(ambiguous)+1:05d}",
                    "source_fact_id":rec["fact_id"],
                    "fact_type":"OPENAPI_OPERATION",
                    "operation_id":rec.get("operation_id"),
                    "summary":rec.get("summary"),
                    "method":rec.get("method"),
                    "path":rec.get("path"),
                    "file":rec.get("file"),
                })

        # Retain result/state clues from deterministic functions and from functions eligible
        # for LLM semantic fallback. They still remain analyst-confirmed candidates.
        semantic_function_names={
            rec.get("qualified_name") for rec in functions if rec.get("function_candidates")
        }
        semantic_function_names.update(
            x.get("symbol") for x in ambiguous
            if x.get("fact_type")=="FUNCTION" and x.get("symbol")
        )
        result_tokens=[
            x for x in all_result_tokens
            if x.get("function") in semantic_function_names
        ]
        state_guards=[
            x for x in all_state_guards
            if x.get("function") in semantic_function_names
        ]

        # These are suggestions only. They never become confirmed TARA contexts automatically.
        result_candidate=bool(result_tokens)
        state_candidate=bool(state_guards)

        return {
            "schema_version":"cc-trace-source-evidence-1.0",
            "manifest":manifest,
            "scan_policy":{
                "target_code_executed":False,
                "target_code_imported":False,
                "dependencies_installed":False,
                "supported_suffixes":sorted(SUPPORTED_SUFFIXES),
            },
            "files":[
                {"path":sf.relpath,"sha256":sf.sha256,"source_role":sf.source_role}
                for sf in files
            ],
            "function_candidates":function_candidates,
            "non_activating_semantic_evidence":non_activating_semantic_evidence,
            "ambiguous_semantic_candidates":ambiguous,
            "result_status_candidate":{
                "status":"CANDIDATE" if result_candidate else "NOT_OBSERVED",
                "evidence":result_tokens[:50],
            },
            "state_acceptance_candidate":{
                "status":"CANDIDATE" if state_candidate else "NOT_OBSERVED",
                "evidence":state_guards[:50],
                "warning":"A source-level state guard does not prove vehicle-side command-acceptance semantics.",
            },
            "http_evidence":http_calls[:100],
            "parse_errors":parse_errors,
            "summary":{
                "supported_files":len(files),
                "production_files":sum(1 for sf in files if sf.source_role=="PRODUCTION"),
                "supporting_files":sum(1 for sf in files if sf.source_role=="SUPPORTING"),
                "function_candidates":len(function_candidates),
                "non_activating_semantic_evidence":len(non_activating_semantic_evidence),
                "ambiguous_semantic_candidates":len(ambiguous),
                "result_tokens":len(result_tokens),
                "state_guards":len(state_guards),
                "http_calls":len(http_calls),
                "parse_errors":len(parse_errors),
            }
        }
    finally:
        if temp_root:
            shutil.rmtree(temp_root,ignore_errors=True)
