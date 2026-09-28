# CC-TRACE

CC-TRACE analyzes connected-car source code, OpenAPI specifications, or analyst input and maps the observed system behavior to an ISO/SAE 21434-based reference TARA.

It combines static source analysis, optional LLM-assisted semantic mapping, analyst confirmation, and a deterministic TARA knowledge base.

## Workflow

```text
Source code / OpenAPI / analyst input
                |
                v
        Static source analysis
                |
        +-------+--------+
        |                |
   deterministic      ambiguous
      mapping          evidence
        |                |
        |          optional LLM
        |                |
        +-------+--------+
                |
        analyst confirmation
                |
                v
          Item Definition
                |
                v
       Reference TARA KB
                |
                v
      Applicability analysis
                |
                v
        JSON + Markdown output
```

## What CC-TRACE provides

- Interactive Item Definition
- Static Python source analysis
- OpenAPI JSON/YAML analysis
- Local directory, ZIP, and public GitHub repository input
- Command vs. query/telemetry separation
- Qualified function and method evidence
- Lightweight architecture reachability checks
- Function-scoped vehicle-state analysis
- Optional Gemini, OpenAI, Anthropic, and Groq assistance for ambiguous input
- Analyst confirmation before ambiguous mappings are applied
- Deterministic Attack Feasibility, Risk, Treatment, Goal/Claim, and CAL processing from the reference knowledge base
- Traceable JSON and Markdown outputs

The bundled connected-car reference TARA contains 7 Item Functions, 13 Assets, 17 Damage Scenarios, 43 Threat Scenarios, and 16 Attack Paths.

## Installation

Python 3.11 or later is required.

```powershell
git clone https://github.com/0xsuyeon/cc-trace.git
cd cc-trace
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
```

Check the installation:

```powershell
.\.venv\Scripts\cc-trace.exe validate
```

## Usage

### Interactive analysis

```powershell
.\.venv\Scripts\cc-trace.exe analyze
```

CC-TRACE asks for the system information required to construct the Item Definition and writes the resulting TARA analysis to `cc_trace_output/`.

### Analyze a local project

```powershell
.\.venv\Scripts\cc-trace.exe analyze `
  --source "C:\path\to\vehicle-api" `
  --output-dir .\cc_trace_output
```

### Analyze a public GitHub repository

```powershell
.\.venv\Scripts\cc-trace.exe analyze `
  --source "https://github.com/Hyundai-Kia-Connect/hyundai_kia_connect_api" `
  --llm gemini `
  --output-dir .\hyundai_kia_cc_trace_output
```

For a GitHub URL, CC-TRACE performs a shallow clone and analyzes the supported source files locally.

### Inspect source evidence without running the full TARA workflow

```powershell
.\.venv\Scripts\cc-trace.exe inspect-source `
  "https://github.com/Hyundai-Kia-Connect/hyundai_kia_connect_api" `
  --output .\source_evidence.json
```

## LLM assistance

LLM use is optional. It is used when deterministic rules cannot confidently map source/API evidence, or when an interactive answer is provided in natural language.

Supported providers:

| Provider | CLI value | API key |
|---|---|---|
| Gemini | `gemini` | `GEMINI_API_KEY` |
| OpenAI | `openai`, `gpt` | `OPENAI_API_KEY` |
| Anthropic | `anthropic`, `claude` | `ANTHROPIC_API_KEY` |
| Groq | `groq` | `GROQ_API_KEY` |

Example:

```powershell
.\.venv\Scripts\cc-trace.exe analyze `
  --source "https://github.com/Hyundai-Kia-Connect/hyundai_kia_connect_api" `
  --llm gemini
```

If the selected provider key is not present in the environment, the CLI asks for it using hidden input.

Ambiguous source evidence is mapped only to the local Item Function taxonomy (`IF-01` to `IF-07`) or `UNKNOWN`. The mapping is validated locally and shown to the analyst before it is used.

## Supported source input

- Python (`.py`)
- OpenAPI JSON
- OpenAPI YAML
- local file or directory
- ZIP archive
- public GitHub repository URL

Target source is parsed statically; it is not imported or executed by the analyzer.

## Output

A source-assisted run typically creates:

```text
cc_trace_output/
├── item_definition.json
├── source_evidence.json
├── semantic_mapping.json
├── tara.json
└── report.md
```

`semantic_mapping.json` is created when LLM-assisted mapping is used.

## Method

CC-TRACE keeps the analysis pipeline separated into three parts:

```text
TARA method knowledge
        +
connected-car reference TARA
        +
source / Item applicability evidence
```

The reference TARA is stored under `cc_trace_kb/knowledge/domain/`, and the calculation method is stored under `cc_trace_kb/knowledge/method/`.

Detailed documentation:

- [`docs/methodology.md`](docs/methodology.md)
- [`docs/source-analysis.md`](docs/source-analysis.md)
- [`docs/llm-assistance.md`](docs/llm-assistance.md)
- [`docs/validation.md`](docs/validation.md)

## Validation

The repository includes unit, integration, and adversarial regression tests together with canonical TARA consistency checks.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\cc-trace.exe validate
```

The current repository passes 80 regression tests and 283 report-alignment checks. The validation scope is documented in [`docs/validation.md`](docs/validation.md).

## Repository structure

```text
cc-trace/
├── cc_trace_kb/          # CLI, source analyzer, semantic mapper, TARA engine, knowledge base
├── docs/                 # Method and validation documentation
├── examples/             # Example inputs
├── tests/                # Regression tests
├── tools/                # Validation and reproducibility utilities
├── .github/workflows/    # CI
├── CITATION.cff
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
├── pyproject.toml
└── README.md
```

## Citation

Citation metadata is provided in [`CITATION.cff`](CITATION.cff).

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
