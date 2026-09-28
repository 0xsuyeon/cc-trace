# LLM Assistance

CC-TRACE uses LLM providers as a bounded semantic mapper.

## When a provider is called

A provider is used only when:

- a source/API candidate remains ambiguous after deterministic mapping, or
- an interactive natural-language answer needs to be converted into structured Item facts

Direct numeric selections and explicit `y/n` answers do not require an LLM call.

## Supported providers

| Provider | CLI aliases | API-key environment variable |
|---|---|---|
| Gemini | `gemini`, `google` | `GEMINI_API_KEY` |
| OpenAI | `openai`, `gpt` | `OPENAI_API_KEY` |
| Anthropic | `anthropic`, `claude` | `ANTHROPIC_API_KEY` |
| Groq | `groq` | `GROQ_API_KEY` |

If the environment variable is absent, the interactive CLI asks for the key using hidden input.

## Output constraint

Ambiguous source candidates are mapped to:

```text
IF-01
IF-02
IF-03
IF-04
IF-05
IF-06
IF-07
UNKNOWN
```

Candidate IDs, taxonomy values, duplicates, and missing outputs are validated locally before a mapping is shown to the analyst.

## Data sent to providers

CC-TRACE sends bounded candidate metadata such as symbol names, parameters, callees, endpoint literals, file metadata, and source-fact IDs. Complete source-file bodies are not included in semantic-mapping requests.

## Gemini batching

Gemini ambiguous candidates are sent in batches of 12. The current client uses JSON structured output, low thinking for the bounded classification task, and a 60-second default request timeout.

## Analysis artifacts

When LLM assistance is used, `semantic_mapping.json` records provider, model, mapping status, accepted mappings, rejections, and request metadata. API keys are not written to analysis artifacts.
