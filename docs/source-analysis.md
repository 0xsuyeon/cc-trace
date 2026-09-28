# Source Analysis

CC-TRACE extracts source evidence without executing or importing the target project.

## Supported input

- Python source (`.py`)
- OpenAPI JSON
- OpenAPI YAML
- local file or directory
- ZIP archive
- public GitHub repository URL

GitHub repositories are acquired with a shallow clone.

## Evidence extraction

The analyzer records function and API evidence such as:

- qualified Python symbol
- parameters
- called symbols
- HTTP method and endpoint literals
- result/status indicators
- vehicle-state guard indicators
- source file and location

Same-name methods in different classes are kept separate through qualified symbol identity.

## Command and query separation

Read/query/telemetry operations do not activate remote-command Item Functions. Command activation is based on operation semantics rather than HTTP method alone.

## Source roles

Files under normal implementation paths are treated as production evidence. Files under common test/example/fixture/sample paths are retained as supporting evidence but cannot activate an Item Function by themselves.

## Vehicle state

The analyzer recognizes common state expressions including:

```python
vehicle.speed
state["speed"]
state.get("gear")
```

State applicability is tracked per Item Function rather than as an Item-wide flag.

## Output

`source_evidence.json` preserves the source facts and analyst decisions used to build the Item Definition.
