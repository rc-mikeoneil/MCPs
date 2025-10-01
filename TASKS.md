# Proposed Follow-up Tasks

## Fix Typo
- Correct the product name casing in `cs_builder/readme.md` so it uses the official "CrowdStrike" spelling instead of "Crowdstrike" to match vendor branding in project documentation. 【F:cs_builder/readme.md†L1-L3】

## Fix Bug
- Update the natural-language parsing pipeline in `kql_builder/kql_builder.py` so that `_nl_to_structured` does not overwrite a `None` limit returned by `_parse_aggregation_from_text` (used when the user asks for "all" results). Right now the subsequent `_parse_limit_from_text` call resets the limit back to `100`, which contradicts the intent parsed from text. 【F:kql_builder/kql_builder.py†L315-L320】【F:kql_builder/kql_builder.py†L474-L510】

## Resolve Documentation Discrepancy
- Align the README tool list with the actual MCP tools exported by `server.py`. The README still documents a `refresh_schema` tool that no longer exists and omits that the registered function is named `suggest_columns_tool`, leading to confusion for clients looking up available commands. 【F:kql_builder/README.md†L15-L20】【F:kql_builder/server.py†L96-L138】

## Improve Testing
- Introduce unit tests for `suggest_columns` to validate keyword filtering and input validation paths, preventing regressions in how the function handles whitespace or non-string keywords. 【F:kql_builder/kql_builder.py†L229-L257】
