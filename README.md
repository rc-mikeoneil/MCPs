# MCPs

A collection of experimental Model Context Protocol (MCP) servers that help security analysts generate hunting queries from natural language prompts and other structured inputs.

## Repository Structure

| Directory | Description |
| --- | --- |
| **`kql_builder/`** | Production-ready MCP server for Microsoft Defender XDR Advanced Hunting. Provides schema scraping, natural-language-to-KQL conversion, retrieval-augmented grounding, and metadata-rich query logging utilities. |
| **`cs_builder/`** | Early exploration of a CrowdStrike Humio query assistant. Houses extracted reference material that will be converted into a structured schema for future MCP tooling. |
| **`tests/`** | Regression tests that validate natural-language parsing, table defaults, and guardrails for the KQL builder. |

Each server exposes a FastMCP-compatible `server.py` entry point and follows the same `.cache/` convention for persisting schemas and embeddings.

## Key Features

### Microsoft Defender KQL Builder
- **Automatic schema discovery** – `schema_scraper.py` keeps a cached copy of Defender table metadata so tools like `list_tables`, `get_table_schema`, and `suggest_columns_tool` respond instantly.
- **Natural language query synthesis** – `build_kql_query` translates intent such as "top 5 processes" into validated KQL while applying safety checks for table names, column selection, and where clauses.
- **Retrieval-augmented grounding** – The `rag.py` service embeds Microsoft Learn documentation and returns the most relevant passages when building or contextualising a query.
- **Query validation & logging utilities** – `query_logging.py` provides helpers to capture syntax, schema, and execution metadata for every generated query, enabling downstream auditing workflows.
- **Docker-first workflow** – `docker-compose.yml` and the accompanying `Dockerfile` provide a batteries-included setup with persistent caches, ideal for running inside sandboxes or CI agents.

### CrowdStrike Humio Builder (Preview)
- Extracted reference events (`cs_builder/extracted_events.html`) and notes on converting documentation into JSON drive an upcoming MCP toolset for Humio queries.

## Getting Started

1. **Install dependencies**
   ```bash
   cd kql_builder
   pip install -r requirements.txt
   ```
2. **Run the KQL MCP server**
   ```bash
   python server.py
   ```
   The server exposes tools such as `list_tables`, `get_table_schema`, `suggest_columns_tool`, `examples`, `retrieve_context`, and `build_query` to any MCP-compatible client.
3. **(Optional) Docker workflow**
   ```bash
   docker compose up --build
   ```
   This launches the FastMCP server with a persistent `.cache/` volume for schemas and embeddings. The Docker image exposes both stdio (default) and TCP transports to simplify client integration.

4. **Connect from your MCP client**
   - For stdio clients (e.g. Cursor, Continue), point the client to `python server.py` within `kql_builder/`.
   - For TCP clients, use the supplied `docker-compose` service or wrap `python server.py` with `socat` as demonstrated in `kql_builder/entrypoint.sh`.

### CrowdStrike Humio Builder Preview

Until the Humio tooling ships, you can explore the scraped documentation in `cs_builder/extracted_events.html`. Upcoming work includes:
- Converting the HTML reference into JSON schema assets.
- Mirroring the KQL builder tool surface for Humio searches.
- Adding regression tests once the server stabilises.

## Testing

Run the unit suite from the repository root:

```bash
pytest
```

The existing tests verify that natural-language intents respect requested limits and that defaults remain stable.

You can also target individual modules:

```bash
pytest tests/test_kql_builder.py
```

## Roadmap

- Finish converting the CrowdStrike documentation into a reusable schema and expose an MCP server alongside the Defender builder.
- Add richer unit coverage for column suggestion, aggregation parsing, and query logging.
- Publish example MCP client configurations for popular editors and notebooks.

