# KQL Query Builder MCP Server

A Model Context Protocol (MCP) server that helps build Kusto Query Language (KQL) queries for Microsoft Defender XDR Advanced Hunting.

## Features

- **Schema Discovery** – `schema_scraper.py` automatically scrapes and caches Microsoft Defender XDR table schemas for instant responses.
- **Intelligent Query Building** – `kql_builder.build_kql_query` constructs validated KQL from structured parameters or natural-language intent, applying guardrails for limits and default time windows.
- **Table & Column Suggestions** – `suggest_columns` and `example_queries_for_table` surface helpful column metadata and starter hunts for each table.
- **Retrieval-Augmented Context** – `rag.py` embeds schema documentation and retrieves the most relevant passages to guide query building. Natural-language queries automatically include the retrieved passages in the tool metadata.
- **Query Logging Utilities** – `query_logging.py` centralises audit-ready metadata for every generated query so you can store outputs downstream.
- **Docker Support** – `Dockerfile` and `docker-compose.yml` provide a container-first workflow with persistent caching for schemas and embeddings.

## Tools

All tools are registered via FastMCP inside `server.py`:

- `list_tables` – List available Advanced Hunting tables with optional keyword filtering.
- `get_table_schema` – Return column information and the documentation URL for a specific table.
- `suggest_columns_tool` – Suggest relevant columns for a table based on optional keywords (the `_tool` suffix keeps legacy clients compatible).
- `examples` – Surface example KQL queries for a table.
- `build_query` – Build a KQL query from structured parameters or natural-language intent. When `natural_language_intent` is provided the response metadata includes a `rag_context` field with matched passages.
- `retrieve_context` – Retrieve Defender schema context passages related to a natural language question.

The schema cache refreshes on demand; delete `.cache/schema.json` to force a re-scrape or call `schema_scraper.SchemaCache.refresh()` from a Python shell.

## Installation

### Prerequisites

- Python 3.12+
- `pip` for dependency installation
- Optional: Docker 24+ and Docker Compose v2 for container workflows

### Using Docker (Recommended)

```bash
# Build and run with Docker Compose
docker-compose up --build

# Or build manually
docker build -t kql-mcp .
docker run -v kql_cache:/app/.cache kql-mcp
```

The Docker image exposes the default FastMCP stdio transport. To enable TCP, replicate the `socat` wrapper shown in `entrypoint.sh` or publish the service via Docker networking.

### Local Installation

```bash
pip install -r requirements.txt
python server.py
```

If you prefer an isolated environment, create a virtual environment first:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

- Schema cache is stored in `.cache/schema.json` and automatically created on first run.
- Configure logging level via the `LOG_LEVEL` environment variable (defaults to `INFO`).
- Supports both stdio (default) and TCP transport modes; see `entrypoint.sh` for a reference TCP setup.

## Dependencies

Core dependencies are listed in `requirements.txt` and installed via the commands above:

- FastMCP 2.x for tool registration and stdio/TCP transports.
- httpx, beautifulsoup4, and lxml for schema scraping.
- rapidfuzz for fuzzy table matching when a schema name is slightly off.
- pydantic for parameter validation.

## Usage

Connect this MCP server to your MCP-compatible client to start building KQL queries interactively. Typical workflows include:

### Retrieval-Augmented Workflows

1. Call `retrieve_context` with a natural language question to surface the most relevant Defender schema passages (table descriptions, column metadata, and documentation URLs).
2. Provide the resulting passages as context to your AI assistant, or rely on `build_query`'s response metadata—when you pass `natural_language_intent`, the tool automatically attaches a `rag_context` field containing the top matches.

The first invocation of the retrieval tool or a natural-language query build will download the embedding model and generate a cached FAISS index in `.cache/`. Subsequent runs reuse the cache for fast lookups.

### Testing

From the repository root run:

```bash
pytest tests/test_kql_builder.py -k natural_language
```

The tests assert limit enforcement, table defaults, and guardrails around natural-language parsing.
