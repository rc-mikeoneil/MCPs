# Carbon Black Cloud EDR Query Builder MCP Server

This Model Context Protocol (MCP) server helps you explore the Carbon Black Cloud
EDR schema and build valid search queries. It follows the same design as the
`kql_builder` service in this repository, but it is tailored to Carbon Black's
Lucene-inspired query syntax and metadata.

## Features

- **Schema-aware tools** – The server loads `cb_edr_schema.json` and exposes
  helpers to list search types, inspect available fields, review operators, and
  retrieve best practices or example queries.
- **Natural-language assistance** – Provide a high-level intent and the
  `build_query` tool will extract hashes, process names, IPs, and other
  indicators to assemble a Carbon Black query with sensible defaults.
- **Container-first workflow** – A lightweight Dockerfile and optional
  `docker-compose.yml` make it easy to run the MCP server in an isolated
  environment.

## Quick start

```bash
# From the repository root
cd cbc_builder
pip install -r requirements.txt
python server.py
```

Or build the Docker image:

```bash
docker build -t cbc-mcp .
docker run --rm -it cbc-mcp
```

## Available tools

- `list_search_types` – Inspect supported Carbon Black search types such as
  process, binary, and alert searches.
- `get_fields` – Retrieve the available fields for a given search type,
  including descriptions from the schema file.
- `get_operator_reference` – Surface logical and wildcard operator guidance
  from the schema metadata.
- `get_best_practices` – Return the published query-building best practices.
- `get_example_queries` – Fetch representative example queries by category.
- `build_query` – Build a Carbon Black Cloud EDR query from structured
  parameters or from a natural-language description.

The `build_query` tool returns both the composed query string and metadata about
the recognised indicators and applied defaults, making it easier to present the
result or offer further guidance to the user.

