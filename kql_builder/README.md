# KQL Query Builder MCP Server

A Model Context Protocol (MCP) server that helps build Kusto Query Language (KQL) queries for Microsoft Defender XDR Advanced Hunting.

## Features

- **Schema Discovery**: Automatically scrapes and caches Microsoft Defender XDR table schemas
- **Intelligent Query Building**: Construct KQL queries from structured parameters or natural language intent
- **Table Suggestions**: Get column suggestions and example queries for Defender tables
- **Natural Language Processing**: Parse natural language descriptions into KQL queries
- **Retrieval-Augmented Context**: Embed schema documentation and retrieve the most relevant passages to guide query building
- **Docker Support**: Containerized deployment with persistent caching

## Tools

- `list_tables` - List available Advanced Hunting tables with optional keyword filtering
- `get_table_schema` - Get column information and documentation URL for a specific table
- `suggest_columns` - Suggest relevant columns for a table based on keywords
- `refresh_schema` - Refresh the local schema cache from Microsoft Learn
- `examples` - Get example KQL queries for a table
- `build_query` - Build a KQL query from parameters or natural language intent
- `retrieve_context` - Retrieve Defender schema context passages related to a natural language question

## Installation

### Using Docker (Recommended)

```bash
# Build and run with Docker Compose
docker-compose up --build

# Or build manually
docker build -t kql-mcp .
docker run -v kql_cache:/app/.cache kql-mcp
```

### Local Installation

```bash
pip install -r requirements.txt
python server.py
```

## Configuration

- Schema cache is stored in `.cache/schema.json`
- Configure logging level via environment variables
- Supports both stdio and TCP transport modes

## Dependencies

- Python 3.12+
- FastMCP 2.x
- httpx, beautifulsoup4, lxml for web scraping
- rapidfuzz for fuzzy string matching
- pydantic for data validation

## Usage

Connect this MCP server to your MCP-compatible client to start building KQL queries interactively.

### Retrieval-Augmented Workflows

1. Call `retrieve_context` with a natural language question to surface the most relevant Defender schema passages (table descriptions, column metadata, and documentation URLs).
2. Provide the resulting passages as context to your AI assistant, or rely on `build_query`'s response metadata—when you pass `natural_language_intent`, the tool automatically attaches a `rag_context` field containing the top matches.

The first invocation of the retrieval tool or a natural-language query build will download the embedding model and generate a cached FAISS index in `.cache/`. Subsequent runs reuse the cache for fast lookups.
