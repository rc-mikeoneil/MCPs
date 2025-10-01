# KQL Query Builder MCP Server

A Model Context Protocol (MCP) server that helps build Kusto Query Language (KQL) queries for Microsoft Defender XDR Advanced Hunting.

## Features

- **Schema Discovery**: Automatically scrapes and caches Microsoft Defender XDR table schemas
- **Intelligent Query Building**: Construct KQL queries from structured parameters or natural language intent
- **Table Suggestions**: Get column suggestions and example queries for Defender tables
- **Natural Language Processing**: Parse natural language descriptions into KQL queries
- **Docker Support**: Containerized deployment with persistent caching

## Tools

- `list_tables` - List available Advanced Hunting tables with optional keyword filtering
- `get_table_schema` - Get column information and documentation URL for a specific table
- `suggest_columns` - Suggest relevant columns for a table based on keywords
- `refresh_schema` - Refresh the local schema cache from Microsoft Learn
- `examples` - Get example KQL queries for a table
- `build_query` - Build a KQL query from parameters or natural language intent

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
