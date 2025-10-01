from __future__ import annotations
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path
import json
import re
import logging

from fastmcp import FastMCP  # FastMCP 2.x
from pydantic import BaseModel, Field

from schema_scraper import SchemaCache
from rag import RAGService
from kql_builder import (
    build_kql_query,
    suggest_columns,
    example_queries_for_table,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ----- Init & cache -----
mcp = FastMCP(name="kql-query-builder")  # keep the same logical name
DATA_DIR = Path(".cache"); DATA_DIR.mkdir(parents=True, exist_ok=True)
SCHEMA_PATH = DATA_DIR / "schema.json"
schema_cache = SchemaCache(schema_path=SCHEMA_PATH)
rag_service = RAGService(schema_cache=schema_cache, cache_dir=DATA_DIR)

# ----- Pydantic params (FastMCP will validate) -----
class ListTablesParams(BaseModel):
    keyword: Optional[str] = Field(None, description="Substring filter")

class GetSchemaParams(BaseModel):
    table: str

class SuggestColumnsParams(BaseModel):
    table: str
    keyword: Optional[str] = None



class BuildQueryParams(BaseModel):
    table: Optional[str] = None
    select: Optional[List[str]] = None
    where: Optional[List[str]] = None
    time_window: Optional[str] = None
    summarize: Optional[str] = None
    order_by: Optional[str] = None
    limit: Optional[int] = 100
    natural_language_intent: Optional[str] = None


class RetrieveContextParams(BaseModel):
    query: str
    k: int = Field(default=5, ge=1, le=20)

# ----- Tools -----

@mcp.tool
def list_tables(params: ListTablesParams) -> Dict[str, Any]:
    """List available Advanced Hunting tables (optionally filter by keyword)."""
    try:
        logger.info(f"Listing tables with keyword filter: {params.keyword}")
        schema = schema_cache.load_or_refresh()
        names = list(schema.keys())
        if params.keyword:
            kw = params.keyword.lower()
            names = [n for n in names if kw in n.lower()]
        result = {"tables": sorted(names)}
        logger.info(f"Found {len(names)} tables matching filter")
        return result
    except Exception as e:
        logger.error(f"Failed to list tables: {e}")
        raise

@mcp.tool
def get_table_schema(params: GetSchemaParams) -> Dict[str, Any]:
    """Return columns and docs URL for a given table."""
    try:
        logger.info(f"Getting schema for table: {params.table}")
        schema = schema_cache.load_or_refresh()
        table = params.table
        if table not in schema:
            try:
                from rapidfuzz import process
                choice, score, _ = process.extractOne(table, schema.keys())
                logger.warning(f"Table '{table}' not found, suggesting '{choice}' with score {score}")
                return {"error": f"Unknown table '{table}'. Did you mean '{choice}' (score {score})?"}
            except ImportError:
                logger.error("rapidfuzz not available for fuzzy matching")
                return {"error": f"Unknown table '{table}'"}
        result = {"table": table, "columns": schema[table]["columns"], "url": schema[table]["url"]}
        logger.info(f"Retrieved schema for table '{table}' with {len(schema[table]['columns'])} columns")
        return result
    except Exception as e:
        logger.error(f"Failed to get table schema for '{params.table}': {e}")
        raise

@mcp.tool
def suggest_columns_tool(params: SuggestColumnsParams) -> Dict[str, Any]:
    """Suggest columns for a table, optionally filtered by keyword."""
    try:
        logger.info(f"Suggesting columns for table '{params.table}' with keyword '{params.keyword}'")
        schema = schema_cache.load_or_refresh()
        suggestions = suggest_columns(schema, params.table, params.keyword)
        result = {"suggestions": suggestions}
        logger.info(f"Found {len(suggestions)} column suggestions")
        return result
    except Exception as e:
        logger.error(f"Failed to suggest columns for table '{params.table}': {e}")
        raise



@mcp.tool
def examples(params: GetSchemaParams) -> Dict[str, Any]:
    """Return example KQL for a given table."""
    try:
        logger.info(f"Getting examples for table: {params.table}")
        schema = schema_cache.load_or_refresh()
        examples = example_queries_for_table(schema, params.table)
        result = {"examples": examples}
        logger.info(f"Generated {len(examples)} examples for table '{params.table}'")
        return result
    except Exception as e:
        logger.error(f"Failed to get examples for table '{params.table}': {e}")
        raise

@mcp.tool
def retrieve_context(params: RetrieveContextParams) -> Dict[str, Any]:
    """Return the most relevant Defender schema passages for a natural language question."""

    try:
        logger.info(f"Retrieving context for query: {params.query}")
        hits = rag_service.search(params.query, k=params.k)
        logger.info(f"RAG service returned {len(hits)} matches")
        return {"matches": hits}
    except Exception as e:
        logger.error(f"Failed to retrieve context for '{params.query}': {e}")
        raise

@mcp.tool
def build_query(params: BuildQueryParams) -> Dict[str, Any]:
    """Build a KQL query from structured params or natural-language intent."""
    try:
        logger.info(f"Building KQL query for table: {params.table}")
        schema = schema_cache.load_or_refresh()
        payload = params.model_dump()
        kql, meta = build_kql_query(schema=schema, **payload)

        if payload.get("natural_language_intent"):
            try:
                context = rag_service.search(payload["natural_language_intent"], k=5)
                if context:
                    meta = {**meta, "rag_context": context}
            except Exception as exc:
                logger.warning(f"Failed to retrieve RAG context: {exc}")

        result = {"kql": kql, "meta": meta}
        logger.info(f"Successfully built KQL query for table '{meta.get('table', 'unknown')}'")
        return result
    except Exception as e:
        logger.error(f"Failed to build KQL query: {e}")
        raise

# ----- Entrypoint -----
if __name__ == "__main__":
    # FastMCP stdio runner; most clients expect stdio by default.
    # For TCP, keep using the socat wrapper shown below.
    mcp.run()
