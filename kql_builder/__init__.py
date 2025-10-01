"""kql_builder package initialization."""

from .kql_builder import build_kql_query, suggest_columns, example_queries_for_table
from .query_logging import (
    QueryLogger,
    ValidationResults,
    calculate_quality_score,
    determine_confidence,
    example_usage,
    test_execution,
    validate_schema,
    validate_syntax,
)

__all__ = [
    "build_kql_query",
    "QueryLogger",
    "ValidationResults",
    "calculate_quality_score",
    "determine_confidence",
    "example_usage",
    "test_execution",
    "validate_schema",
    "validate_syntax",
    "suggest_columns",
    "example_queries_for_table",
]
