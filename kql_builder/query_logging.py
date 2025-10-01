"""Utility module providing comprehensive query logging and validation helpers.

This module is intentionally framework agnostic so it can be imported both by the
FastMCP server as well as unit tests.  The main entry point is ``QueryLogger``
which stores rich metadata about every generated KQL query in JSON Lines format.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import json
import random
import re
import threading
import time
import uuid
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Data containers


@dataclass
class ValidationResults:
    """Container describing validation outcomes for a generated query."""

    syntax_valid: Optional[bool] = None
    schema_valid: Optional[bool] = None
    executed: Optional[bool] = None
    execution_time_ms: Optional[float] = None
    row_count: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a JSON serialisable dictionary."""

        return {
            "syntax_valid": self.syntax_valid,
            "schema_valid": self.schema_valid,
            "executed": self.executed,
            "execution_time_ms": self.execution_time_ms,
            "row_count": self.row_count,
            "details": self.details or None,
        }


# ---------------------------------------------------------------------------
# Validation helpers


_PAREN_PAIRS = {"(": ")", "[": "]", "{": "}"}


def validate_syntax(query: str) -> Tuple[bool, Dict[str, Any]]:
    """Perform light-weight KQL syntax validation.

    This does not aim to be a full parser; the goal is to catch obvious
    structural mistakes that the downstream Kusto engine would reject, such as
    unterminated parenthesis or malformed pipe chains.

    Returns a tuple of ``(is_valid, details)``.  ``details`` contains helpful
    error messages that will be stored in the query log.
    """

    errors: List[str] = []

    if not query or not isinstance(query, str):
        errors.append("Query must be a non-empty string")
        return False, {"errors": errors}

    stack: List[str] = []
    for idx, char in enumerate(query):
        if char in _PAREN_PAIRS:
            stack.append(char)
        elif char in _PAREN_PAIRS.values():
            if not stack:
                errors.append(f"Unmatched closing bracket '{char}' at position {idx}")
                break
            open_char = stack.pop()
            if _PAREN_PAIRS[open_char] != char:
                errors.append(
                    f"Mismatched brackets: expected '{_PAREN_PAIRS[open_char]}', "
                    f"found '{char}' at position {idx}"
                )
                break

    if stack:
        errors.append("Unclosed bracket(s) detected: " + ", ".join(stack))

    # Basic pipe usage sanity check: avoid ``||`` or pipe at the end.
    stripped = query.strip()
    if stripped.endswith("|"):
        errors.append("Query ends with a pipe operator")
    if "||" in query:
        errors.append("Double pipe sequence detected")

    is_valid = not errors
    return is_valid, {"errors": errors or None}


def _extract_candidate_tables(query: str) -> List[str]:
    """Very small heuristic to extract table names from a KQL statement."""

    # Match constructs like ``<table> |`` or ``from <table>``.
    candidates: List[str] = []
    table_pipe_match = re.match(r"\s*([A-Za-z0-9_]+)\s*\|", query)
    if table_pipe_match:
        candidates.append(table_pipe_match.group(1))

    candidates.extend(re.findall(r"from\s+([A-Za-z0-9_]+)", query, flags=re.IGNORECASE))
    return list(dict.fromkeys(candidates))  # Preserve order, remove duplicates.


def _extract_candidate_columns(query: str) -> Iterable[str]:
    """Extract column identifiers from ``project``/``extend`` clauses."""

    column_patterns = [
        r"project\s+([^\|]+)",
        r"extend\s+([^\|]+)",
        r"summarize\s+([^\|]+) by ([^\|]+)",
    ]
    for pattern in column_patterns:
        for match in re.finditer(pattern, query, flags=re.IGNORECASE):
            # Split on commas and whitespace.
            section = match.group(1)
            tokens = re.split(r"[,\s]+", section)
            for token in tokens:
                token = token.strip()
                if token and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", token):
                    yield token


def validate_schema(query: str, schemas: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    """Verify that referenced tables and columns exist in the provided schema."""

    details: Dict[str, Any] = {"missing_tables": [], "missing_columns": []}

    if not schemas:
        details["error"] = "Schema dictionary is empty"
        return False, details

    table_candidates = _extract_candidate_tables(query)

    missing_tables: List[str] = []
    columns_by_table: Dict[str, List[str]] = {}

    for table in table_candidates:
        table_schema = schemas.get(table)
        if not table_schema:
            missing_tables.append(table)
            continue
        columns = table_schema.get("columns", [])
        column_names = {col.get("name") for col in columns if isinstance(col, dict)}
        columns_by_table[table] = [col for col in column_names if col]

    missing_columns: List[str] = []
    for column in _extract_candidate_columns(query):
        if not any(column in cols for cols in columns_by_table.values()):
            missing_columns.append(column)

    details["missing_tables"] = missing_tables or None
    details["missing_columns"] = missing_columns or None

    is_valid = not missing_tables and not missing_columns
    return is_valid, details


def test_execution(
    query: str,
    executor: Optional[Callable[[str], Dict[str, Any]]] = None,
    timeout: float = 10.0,
) -> Tuple[bool, Dict[str, Any]]:
    """Execute a query using the provided ``executor`` with a timeout.

    ``executor`` should be a callable that takes a query string and returns a
    dictionary containing ``row_count`` and ``execution_time_ms`` keys.  When no
    executor is supplied the function returns ``executed=False`` with details
    explaining the missing sandbox.
    """

    if executor is None:
        return False, {"error": "No execution sandbox provided"}

    result: Dict[str, Any] = {}
    error_holder: List[str] = []

    def _run() -> None:
        nonlocal result
        try:
            start = time.perf_counter()
            execution_payload = executor(query)
            elapsed_ms = (time.perf_counter() - start) * 1000
            result = {
                "row_count": execution_payload.get("row_count"),
                "execution_time_ms": execution_payload.get(
                    "execution_time_ms", elapsed_ms
                ),
                "raw_result": execution_payload,
            }
        except Exception as exc:  # pragma: no cover - defensive guard
            error_holder.append(str(exc))

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(timeout)

    if thread.is_alive():
        error_holder.append("Execution timed out")
        return False, {"error": error_holder[-1]}

    if error_holder:
        return False, {"error": error_holder[-1]}

    return True, result


def calculate_quality_score(query: str, execution_result: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
    """Calculate a heuristic quality score in the range [0, 100]."""

    score = 0.0
    reasons: List[str] = []

    if re.search(r"ago\s*\(", query, flags=re.IGNORECASE):
        score += 25
    else:
        reasons.append("Missing relative time filter (e.g. ago()).")

    if re.search(r"\|\s*project\b", query, flags=re.IGNORECASE):
        score += 20
    else:
        reasons.append("Query does not use project to limit returned columns.")

    row_count = execution_result.get("row_count")
    if isinstance(row_count, int):
        if row_count == 0:
            reasons.append("Query returned zero rows.")
        elif 1 <= row_count <= 10000:
            score += 20
        elif row_count > 50000:
            reasons.append("Query returns more than 50k rows; consider additional filters.")
        else:
            score += 10
    else:
        reasons.append("Row count unavailable; unable to judge selectivity.")

    execution_time = execution_result.get("execution_time_ms")
    if isinstance(execution_time, (int, float)):
        if execution_time < 1000:
            score += 20
        elif execution_time > 10000:
            reasons.append("Execution time exceeds 10 seconds.")
        else:
            score += 10
    else:
        reasons.append("Execution time not reported.")

    anti_patterns = [
        (r"project-away\s+\*", "Uses project-away * which removes all columns."),
        (r"\|\s*take\s+\d{6,}", "take operator requests an extremely high limit."),
        (r"union\s+\*", "Wildcard union detected; can be expensive."),
    ]
    for pattern, message in anti_patterns:
        if re.search(pattern, query, flags=re.IGNORECASE):
            reasons.append(message)
            score -= 10

    # Clamp score between 0 and 100
    score = max(0.0, min(100.0, score))

    return score, {"reasons": reasons or None}


def determine_confidence(
    validation: ValidationResults,
    quality_score: float,
) -> str:
    """Assign a confidence label based on validation outcomes."""

    if not validation.syntax_valid or not validation.schema_valid or not validation.executed:
        return "low_confidence"

    if quality_score >= 80:
        return "high_confidence"

    return "medium_confidence"


# ---------------------------------------------------------------------------
# Query logger implementation


class QueryLogger:
    """Persist rich query telemetry in JSON Lines format."""

    def __init__(
        self,
        log_path: Path | str,
        review_sample_rate: float = 0.1,
        random_seed: Optional[int] = None,
    ) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.review_sample_rate = review_sample_rate
        self._random = random.Random(random_seed)

        # Ensure the log file exists so downstream operations like reading work.
        if not self.log_path.exists():
            self.log_path.touch()

    # ------------------------------------------------------------------
    # Logging helpers

    def log_query(
        self,
        user_query: str,
        retrieved_schemas: List[Dict[str, Any]],
        mcp_examples: List[str],
        generated_query: str,
    ) -> str:
        """Append a fresh query entry to the JSONL log and return its ID."""

        query_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        entry = {
            "query_id": query_id,
            "timestamp": timestamp,
            "user_query": user_query,
            "retrieved_schemas": retrieved_schemas,
            "mcp_examples": mcp_examples,
            "generated_query": generated_query,
            "validation_results": ValidationResults().to_dict(),
            "quality_score": None,
            "confidence_level": None,
            "flagged_for_review": False,
            "user_feedback": None,
        }

        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

        return query_id

    # ------------------------------------------------------------------
    # Update helpers

    def _load_entries(self) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        with self.log_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:  # pragma: no cover - defensive guard
                    continue
        return entries

    def _write_entries(self, entries: List[Dict[str, Any]]) -> None:
        with self.log_path.open("w", encoding="utf-8") as fh:
            for entry in entries:
                fh.write(json.dumps(entry) + "\n")

    def update_validation(
        self,
        query_id: str,
        validation: ValidationResults,
        quality_score: float,
        quality_details: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update the log entry with validation results and derived metadata."""

        entries = self._load_entries()
        updated_entry: Optional[Dict[str, Any]] = None

        for entry in entries:
            if entry.get("query_id") == query_id:
                entry["validation_results"] = validation.to_dict()
                entry["quality_score"] = quality_score
                entry.setdefault("meta", {})
                entry["meta"]["quality_details"] = quality_details or None

                confidence = determine_confidence(validation, quality_score)
                entry["confidence_level"] = confidence

                flagged = confidence == "low_confidence"
                if not flagged and confidence in {"medium_confidence", "high_confidence"}:
                    flagged = self._random.random() < self.review_sample_rate
                entry["flagged_for_review"] = flagged

                updated_entry = entry
                break

        if updated_entry is None:
            raise ValueError(f"Query ID {query_id} not found in log")

        self._write_entries(entries)
        return updated_entry

    # ------------------------------------------------------------------
    # Review utilities

    def export_for_review(self, destination: Path | str) -> List[Dict[str, Any]]:
        """Export all flagged queries to ``destination`` (JSON Lines)."""

        flagged_entries = [
            entry for entry in self._load_entries() if entry.get("flagged_for_review")
        ]

        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)

        with destination_path.open("w", encoding="utf-8") as fh:
            for entry in flagged_entries:
                fh.write(json.dumps(entry) + "\n")

        return flagged_entries

    # ------------------------------------------------------------------
    # Feedback collection

    def record_feedback(self, query_id: str, feedback: Optional[str]) -> Dict[str, Any]:
        """Persist human feedback (e.g., thumbs up/down) for a logged query."""

        if feedback is not None and feedback not in {"thumbs_up", "thumbs_down"}:
            raise ValueError("Feedback must be 'thumbs_up', 'thumbs_down', or None")

        entries = self._load_entries()
        updated_entry: Optional[Dict[str, Any]] = None
        for entry in entries:
            if entry.get("query_id") == query_id:
                entry["user_feedback"] = feedback
                updated_entry = entry
                break

        if updated_entry is None:
            raise ValueError(f"Query ID {query_id} not found in log")

        self._write_entries(entries)
        return updated_entry


# ---------------------------------------------------------------------------
# Example usage


def _example_executor(_: str) -> Dict[str, Any]:
    """A dummy executor used in the example at the bottom of the file."""

    # Pretend the query took ~250ms and produced 123 rows.  A real deployment
    # would connect to a test cluster instead.
    time.sleep(0.05)
    return {"row_count": 123, "execution_time_ms": 250}


def example_usage() -> Dict[str, Any]:
    """Demonstrate how the logger integrates with the query pipeline."""

    logger = QueryLogger(log_path=Path(".cache/query_logs.jsonl"), random_seed=42)

    user_question = "Show me the last 24 hours of sign-in failures"
    retrieved_schemas = [
        {
            "table": "SigninLogs",
            "columns": [
                {"name": "TimeGenerated"},
                {"name": "UserPrincipalName"},
                {"name": "ResultType"},
            ],
        }
    ]
    mcp_examples = ["SigninLogs | where ResultType != 0 | summarize count()"]
    generated_query = (
        "SigninLogs | where TimeGenerated > ago(24h) and ResultType != 0 "
        "| project TimeGenerated, UserPrincipalName, ResultType"
    )

    query_id = logger.log_query(
        user_query=user_question,
        retrieved_schemas=retrieved_schemas,
        mcp_examples=mcp_examples,
        generated_query=generated_query,
    )

    # ----- Validations -----
    syntax_valid, syntax_details = validate_syntax(generated_query)
    schema_map = {item["table"]: item for item in retrieved_schemas}
    schema_valid, schema_details = validate_schema(generated_query, schema_map)
    executed, execution_result = test_execution(generated_query, executor=_example_executor)

    validation_results = ValidationResults(
        syntax_valid=syntax_valid,
        schema_valid=schema_valid,
        executed=executed,
        execution_time_ms=execution_result.get("execution_time_ms") if executed else None,
        row_count=execution_result.get("row_count") if executed else None,
        details={
            "syntax": syntax_details,
            "schema": schema_details,
            "execution": execution_result if executed else {"error": execution_result.get("error")},
        },
    )

    quality_score, quality_details = calculate_quality_score(generated_query, execution_result)
    updated_entry = logger.update_validation(query_id, validation_results, quality_score, quality_details)

    # Example human feedback recorded later.
    logger.record_feedback(query_id, "thumbs_up")

    return updated_entry


__all__ = [
    "QueryLogger",
    "ValidationResults",
    "validate_syntax",
    "validate_schema",
    "test_execution",
    "calculate_quality_score",
    "determine_confidence",
    "example_usage",
]

