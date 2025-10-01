from __future__ import annotations
from typing import Dict, Any, List, Tuple, Optional
import re
import logging

logger = logging.getLogger(__name__)

DEFAULT_TIME_WINDOW = "7d"

def _quote(val: str) -> str:
    """Safely quote a string value for KQL."""
    if not isinstance(val, str):
        val = str(val)
    return "'" + val.replace("\\", "\\\\").replace("'", "\\'") + "'"

def _validate_table_name(table: str, schema: Dict[str, Any]) -> str:
    """Validate and normalize table name."""
    if not table or not isinstance(table, str):
        raise ValueError("Table name must be a non-empty string")

    table = table.strip()
    if not table:
        raise ValueError("Table name cannot be empty or whitespace")

    # Check for potentially dangerous characters
    if any(char in table for char in [';', '|', '\n', '\r', '\t']):
        raise ValueError("Table name contains invalid characters")

    return table

def _validate_column_names(columns: List[str], schema: Dict[str, Any], table: str) -> List[str]:
    """Validate column names against schema."""
    if not columns:
        return columns

    if not isinstance(columns, list):
        raise ValueError("Columns must be a list")

    available_columns = {col["name"] for col in schema.get(table, {}).get("columns", [])}

    validated_columns = []
    for col in columns:
        if not isinstance(col, str):
            raise ValueError(f"Column name must be a string, got {type(col)}")

        col = col.strip()
        if not col:
            continue

        # Check for dangerous characters
        if any(char in col for char in [';', '|', '\n', '\r', '\t', "'", '"']):
            raise ValueError(f"Column name '{col}' contains invalid characters")

        # Check if column exists in schema (warning only, don't fail)
        if available_columns and col not in available_columns:
            logger.warning(f"Column '{col}' not found in schema for table '{table}'")

        validated_columns.append(col)

    return validated_columns

def _validate_where_conditions(conditions: List[str]) -> List[str]:
    """Validate WHERE conditions for safety."""
    if not conditions:
        return conditions

    if not isinstance(conditions, list):
        raise ValueError("WHERE conditions must be a list")

    validated_conditions = []
    for condition in conditions:
        if not isinstance(condition, str):
            raise ValueError(f"WHERE condition must be a string, got {type(condition)}")

        condition = condition.strip()
        if not condition:
            continue

        # Basic safety checks - prevent SQL injection-like patterns
        dangerous_patterns = [
            r';\s*(?:drop|delete|update|insert|alter|create|truncate)',
            r';\s*(?:exec|execute)\s+',
            r'union\s+select',
            r'--',  # SQL comments
            r'/\*.*\*/',  # Block comments
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, condition, re.IGNORECASE):
                raise ValueError(f"WHERE condition contains potentially dangerous pattern: {condition}")

        # Check for balanced quotes
        single_quotes = condition.count("'")
        if single_quotes % 2 != 0:
            raise ValueError(f"Unbalanced quotes in WHERE condition: {condition}")

        validated_conditions.append(condition)

    return validated_conditions

def _validate_time_window(time_window: str) -> str:
    """Validate time window format."""
    if not time_window or not isinstance(time_window, str):
        return DEFAULT_TIME_WINDOW

    time_window = time_window.strip()
    if not time_window:
        return DEFAULT_TIME_WINDOW

    # Check format: number followed by d/h/m
    if not re.fullmatch(r'\d+[dhm]', time_window):
        logger.warning(f"Invalid time window format '{time_window}', using default")
        return DEFAULT_TIME_WINDOW

    # Reasonable bounds check
    match = re.match(r'(\d+)([dhm])', time_window)
    if match:
        num = int(match.group(1))
        unit = match.group(2)

        max_values = {'d': 365, 'h': 8760, 'm': 525600}  # 1 year in each unit
        if num > max_values.get(unit, 365):
            logger.warning(f"Time window '{time_window}' is very large, consider using a smaller window")
        elif num < 1:
            logger.warning(f"Time window '{time_window}' is invalid, using default")
            return DEFAULT_TIME_WINDOW

    return time_window

def _validate_limit(limit: Optional[int]) -> int:
    """Validate and normalize limit value."""
    if limit is None:
        return 100

    if not isinstance(limit, int):
        try:
            limit = int(limit)
        except (ValueError, TypeError):
            logger.warning(f"Invalid limit value, using default: {limit}")
            return 100

    if limit < 1:
        logger.warning(f"Limit must be positive, using default: {limit}")
        return 100

    if limit > 10000:
        logger.warning(f"Limit is very large ({limit}), consider using a smaller value")
        return min(limit, 50000)  # Allow up to 50k but warn

    return limit

def _validate_summarize_expression(summarize: Optional[str]) -> Optional[str]:
    """Validate summarize expression for safety."""
    if not summarize or not isinstance(summarize, str):
        return summarize

    summarize = summarize.strip()
    if not summarize:
        return None

    # Basic safety checks
    dangerous_patterns = [
        r';\s*(?:drop|delete|update|insert|alter|create|truncate)',
        r';\s*(?:exec|execute)\s+',
        r'union\s+select',
        r'--',  # SQL comments
        r'/\*.*\*/',  # Block comments
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, summarize, re.IGNORECASE):
            raise ValueError(f"Summarize expression contains potentially dangerous pattern: {summarize}")

    return summarize

def _validate_order_by_expression(order_by: Optional[str]) -> Optional[str]:
    """Validate order by expression for safety."""
    if not order_by or not isinstance(order_by, str):
        return order_by

    order_by = order_by.strip()
    if not order_by:
        return None

    # Check for valid order by patterns
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*\s+(?:asc|desc)$', order_by):
        logger.warning(f"Order by expression may be invalid: {order_by}")

    return order_by

def _parse_time_window(s: Optional[str]) -> str:
    """Parse and validate time window string."""
    if not s:
        return DEFAULT_TIME_WINDOW

    s = s.strip()
    if not s:
        return DEFAULT_TIME_WINDOW

    # Check format: number followed by d/h/m
    if not re.fullmatch(r'\d+[dhm]', s):
        logger.warning(f"Invalid time window format '{s}', using default")
        return DEFAULT_TIME_WINDOW

    return s

def list_columns(schema: Dict[str, Any], table: str) -> List[str]:
    """List all columns for a given table with input validation."""
    if not isinstance(schema, dict):
        logger.error("Schema must be a dictionary")
        return []

    if not isinstance(table, str) or not table.strip():
        logger.error("Table name must be a non-empty string")
        return []

    table = table.strip()
    if table not in schema:
        logger.warning(f"Table '{table}' not found in schema")
        return []

    try:
        columns = schema[table].get("columns", [])
        return [c["name"] for c in columns if isinstance(c, dict) and "name" in c]
    except (KeyError, TypeError) as e:
        logger.error(f"Error accessing columns for table '{table}': {e}")
        return []

def suggest_columns(schema: Dict[str, Any], table: str, keyword: Optional[str]=None) -> List[str]:
    """Suggest columns for a table, optionally filtered by keyword, with input validation."""
    if not isinstance(schema, dict):
        logger.error("Schema must be a dictionary")
        return []

    if not isinstance(table, str) or not table.strip():
        logger.error("Table name must be a non-empty string")
        return []

    if keyword is not None and not isinstance(keyword, str):
        logger.error("Keyword must be a string or None")
        return []

    cols = list_columns(schema, table)

    if not keyword or not keyword.strip():
        return cols[:50]

    kw = keyword.lower().strip()
    if not kw:
        return cols[:50]

    try:
        filtered_cols = [c for c in cols if kw in c.lower()]
        return filtered_cols[:50]
    except Exception as e:
        logger.error(f"Error filtering columns with keyword '{keyword}': {e}")
        return cols[:50]

def _best_table(schema: Dict[str, Any], name: str) -> str:
    """Find the best matching table name with improved error handling."""
    if not isinstance(schema, dict):
        logger.error("Schema must be a dictionary")
        return name

    if not isinstance(name, str) or not name.strip():
        logger.error("Table name must be a non-empty string")
        return name

    name = name.strip()
    if name in schema:
        return name

    try:
        from rapidfuzz import process
        if not schema:
            logger.warning("Schema is empty, cannot find best match")
            return name

        choice, score, _ = process.extractOne(name, list(schema.keys()))
        if score >= 80:  # Only use fuzzy match if confidence is high
            logger.info(f"Using fuzzy match for table '{name}' -> '{choice}' (score: {score})")
            return choice
        else:
            logger.warning(f"No good fuzzy match found for table '{name}' (best score: {score})")
            return name
    except ImportError:
        logger.error("rapidfuzz not available for fuzzy matching")
        return name
    except Exception as e:
        logger.error(f"Error in fuzzy table matching for '{name}': {e}")
        return name

def _nl_to_structured(schema: Dict[str, Any], intent: str) -> Dict[str, Any]:
    """Enhanced natural language to structured query parsing with better pattern matching."""
    if not intent or not intent.strip():
        logger.warning("Empty or None natural language intent provided")
        return _get_default_query_params()

    text = intent.lower().strip()
    logger.info(f"Parsing natural language intent: {text}")

    # Initialize query parameters
    params = _get_default_query_params()

    # Determine table from keywords
    params["table"] = _infer_table_from_text(text, schema)

    # Parse time window
    params["time_window"] = _parse_time_window_from_text(text)

    # Parse conditions and filters
    params["where"] = _parse_conditions_from_text(text)

    # Parse aggregation and ordering
    agg_result = _parse_aggregation_from_text(text)
    params.update(agg_result)

    # Parse limit
    params["limit"] = _parse_limit_from_text(text)

    # Parse select columns if specified
    params["select"] = _parse_select_from_text(text)

    logger.info(f"Parsed query parameters: {params}")
    return params

def _get_default_query_params() -> Dict[str, Any]:
    """Get default query parameters."""
    return {
        "table": None,
        "select": None,
        "where": None,
        "time_window": DEFAULT_TIME_WINDOW,
        "summarize": None,
        "order_by": None,
        "limit": 100
    }

def _infer_table_from_text(text: str, schema: Dict[str, Any]) -> Optional[str]:
    """Infer table from text using comprehensive keyword mapping."""
    # Expanded table hints with more keywords
    table_hints = {
        "DeviceProcessEvents": [
            "process", "processes", "exe", "executable", "cmd", "command", "powershell",
            "script", "batch", "ps1", "vbs", "wscript", "cscript", "rundll32", "regsvr32"
        ],
        "DeviceNetworkEvents": [
            "network", "net", "connection", "connect", "dns", "domain", "url", "http",
            "https", "tcp", "udp", "port", "firewall", "traffic", "web", "browser"
        ],
        "DeviceFileEvents": [
            "file", "files", "document", "doc", "pdf", "txt", "log", "config", "ini",
            "registry", "reg", "disk", "drive", "folder", "directory"
        ],
        "EmailEvents": [
            "email", "mail", "smtp", "outlook", "exchange", "message", "attachment",
            "sender", "recipient", "subject", "phishing", "spam"
        ],
        "AlertInfo": [
            "alert", "alerts", "threat", "security", "incident", "detection", "malware",
            "attack", "breach", "compromise", "suspicious"
        ],
        "IdentityLogonEvents": [
            "logon", "login", "sign-in", "authentication", "auth", "user", "account",
            "credential", "password", "session", "interactive"
        ],
        "DeviceInfo": [
            "device", "machine", "computer", "host", "endpoint", "system", "os",
            "windows", "linux", "mac", "version", "build"
        ]
    }

    # Check for explicit table mentions first
    for table_name in schema.keys():
        if table_name.lower() in text:
            return table_name

    # Check keyword hints
    for table_name, keywords in table_hints.items():
        if table_name in schema and any(kw in text for kw in keywords):
            return table_name

    return None

def _parse_time_window_from_text(text: str) -> str:
    """Parse time window from natural language text with safe regex operations."""
    if not isinstance(text, str):
        logger.error("Text must be a string for time window parsing")
        return DEFAULT_TIME_WINDOW

    # Multiple time pattern formats
    time_patterns = [
        r"(?:last|past|previous)\s+(\d+)\s*(day|days|d|hour|hours|h|minute|minutes|min|m)",
        r"(\d+)\s*(day|days|d|hour|hours|h|minute|minutes|min|m)\s+(?:ago|back|earlier)",
        r"since\s+(\d+)\s*(day|days|d|hour|hours|h|minute|minutes|min|m)\s+ago",
        r"within\s+(?:the\s+)?(?:last|past)\s+(\d+)\s*(day|days|d|hour|hours|h|minute|minutes|min|m)"
    ]

    for pattern in time_patterns:
        try:
            match = re.search(pattern, text, re.IGNORECASE)
            if match and len(match.groups()) >= 2:
                n = match.group(1)
                unit = match.group(2)

                if n and unit:
                    unit = unit.lower()

                    # Normalize unit
                    if unit in ['day', 'days', 'd']:
                        return f"{n}d"
                    elif unit in ['hour', 'hours', 'h']:
                        return f"{n}h"
                    elif unit in ['minute', 'minutes', 'min', 'm']:
                        return f"{n}m"
        except (IndexError, AttributeError) as e:
            logger.warning(f"Error parsing time pattern {pattern}: {e}")
            continue

    return DEFAULT_TIME_WINDOW

def _parse_conditions_from_text(text: str) -> Optional[List[str]]:
    """Parse WHERE conditions from natural language text."""
    conditions = []

    # Enhanced condition patterns
    condition_patterns = [
        # Action types
        (r"action\s+(?:type\s+)?(?:is|=|equals?)\s+['\"]?([A-Za-z0-9_]+)['\"]?", lambda m: f"ActionType == {_quote(m.group(1))}"),
        (r"action\s+['\"]?([A-Za-z0-9_]+)['\"]?", lambda m: f"ActionType == {_quote(m.group(1))}"),

        # Process names
        (r"process\s+(?:name\s+)?(?:is|=|equals?|contains|like)\s+['\"]?([A-Za-z0-9._\\-]+)['\"]?", lambda m: f"ProcessName =~ {_quote(m.group(1))}"),
        (r"(?:running|executing)\s+['\"]?([A-Za-z0-9._\\-]+)['\"]?", lambda m: f"ProcessName =~ {_quote(m.group(1))}"),

        # File names
        (r"file\s+(?:name\s+)?(?:is|=|equals?|contains|like)\s+['\"]?([A-Za-z0-9._\\-]+)['\"]?", lambda m: f"FileName =~ {_quote(m.group(1))}"),
        (r"(?:accessing|opening|creating|deleting)\s+(?:file\s+)?['\"]?([A-Za-z0-9._\\-]+)['\"]?", lambda m: f"FileName =~ {_quote(m.group(1))}"),

        # Device names
        (r"device\s+(?:name\s+)?(?:is|=|equals?|on)\s+['\"]?([A-Za-z0-9._\\-]+)['\"]?", lambda m: f"DeviceName =~ {_quote(m.group(1))}"),
        (r"(?:on|from)\s+(?:device|machine|computer)\s+['\"]?([A-Za-z0-9._\\-]+)['\"]?", lambda m: f"DeviceName =~ {_quote(m.group(1))}"),

        # IP addresses
        (r"ip\s+(?:address\s+)?(?:is|=|equals?)\s+['\"]?([0-9a-fA-F\.:]+)['\"]?", lambda m: f"RemoteIP == {_quote(m.group(1))}"),
        (r"(?:connecting\s+to|from\s+ip)\s+['\"]?([0-9a-fA-F\.:]+)['\"]?", lambda m: f"RemoteIP == {_quote(m.group(1))}"),

        # User accounts
        (r"(?:user|account)\s+(?:name\s+)?(?:is|=|equals?|by)\s+['\"]?([A-Za-z0-9._\\-]+)['\"]?", lambda m: f"AccountName =~ {_quote(m.group(1))}"),
        (r"(?:logged\s+in\s+as|running\s+as)\s+['\"]?([A-Za-z0-9._\\-]+)['\"]?", lambda m: f"AccountName =~ {_quote(m.group(1))}"),

        # Domains/URLs
        (r"domain\s+(?:is|=|equals?|contains)\s+['\"]?([A-Za-z0-9._-]+)['\"]?", lambda m: f"RemoteUrl endswith {_quote(m.group(1))} or RemoteUrl contains {_quote(m.group(1))}"),
        (r"(?:visiting|accessing)\s+['\"]?([A-Za-z0-9._-]+)['\"]?", lambda m: f"RemoteUrl contains {_quote(m.group(1))}"),
    ]

    for pattern, condition_func in condition_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            try:
                condition = condition_func(match)
                if condition and condition not in conditions:
                    conditions.append(condition)
            except Exception as e:
                logger.warning(f"Failed to parse condition from pattern {pattern}: {e}")

    return conditions if conditions else None

def _parse_aggregation_from_text(text: str) -> Dict[str, Any]:
    """Parse aggregation and ordering from text with safe regex operations."""
    if not isinstance(text, str):
        logger.error("Text must be a string for aggregation parsing")
        return {"summarize": None, "order_by": None}

    result = {"summarize": None, "order_by": None}

    # Top/bottom patterns
    try:
        top_match = re.search(r"(?:top|most)\s+(\d+|\w+)\s+(?:by|per|grouped\s+by)\s+(\w+)", text, re.IGNORECASE)
        if top_match and len(top_match.groups()) >= 2:
            count = top_match.group(1)
            group_by = top_match.group(2)

            if count and group_by:
                if count.isdigit():
                    result["limit"] = int(count)
                elif count.lower() in ['all', 'every', 'each']:
                    result["limit"] = None

                result["summarize"] = f"count() by {group_by}"
                result["order_by"] = "count_ desc"
    except (IndexError, AttributeError) as e:
        logger.warning(f"Error parsing top/bottom pattern: {e}")

    # Count patterns
    if "count" in text or "number of" in text or "how many" in text:
        pass

    if "count" in text or "number of" in text or "how many" in text:
        if "by" in text:
            try:
                by_match = re.search(r"(?:by|per|grouped\s+by)\s+(\w+)", text, re.IGNORECASE)
                if by_match and len(by_match.groups()) >= 1:
                    group_by = by_match.group(1)
                    if group_by:
                        result["summarize"] = f"count() by {group_by}"
                        result["order_by"] = "count_ desc"
            except (IndexError, AttributeError) as e:
                logger.warning(f"Error parsing count pattern: {e}")

    return result

def _parse_limit_from_text(text: str) -> int:
    """Parse limit from text."""
    limit_patterns = [
        r"(?:limit|top|first)\s+(\d+)",
        r"(\d+)\s+(?:results?|records?|entries?|items?)",
        r"show\s+(?:me\s+)?(\d+)"
    ]

    for pattern in limit_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            try:
                limit = int(match.group(1))
                if 1 <= limit <= 10000:  # Reasonable bounds
                    return limit
            except ValueError:
                continue

    return 100  # Default

def _parse_select_from_text(text: str) -> Optional[List[str]]:
    """Parse select columns from text."""
    if "show" not in text and "display" not in text and "select" not in text:
        return None

    # Look for column names in the text
    select_patterns = [
        r"show\s+(?:me\s+)?(.+?)(?:\s+(?:where|when|with|from)|\s*$)",
        r"display\s+(.+?)(?:\s+(?:where|when|with|from)|\s*$)",
        r"select\s+(.+?)(?:\s+(?:where|when|with|from)|\s*$)"
    ]

    for pattern in select_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            columns_text = match.group(1).strip()
            # Split by common separators
            columns = re.split(r'[,&\s]+(?:and\s+)?', columns_text)
            # Clean up column names
            clean_columns = []
            for col in columns:
                col = col.strip()
                if col and not any(word in col.lower() for word in ['where', 'when', 'with', 'from', 'the', 'only']):
                    clean_columns.append(col)

            if clean_columns:
                return clean_columns

    return None

def build_kql_query(
    schema: Dict[str, Any],
    table: Optional[str] = None,
    select: Optional[List[str]] = None,
    where: Optional[List[str]] = None,
    time_window: Optional[str] = None,
    summarize: Optional[str] = None,
    order_by: Optional[str] = None,
    limit: Optional[int] = 100,
    natural_language_intent: Optional[str] = None,
) -> Tuple[str, Dict[str, Any]]:
    """Build a KQL query with comprehensive input validation."""
    try:
        logger.info("Building KQL query with parameters: table=%s, select=%s, where=%s, time_window=%s, summarize=%s, order_by=%s, limit=%s, natural_language_intent=%s",
                   table, select, where, time_window, summarize, order_by, limit, bool(natural_language_intent))

        # Parse natural language intent if provided
        if natural_language_intent:
            derived = _nl_to_structured(schema, natural_language_intent)
            table = table or derived["table"]
            select = select or derived["select"]
            where = (where or []) + (derived["where"] or [])
            time_window = time_window or derived["time_window"]
            summarize = summarize or derived["summarize"]
            order_by = order_by or derived["order_by"]
            limit = limit or derived["limit"]

        # Validate table
        if not table:
            raise ValueError("Table is required (pass 'table' or provide 'natural_language_intent' that implies a table).")
        table = _validate_table_name(table, schema)
        table = _best_table(schema, table)

        # Validate and get available columns
        cols = [c["name"] for c in schema.get(table, {}).get("columns", [])]

        # Validate inputs
        if select:
            select = _validate_column_names(select, schema, table)
        if where:
            where = _validate_where_conditions(where)
        time_window = _validate_time_window(time_window)
        limit = _validate_limit(limit)
        if summarize:
            summarize = _validate_summarize_expression(summarize)
        if order_by:
            order_by = _validate_order_by_expression(order_by)

        # Build query
        q = [table]

        # Add time window filter if Timestamp column exists
        if "Timestamp" in cols:
            tw = _parse_time_window(time_window)
            q.append(f"| where Timestamp > ago({tw})")

        # Add WHERE conditions
        if where:
            for cond in where:
                q.append(f"| where {cond}")

        # Add SELECT projection
        if select:
            q.append("| project " + ", ".join(select))

        # Add summarization
        if summarize:
            q.append("| summarize " + summarize)

        # Add ordering
        if order_by:
            q.append("| order by " + order_by)

        # Add limit
        if limit:
            q.append("| limit " + str(limit))

        kql_query = "\n".join(q)
        logger.info("Successfully built KQL query for table '%s'", table)

        return kql_query, {
            "table": table,
            "time_window": time_window,
            "has_timestamp": "Timestamp" in cols,
            "column_count": len(cols),
            "conditions_count": len(where) if where else 0,
            "selected_columns": len(select) if select else None
        }

    except Exception as e:
        logger.error("Failed to build KQL query: %s", str(e))
        raise

def example_queries_for_table(schema: Dict[str, Any], table: str) -> List[str]:
    t = _best_table(schema, table)
    cols = [c["name"] for c in schema.get(t, {}).get("columns", [])]
    ex = []
    if t == "DeviceProcessEvents":
        ex.append(
            "DeviceProcessEvents\n"
            "| where Timestamp > ago(7d)\n"
            "| where ActionType == 'ProcessCreated'\n"
            "| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName\n"
            "| limit 200"
        )
    elif t == "DeviceNetworkEvents":
        ex.append(
            "DeviceNetworkEvents\n"
            "| where Timestamp > ago(24h)\n"
            "| where RemoteUrl contains 'example.com' or RemoteIP == '1.2.3.4'\n"
            "| summarize count() by DeviceName, RemoteUrl\n"
            "| order by count_ desc\n"
            "| limit 100"
        )
    else:
        ex.append(
            f"{t}\n"
            "| where Timestamp > ago(7d)\n"
            "| limit 100"
        )
    return ex
