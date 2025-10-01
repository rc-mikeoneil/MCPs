from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from kql_builder.kql_builder import build_kql_query


def _minimal_schema():
    return {
        "DeviceProcessEvents": {
            "columns": [
                {"name": "Timestamp"},
                {"name": "DeviceName"},
                {"name": "ProcessCommandLine"},
            ]
        }
    }


def test_top_limit_from_natural_language():
    schema = _minimal_schema()

    query, _ = build_kql_query(
        schema=schema,
        natural_language_intent="top 5 processes",
    )

    assert "| limit 5" in query


def test_default_limit_applied_when_unspecified():
    schema = _minimal_schema()

    query, _ = build_kql_query(
        schema=schema,
        table="DeviceProcessEvents",
    )

    assert "| limit 100" in query
