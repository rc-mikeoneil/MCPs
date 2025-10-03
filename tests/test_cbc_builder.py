from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

from cbc_builder.query_builder import build_cbc_query, QueryBuildError


def _load_schema() -> dict:
    schema_path = Path(__file__).resolve().parents[1] / "cbc_builder" / "cb_edr_schema.json"
    data = json.loads(schema_path.read_text(encoding="utf-8"))
    return data["carbonblack_edr_query_schema"]


def test_build_query_from_natural_language_md5():
    schema = _load_schema()
    md5 = "5a18f00ab9330ac7539675f326cf1100"
    query, metadata = build_cbc_query(
        schema,
        search_type="process",
        natural_language_intent=f"find processes with hash {md5}",
    )

    assert md5 in query
    assert any(entry["type"] == "md5" for entry in metadata["recognised"])
    assert metadata["search_type"] == "process_search"


def test_limit_clamped():
    schema = _load_schema()
    hash_value = "f" * 64
    query, metadata = build_cbc_query(
        schema,
        search_type="binary",
        natural_language_intent=f"binary sha256 is {hash_value}",
        limit=999999,
    )

    assert hash_value in query
    assert metadata["limit"] <= metadata["limit_clamped"]


def test_error_when_no_terms():
    schema = _load_schema()
    with pytest.raises(QueryBuildError):
        build_cbc_query(schema, search_type="process")
