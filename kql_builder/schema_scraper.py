from __future__ import annotations
import json, logging
from dataclasses import dataclass
from typing import Dict, Any, List
from pathlib import Path

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class SchemaCache:
    schema_path: Path

    def load_or_refresh(self) -> Dict[str, Any]:
        """Load schema from local JSON files."""
        return self._load_schema_from_json()

    def refresh(self, force: bool = False) -> bool:
        """No-op since schema is now static/local."""
        logger.info("Schema refresh not needed - using local JSON files")
        return True

    def _load_schema_from_json(self) -> Dict[str, Any]:
        """Load schema from local JSON files in defender_xdr_kql_schema_fuller/ directory."""
        try:
            logger.info("Loading schema from local JSON files")

            # Path to the schema directory (relative to this script's location)
            schema_dir = Path(__file__).parent / "defender_xdr_kql_schema_fuller"
            if not schema_dir.exists():
                raise FileNotFoundError(f"Schema directory not found: {schema_dir}")

            # Load schema index
            index_path = schema_dir / "schema_index.json"
            if not index_path.exists():
                raise FileNotFoundError(f"Schema index not found: {index_path}")

            with open(index_path, 'r', encoding='utf-8') as f:
                index_data = json.load(f)

            schema: Dict[str, Any] = {}

            # Process each table in the index
            for table_info in index_data["tables"]:
                table_name = table_info["name"]
                table_url = table_info["url"]
                has_columns_json = table_info.get("has_columns_json", False)

                if has_columns_json:
                    # Load table-specific JSON file
                    table_file = schema_dir / f"{table_name}.json"
                    if table_file.exists():
                        try:
                            with open(table_file, 'r', encoding='utf-8') as f:
                                table_data = json.load(f)

                            # Transform to expected format
                            schema[table_name] = {
                                "columns": table_data["columns"],
                                "url": table_data["source_url"]
                            }
                            logger.debug(f"Loaded schema for table '{table_name}' with {len(table_data['columns'])} columns")
                        except Exception as e:
                            logger.error(f"Failed to load table file for '{table_name}': {e}")
                            continue
                    else:
                        logger.warning(f"Table file not found for '{table_name}': {table_file}")
                else:
                    # Table without columns JSON - just store URL
                    schema[table_name] = {
                        "columns": [],
                        "url": table_url
                    }
                    logger.debug(f"Added table '{table_name}' without columns (no JSON file)")

            logger.info(f"Successfully loaded schema for {len(schema)} tables")
            return schema

        except Exception as e:
            logger.error(f"Schema loading failed: {e}")
            raise
