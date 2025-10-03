"""
Schema rescraper for Microsoft Defender XDR Advanced Hunting tables.

This script revisits the documentation URLs for tables that previously failed to scrape
schema information and attempts to extract column metadata.
"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

import httpx
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def extract_schema_from_html(html_content: str, url: str) -> Optional[Dict[str, Any]]:
    """
    Extract schema information from Microsoft Learn documentation HTML.

    Looks for tables with schema information containing columns: Column name, Type, Description.
    """
    soup = BeautifulSoup(html_content, 'lxml')

    # Find tables that might contain schema
    tables = soup.find_all('table')

    for table in tables:
        headers = []
        header_row = table.find('thead')
        if header_row:
            header_cells = header_row.find_all(['th', 'td'])
            headers = [cell.get_text(strip=True).lower() for cell in header_cells]

        # Check if this looks like a schema table
        if any('column' in header.lower() for header in headers) or \
           any('type' in header.lower() for header in headers) or \
           any('description' in header.lower() for header in headers):

            # Try to extract table name from page title or URL
            title_element = soup.find('h1')
            page_title = title_element.get_text(strip=True) if title_element else ""
            table_name = extract_table_name_from_title(page_title) or extract_table_name_from_url(url)

            if not table_name:
                continue

            # Extract column data
            rows = table.find_all('tr')[1:]  # Skip header row
            columns = []

            for row in rows:
                cells = row.find_all(['td', 'th'])
                if len(cells) >= 3:
                    col_name = cells[0].get_text(strip=True)
                    col_type = cells[1].get_text(strip=True)
                    col_desc = cells[2].get_text(strip=True)

                    if col_name and col_type:  # Basic validation
                        columns.append({
                            "name": col_name,
                            "type": col_type,
                            "description": col_desc
                        })

            if columns:  # Only return if we found columns
                return {
                    "table": table_name,
                    "source_url": url,
                    "page_date": datetime.now().strftime("%Y-%m-%d"),
                    "columns": columns,
                    "col_count": len(columns),
                    "generated_at": datetime.now().isoformat() + "Z"
                }

    return None


def extract_table_name_from_title(title: str) -> Optional[str]:
    """Extract table name from page title."""
    # Common patterns: "DeviceEvents table" -> "DeviceEvents"
    import re
    match = re.search(r'(\w+) table', title, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def extract_table_name_from_url(url: str) -> Optional[str]:
    """Extract table name from URL."""
    # URL format: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetable-table
    import re
    match = re.search(r'advanced-hunting-(\w+)-table', url)
    if match:
        return match.group(1)
    return None


def rescrape_schema_tables(schema_dir: Path, rate_limit: float = 1.0) -> Dict[str, bool]:
    """
    Rescrape schema information for tables that don't have column JSON files.

    Args:
        schema_dir: Path to the defender_xdr_kql_schema_fuller directory
        rate_limit: Seconds to wait between requests

    Returns:
        Dictionary mapping table names to success status
    """
    index_path = schema_dir / "schema_index.json"

    if not index_path.exists():
        raise FileNotFoundError(f"Schema index not found: {index_path}")

    # Load current index
    with open(index_path, 'r', encoding='utf-8') as f:
        index_data = json.load(f)

    results = {}

    # Process tables without columns JSON
    tables_to_scrape = [
        table for table in index_data["tables"]
        if not table.get("has_columns_json", False)
    ]

    logger.info(f"Found {len(tables_to_scrape)} tables to rescrape")

    with httpx.Client(timeout=30.0) as client:
        for table_info in tables_to_scrape:
            table_name = table_info["name"]
            url = table_info["url"]

            logger.info(f"Attempting to scrape schema for {table_name} from {url}")

            try:
                response = client.get(url)
                response.raise_for_status()

                schema_data = extract_schema_from_html(response.text, url)

                if schema_data:
                    # Save the schema file
                    json_path = schema_dir / f"{table_name}.json"
                    with open(json_path, 'w', encoding='utf-8') as f:
                        json.dump(schema_data, f, indent=2, ensure_ascii=False)

                    # Update the index
                    table_info["has_columns_json"] = True
                    results[table_name] = True
                    logger.info(f"Successfully scraped {len(schema_data['columns'])} columns for {table_name}")
                else:
                    logger.warning(f"Could not extract schema from {url}")
                    results[table_name] = False

            except Exception as e:
                logger.error(f"Failed to scrape {table_name}: {e}")
                results[table_name] = False

            # Rate limiting
            if rate_limit > 0:
                time.sleep(rate_limit)

    # Save updated index
    index_data["generated_at"] = datetime.now().isoformat() + "Z"
    with open(index_path, 'w', encoding='utf-8') as f:
        json.dump(index_data, f, indent=2, ensure_ascii=False)

    logger.info(f"Rescraping complete. Updated {sum(results.values())} tables with schema data.")
    return results


def main():
    """Main entry point for rescraping."""
    import argparse

    parser = argparse.ArgumentParser(description="Rescrape Microsoft Defender XDR table schemas")
    parser.add_argument("--schema-dir", type=Path,
                       default=Path(__file__).parent / "defender_xdr_kql_schema_fuller",
                       help="Path to schema directory")
    parser.add_argument("--rate-limit", type=float, default=1.0,
                       help="Seconds to wait between requests")

    args = parser.parse_args()

    if not args.schema_dir.exists():
        logger.error(f"Schema directory does not exist: {args.schema_dir}")
        return 1

    try:
        results = rescrape_schema_tables(args.schema_dir, args.rate_limit)

        success_count = sum(results.values())
        total_count = len(results)

        logger.info(f"Completed: {success_count}/{total_count} tables successfully rescraped")

        for table, success in results.items():
            status = "SUCCESS" if success else "FAILED"
            logger.info(f"  {table}: {status}")

        return 0 if success_count > 0 else 1

    except Exception as e:
        logger.error(f"Rescraping failed: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
