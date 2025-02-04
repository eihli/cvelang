import pytest
from datetime import datetime
from psycopg2.extensions import cursor, connection
from cvelang.cve_loader import (
    parse_datetime,
    extract_english_description,
    extract_cvss_metrics,
    get_all_references,
    get_all_affected_products,
    load_json_file
)

# Sample test data
SAMPLE_CVE_DATA = {
    "cveMetadata": {
        "cveId": "CVE-2024-31804",
        "state": "PUBLISHED",
        "datePublished": "2024-04-23T00:00:00",
        "dateUpdated": "2024-11-22T15:19:41.887Z"
    },
    "containers": {
        "cna": {
            "descriptions": [
                {
                    "lang": "en",
                    "value": "English description"
                },
                {
                    "lang": "es",
                    "value": "Spanish description"
                }
            ],
            "references": [
                {
                    "url": "https://example.com/ref1",
                    "tags": ["tag1"]
                }
            ],
            "affected": [
                {
                    "vendor": "test_vendor",
                    "product": "test_product",
                    "versions": [
                        {
                            "version": "1.0",
                            "status": "affected"
                        }
                    ]
                }
            ],
            "metrics": [
                {
                    "cvssV3_1": {
                        "vectorString": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 6.7,
                        "baseSeverity": "MEDIUM"
                    }
                }
            ]
        },
        "adp": [
            {
                "references": [
                    {
                        "url": "https://example.com/ref2",
                        "tags": ["tag2"]
                    }
                ],
                "affected": [
                    {
                        "vendor": "test_vendor2",
                        "product": "test_product2",
                        "versions": [
                            {
                                "version": "2.0",
                                "status": "affected"
                            }
                        ]
                    }
                ]
            }
        ]
    }
}

def test_parse_datetime():
    """Test datetime parsing from ISO format strings."""
    # Test with Z timezone
    dt_str = "2024-04-23T00:00:00Z"
    result = parse_datetime(dt_str)
    assert isinstance(result, datetime)
    assert result.year == 2024
    assert result.month == 4
    assert result.day == 23
    
    # Test with explicit timezone
    dt_str = "2024-11-22T15:19:41.887+00:00"
    result = parse_datetime(dt_str)
    assert isinstance(result, datetime)
    assert result.year == 2024
    assert result.month == 11

def test_extract_english_description():
    """Test extracting English description from descriptions list."""
    descriptions = [
        {"lang": "es", "value": "Spanish"},
        {"lang": "en", "value": "English"},
        {"lang": "fr", "value": "French"}
    ]
    
    result = extract_english_description(descriptions)
    assert result == "English"
    
    # Test fallback to first description when no English
    descriptions = [
        {"lang": "es", "value": "Spanish"},
        {"lang": "fr", "value": "French"}
    ]
    
    result = extract_english_description(descriptions)
    assert result == "Spanish"

def test_extract_cvss_metrics():
    """Test extracting CVSS metrics from CVE data."""
    result = extract_cvss_metrics(SAMPLE_CVE_DATA)
    
    assert len(result) == 5
    v3_vector, v3_score, v3_severity, v2_vector, v2_score = result
    
    assert v3_vector == "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
    assert v3_score == 6.7
    assert v3_severity == "MEDIUM"
    assert v2_vector is None
    assert v2_score is None

def test_get_all_references():
    """Test collecting references from both CNA and ADP containers."""
    references = get_all_references(SAMPLE_CVE_DATA)
    
    assert len(references) == 2
    assert references[0]['url'] == "https://example.com/ref1"
    assert references[0]['tags'] == ["tag1"]
    assert references[1]['url'] == "https://example.com/ref2"
    assert references[1]['tags'] == ["tag2"]

def test_get_all_affected_products():
    """Test collecting affected products from both CNA and ADP containers."""
    products = get_all_affected_products(SAMPLE_CVE_DATA)
    
    assert len(products) == 2
    assert products[0]['vendor'] == "test_vendor"
    assert products[0]['product'] == "test_product"
    assert products[0]['versions'][0]['version'] == "1.0"
    assert products[1]['vendor'] == "test_vendor2"
    assert products[1]['product'] == "test_product2"
    assert products[1]['versions'][0]['version'] == "2.0"

def test_load_json_file(tmp_path):
    """Test loading JSON file."""
    # Create a temporary JSON file
    json_file = tmp_path / "test.json"
    json_file.write_text('{"test": "data"}')
    
    result = load_json_file(str(json_file))
    assert result == {"test": "data"}
    
    # Test with non-existent file
    with pytest.raises(FileNotFoundError):
        load_json_file("nonexistent.json")
    
    # Test with invalid JSON
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text('{invalid json}')
    
    with pytest.raises(json.JSONDecodeError):
        load_json_file(str(invalid_json))

@pytest.fixture
def mock_db():
    """Mock database connection and cursor for testing."""
    class MockCursor:
        def __init__(self):
            self.executed = []
            self.params = []
        
        def execute(self, query, params=None):
            self.executed.append(query)
            self.params.append(params)
    
    class MockConnection:
        def __init__(self):
            self.committed = False
            self.rolled_back = False
        
        def commit(self):
            self.committed = True
        
        def rollback(self):
            self.rolled_back = True
    
    return MockConnection(), MockCursor()

def test_database_operations(mock_db):
    """Test database operations using mock connection/cursor."""
    from cvelang.cve_loader import insert_cve_record, insert_references, insert_affected_products
    
    conn, cur = mock_db
    
    # Test insert_cve_record
    cve_id = insert_cve_record(cur, SAMPLE_CVE_DATA)
    assert cve_id == "CVE-2024-31804"
    assert len(cur.executed) == 1
    assert "INSERT INTO cve_records" in cur.executed[0]
    
    # Test insert_references
    references = get_all_references(SAMPLE_CVE_DATA)
    insert_references(cur, cve_id, references)
    assert len(cur.executed) == 3  # DELETE + 2 INSERTs
    assert "DELETE FROM cve_references" in cur.executed[1]
    assert "INSERT INTO cve_references" in cur.executed[2]
    
    # Test insert_affected_products
    products = get_all_affected_products(SAMPLE_CVE_DATA)
    insert_affected_products(cur, cve_id, products)
    assert len(cur.executed) > 3
    assert "DELETE FROM cve_affected_products" in cur.executed[3]
    assert "INSERT INTO cve_affected_products" in cur.executed[4] 