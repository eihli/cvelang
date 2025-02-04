import json
import psycopg2
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from psycopg2.extensions import cursor, connection
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def connect_db(db_config: Dict[str, str]) -> Tuple[connection, cursor]:
    """Create a new database connection and cursor.
    
    Args:
        db_config: Database connection parameters
        
    Returns:
        Tuple of (connection, cursor)
        
    Raises:
        psycopg2.Error: If connection fails
    """
    conn = psycopg2.connect(**db_config)
    cur = conn.cursor()
    return conn, cur

def load_json_file(filepath: str) -> Dict[str, Any]:
    """Load and parse a JSON file.
    
    Args:
        filepath: Path to JSON file
        
    Returns:
        Parsed JSON data as dictionary
        
    Raises:
        JSONDecodeError: If JSON parsing fails
        FileNotFoundError: If file doesn't exist
    """
    with open(filepath, 'r') as f:
        return json.load(f)

def parse_datetime(dt_str: str) -> datetime:
    """Parse an ISO format datetime string.
    
    Args:
        dt_str: ISO format datetime string
        
    Returns:
        datetime object
    """
    return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))

def extract_english_description(descriptions: List[Dict[str, str]]) -> str:
    """Extract the first English description from a list of descriptions.
    
    Args:
        descriptions: List of description objects with 'lang' and 'value' keys
        
    Returns:
        The first English description or the first description if no English found
    """
    return next(
        (d['value'] for d in descriptions if d['lang'].startswith('en')),
        descriptions[0]['value']
    )

def extract_cvss_metrics(cve_data: Dict[str, Any]) -> Tuple[Optional[str], Optional[float], Optional[str], Optional[str], Optional[float]]:
    """Extract CVSS metrics from CVE data.
    
    Args:
        cve_data: CVE record data
        
    Returns:
        Tuple of (v3_vector, v3_score, v3_severity, v2_vector, v2_score)
    """
    metrics = []
    if 'metrics' in cve_data['containers'].get('cna', {}):
        metrics = cve_data['containers']['cna']['metrics']
    elif 'metrics' in cve_data['containers'].get('adp', [{}])[0]:
        metrics = cve_data['containers']['adp'][0]['metrics']

    v3_vector = v3_score = v3_severity = v2_vector = v2_score = None

    for metric in metrics:
        if 'cvssV3_1' in metric:
            cvss_data = metric['cvssV3_1']
            v3_vector = cvss_data.get('vectorString')
            v3_score = cvss_data.get('baseScore')
            v3_severity = cvss_data.get('baseSeverity')
        elif 'cvssV2_0' in metric:
            cvss_data = metric['cvssV2_0']
            v2_vector = cvss_data.get('vectorString')
            v2_score = cvss_data.get('baseScore')

    return v3_vector, v3_score, v3_severity, v2_vector, v2_score

def insert_cve_record(cur: cursor, cve_data: Dict[str, Any]) -> str:
    """Insert or update main CVE record.
    
    Args:
        cur: Database cursor
        cve_data: CVE record data
        
    Returns:
        cve_id of inserted/updated record
        
    Raises:
        psycopg2.Error: If database operation fails
    """
    cve_id = cve_data['cveMetadata']['cveId']
    published = parse_datetime(cve_data['cveMetadata']['datePublished'])
    last_modified = parse_datetime(cve_data['cveMetadata']['dateUpdated'])
    description = extract_english_description(cve_data['containers']['cna']['descriptions'])
    title = cve_data['containers']['cna'].get('title')
    status = cve_data['cveMetadata']['state']
    
    cvss_data = extract_cvss_metrics(cve_data)

    cur.execute("""
        INSERT INTO cve_records (
            cve_id, published_date, last_modified_date, title, 
            description, status, cvss_v3_vector, cvss_v3_base_score,
            cvss_v3_base_severity, cvss_v2_vector, cvss_v2_base_score
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (cve_id) DO UPDATE SET
            last_modified_date = EXCLUDED.last_modified_date,
            title = EXCLUDED.title,
            description = EXCLUDED.description,
            status = EXCLUDED.status,
            cvss_v3_vector = EXCLUDED.cvss_v3_vector,
            cvss_v3_base_score = EXCLUDED.cvss_v3_base_score,
            cvss_v3_base_severity = EXCLUDED.cvss_v3_base_severity,
            cvss_v2_vector = EXCLUDED.cvss_v2_vector,
            cvss_v2_base_score = EXCLUDED.cvss_v2_base_score
    """, (cve_id, published, last_modified, title, description, status, *cvss_data))

    return cve_id

def get_all_references(cve_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Collect all references from CNA and ADP containers.
    
    Args:
        cve_data: CVE record data
        
    Returns:
        List of reference objects
    """
    references = []
    
    if 'references' in cve_data['containers']['cna']:
        references.extend(cve_data['containers']['cna']['references'])
    
    for adp in cve_data['containers'].get('adp', []):
        if 'references' in adp:
            references.extend(adp['references'])
            
    return references

def insert_references(cur: cursor, cve_id: str, references: List[Dict[str, Any]]):
    """Insert references for a CVE record.
    
    Args:
        cur: Database cursor
        cve_id: CVE identifier
        references: List of reference objects
        
    Raises:
        psycopg2.Error: If database operation fails
    """
    cur.execute("DELETE FROM cve_references WHERE cve_id = %s", (cve_id,))
    
    for ref in references:
        cur.execute("""
            INSERT INTO cve_references (cve_id, url, source, tags)
            VALUES (%s, %s, %s, %s)
        """, (
            cve_id,
            ref['url'],
            ref.get('source'),
            ref.get('tags', [])
        ))

def get_all_affected_products(cve_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Collect all affected products from CNA and ADP containers.
    
    Args:
        cve_data: CVE record data
        
    Returns:
        List of affected product objects
    """
    products = []
    
    if 'affected' in cve_data['containers']['cna']:
        products.extend(cve_data['containers']['cna']['affected'])
    
    for adp in cve_data['containers'].get('adp', []):
        if 'affected' in adp:
            products.extend(adp['affected'])
            
    return products

def insert_affected_products(cur: cursor, cve_id: str, products: List[Dict[str, Any]]):
    """Insert affected products for a CVE record.
    
    Args:
        cur: Database cursor
        cve_id: CVE identifier
        products: List of affected product objects
        
    Raises:
        psycopg2.Error: If database operation fails
    """
    cur.execute("DELETE FROM cve_affected_products WHERE cve_id = %s", (cve_id,))
    
    for product in products:
        for version_info in product.get('versions', [{'version': product.get('version', '*')}]):
            cur.execute("""
                INSERT INTO cve_affected_products (
                    cve_id, product, vendor, version, 
                    package_name, ecosystem
                ) VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                cve_id,
                product.get('product', 'n/a'),
                product.get('vendor', 'n/a'),
                version_info.get('version', '*'),
                product.get('packageName'),
                product.get('ecosystem')
            ))

def load_cve(conn: connection, cur: cursor, cve_data: Dict[str, Any]) -> bool:
    """Load a CVE record into the database.
    
    Args:
        conn: Database connection
        cur: Database cursor
        cve_data: CVE record data
        
    Returns:
        True if successful, False otherwise
    """
    try:
        cve_id = insert_cve_record(cur, cve_data)
        
        references = get_all_references(cve_data)
        insert_references(cur, cve_id, references)
        
        products = get_all_affected_products(cve_data)
        insert_affected_products(cur, cve_id, products)
        
        conn.commit()
        return True
        
    except Exception as e:
        logger.error(f"Failed to load CVE {cve_data['cveMetadata']['cveId']}: {e}")
        conn.rollback()
        return False

def load_cve_from_file(conn: connection, cur: cursor, filepath: str) -> bool:
    """Load a CVE record from a file into the database.
    
    Args:
        conn: Database connection
        cur: Database cursor
        filepath: Path to CVE JSON file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        cve_data = load_json_file(filepath)
        return load_cve(conn, cur, cve_data)
    except Exception as e:
        logger.error(f"Failed to load CVE from {filepath}: {e}")
        return False

def main():
    """Example usage of the CVE loading functions."""
    db_config = {
        'dbname': 'langcve',
        'user': 'postgres',
        'password': 'postgres',
        'host': 'localhost',
        'port': '5432'
    }

    try:
        conn, cur = connect_db(db_config)
        
        success = load_cve_from_file(conn, cur, 'cvelang/data/CVE-2024-31804.json')
        if success:
            logger.info("Successfully loaded CVE")
        else:
            logger.error("Failed to load CVE")
            
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

if __name__ == '__main__':
    main() 