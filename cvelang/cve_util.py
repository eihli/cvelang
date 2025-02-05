import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import psycopg2
from psycopg2.extensions import cursor, connection
from sentence_transformers import SentenceTransformer
from tqdm import tqdm


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATA_DIR = Path(os.getenv('XDG_DATA_HOME', Path.home() / '.local' / 'share'))
CVE_DIR = DATA_DIR / 'cvelistV5'

DB_CONFIG = {
    "dbname": "cvelang",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost"
}

def git_clone_cve_data(data_dir):
    if not data_dir.exists():
        data_dir.mkdir(parents=True, exist_ok=True)
        os.chdir(data_dir)
        os.system('git clone https://github.com/CVEProject/cvelistV5')

def cve_filepath_iter(directory):
    for path in directory.glob('cves/[0-9][0-9][0-9][0-9]/**/*.json'):
        yield path

def read_file(path):
    with open(path, 'r') as f:
        return f.read()

def cve_json_iter(cve_dir):
    for path in cve_filepath_iter(cve_dir):
        yield json.loads(read_file(path))

def init_model():
    return SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')

def setup_db():
    """Create tables and indices for storing CVE data"""
    conn = psycopg2.connect(
        dbname="cvelang",
        user="postgres", 
        password="postgres",
        host="localhost"
    )
    cur = conn.cursor()
    # Execute schema.sql
    schema_path = Path(__file__).parent / 'sql' / 'schema.sql'
    with open(schema_path) as f:
        cur.execute(f.read())
    conn.commit()
    cur.close()
    conn.close()

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

def insert_cve_record(cur: cursor, cve_data: Dict[str, Any], model: SentenceTransformer) -> str:
    """Insert or update main CVE record.
    
    Args:
        cur: Database cursor
        cve_data: CVE record data
        model: SentenceTransformer model for generating description embeddings
        
    Returns:
        cve_id of inserted/updated record
        
    Raises:
        psycopg2.Error: If database operation fails
    """
    cve_id = cve_data['cveMetadata']['cveId']
    published = parse_datetime(cve_data['cveMetadata']['datePublished'])
    last_modified = parse_datetime(cve_data['cveMetadata']['dateUpdated'])
    description = extract_english_description(cve_data['containers']['cna']['descriptions'])
    description_vector = model.encode(description, show_progress_bar=False).tolist()  # Generate embedding
    title = cve_data['containers']['cna'].get('title')
    status = cve_data['cveMetadata']['state']
    
    cvss_data = extract_cvss_metrics(cve_data)

    cur.execute("""
        INSERT INTO cve_records (
            cve_id, published_date, last_modified_date, title, 
            description, description_vector, status, cvss_v3_vector, cvss_v3_base_score,
            cvss_v3_base_severity, cvss_v2_vector, cvss_v2_base_score
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (cve_id) DO UPDATE SET
            last_modified_date = EXCLUDED.last_modified_date,
            title = EXCLUDED.title,
            description = EXCLUDED.description,
            description_vector = EXCLUDED.description_vector,
            status = EXCLUDED.status,
            cvss_v3_vector = EXCLUDED.cvss_v3_vector,
            cvss_v3_base_score = EXCLUDED.cvss_v3_base_score,
            cvss_v3_base_severity = EXCLUDED.cvss_v3_base_severity,
            cvss_v2_vector = EXCLUDED.cvss_v2_vector,
            cvss_v2_base_score = EXCLUDED.cvss_v2_base_score
    """, (cve_id, published, last_modified, title, description, description_vector, status, *cvss_data))

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

def insert_cve(conn: connection, cur: cursor, cve_data: Dict[str, Any], model: SentenceTransformer) -> bool:
    """Insert a CVE record into the database.
    
    Args:
        conn: Database connection
        cur: Database cursor
        cve_data: CVE record data
        model: SentenceTransformer model for generating embeddings
        
    Returns:
        True if successful, False otherwise
    """
    try:
        cve_id = insert_cve_record(cur, cve_data, model)
        
        references = get_all_references(cve_data)
        insert_references(cur, cve_id, references)
        
        products = get_all_affected_products(cve_data)
        insert_affected_products(cur, cve_id, products)
        
        conn.commit()
        return True
        
    except Exception as e:
        logger.error(f"Failed to insert CVE {cve_data['cveMetadata']['cveId']}: {e}")
        conn.rollback()
        return False

def seed_db(conn, model, cve_dir):
    """Seed the database with CVE data."""
    cur = conn.cursor()
    try:
        for cve in tqdm(
            cve_json_iter(cve_dir), 
            total=278908, 
            desc="Processing CVEs", 
            position=0,
            leave=True
        ):
            insert_cve(conn, cur, cve, model)
    finally:
        cur.close()
        conn.close()

def semantic_search(model, query_text, limit=10):
    """Search CVEs by semantic similarity to query text"""
    conn = psycopg2.connect(
        dbname="cvelang",
        user="postgres",
        password="postgres",
        host="localhost"
    )
    cur = conn.cursor()
    
    # Generate embedding for query
    query_embedding = model.encode(query_text)
    
    # Search using vector similarity
    cur.execute("""
        SELECT cve_id, description, published_date, 
               1 - (description_vector <-> %s::vector) as similarity
        FROM cve_records
        ORDER BY description_vector <-> %s::vector
        LIMIT %s
    """, (query_embedding.tolist(), query_embedding.tolist(), limit))
    
    results = cur.fetchall()
    cur.close()
    conn.close()
    return results

def example_search(model):
    results = semantic_search(model, """
    XSS vulnerabilities in PHP web applications
    """)
    for r in results:
        print(f"CVE: {r[0]}, Similarity: {r[3]:.3f}")  # Fixed index from 5 to 3
        print(f"Description: {r[1]}")
        print()

if __name__ == "__main__":
    model = init_model()
    example_search(model)
