import os
import json
from pathlib import Path

from sentence_transformers import SentenceTransformer
import psycopg2
from tqdm import tqdm

from cvelang import reference_util

data_dir = Path(os.getenv('XDG_DATA_HOME', Path.home() / '.local' / 'share'))
cve_dir = data_dir / 'cvelistV5'

def git_clone_cve_data():
    if not data_dir.exists():
        data_dir.mkdir(parents=True, exist_ok=True)
        os.chdir(data_dir)
        os.system('git clone https://github.com/CVEProject/cvelistV5')

def cve_filepath_iter():
    for path in cve_dir.glob('cves/[0-9][0-9][0-9][0-9]/**/*.json'):
        yield path

def read_file(path):
    with open(path, 'r') as f:
        return f.read()

def cve_json_iter():
    for path in cve_filepath_iter():
        yield json.loads(read_file(path))

def init_model():
    return SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')

def setup_db():
    """Create tables and indices for storing CVE data"""
    conn = psycopg2.connect(
        dbname="langcve",
        user="postgres", 
        password="postgres",
        host="localhost"
    )
    cur = conn.cursor()
    
    # Enable vector extension
    cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
    
    # Create table for CVEs
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            id SERIAL PRIMARY KEY,
            cve_id TEXT UNIQUE NOT NULL,
            description TEXT,
            description_embedding vector(384),  -- dimension matches MiniLM model
            date_published TIMESTAMP,
            date_updated TIMESTAMP,
            state TEXT,
            vendor TEXT,
            product TEXT,
            data_type TEXT,
            data_version TEXT,
            
            -- ADP fields
            cwe_id TEXT,
            cwe_description TEXT,
            cvss_version TEXT,
            cvss_vector_string TEXT,
            cvss_base_score FLOAT,
            cvss_base_severity TEXT,
            cvss_attack_vector TEXT,
            cvss_attack_complexity TEXT,
            cvss_privileges_required TEXT,
            cvss_user_interaction TEXT,
            cvss_scope TEXT,
            cvss_confidentiality_impact TEXT,
            cvss_integrity_impact TEXT,
            cvss_availability_impact TEXT,
            
            -- SSVC metrics
            ssvc_exploitation TEXT,
            ssvc_automatable TEXT,
            ssvc_technical_impact TEXT,
            ssvc_version TEXT,
            
            -- CPE data
            cpe_list TEXT[],
            affected_versions TEXT[]
        )
    """)
    
    # Create indices for common filters
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_id ON cves(cve_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_date_published ON cves(date_published)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_vendor ON cves(vendor)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_product ON cves(product)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cwe_id ON cves(cwe_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cvss_base_score ON cves(cvss_base_score)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cvss_base_severity ON cves(cvss_base_severity)")
    
    # Create vector similarity index
    cur.execute("CREATE INDEX IF NOT EXISTS idx_embedding ON cves USING ivfflat (description_embedding vector_cosine_ops)")
    
    # Create references table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cve_references (
            id SERIAL PRIMARY KEY,
            cve_id TEXT NOT NULL,
            url TEXT NOT NULL,
            tags TEXT[],
            content TEXT,
            content_embedding vector(384),
            last_fetched TIMESTAMP,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        )
    """)
    
    # Create indices for references
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ref_cve_id ON cve_references(cve_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ref_url ON cve_references(url)")
    
    conn.commit()
    cur.close()
    conn.close()

def safe_get(data, *keys, default=None):
    if keys:
        key = keys[0]
        try:
            data = safe_get(data[key], *keys[1:], default=default)
        except (KeyError, IndexError, TypeError) as e:
            return default
    return data

def insert_cve(model, cve_data):
    """Insert a single CVE record with embeddings"""
    conn = psycopg2.connect(
        dbname="langcve",
        user="postgres",
        password="postgres", 
        host="localhost"
    )
    cur = conn.cursor()
    
    # Extract description
    description = safe_get(cve_data, 'containers', 'cna', 'descriptions', 0, 'value', default='')
    if not description:
        print(f"No description found for {safe_get(cve_data, 'cveMetadata', 'cveId', default='')}")
    
    # Generate embedding
    embedding = model.encode(description)
    
    # Extract other fields
    cve_id = safe_get(cve_data, 'cveMetadata', 'cveId', default='')
    date_published = safe_get(cve_data, 'cveMetadata', 'datePublished', default='1970-01-01T00:00:00Z')
    date_updated = safe_get(cve_data, 'cveMetadata', 'dateUpdated', default='1970-01-01T00:00:00Z')
    state = safe_get(cve_data, 'cveMetadata', 'state', default='')
    
    # Extract vendor/product (handling possible missing data)
    affected = safe_get(cve_data, 'containers', 'cna', 'affected', 0, default={})
    vendor = safe_get(affected, 'vendor', default='unknown')
    product = safe_get(affected, 'product', default='unknown')
    
    data_type = safe_get(cve_data, 'dataType', default='')
    data_version = safe_get(cve_data, 'dataVersion', default='')
    
    # Extract references
    references = safe_get(cve_data, 'containers', 'cna', 'references', default=[])
    
    if references:
        # Insert references
        cur.execute("""
            INSERT INTO cve_references (cve_id, url, tags)
            VALUES %s
            ON CONFLICT (cve_id, url) DO NOTHING
        """, [
            (cve_id, ref.get('url', ''), ref.get('tags', []))
            for ref in references
        ])
    
    cur.execute("""
        INSERT INTO cves (
            cve_id, description, description_embedding, 
            date_published, date_updated, state,
            vendor, product, data_type, data_version
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (cve_id) DO UPDATE SET
            description = EXCLUDED.description,
            description_embedding = EXCLUDED.description_embedding,
            date_updated = EXCLUDED.date_updated,
            state = EXCLUDED.state
    """, (
        cve_id, description, embedding.tolist(),
        date_published, date_updated, state,
        vendor, product, data_type, data_version
    ))
    
    conn.commit()
    cur.close()
    conn.close()

def semantic_search(model, query_text, limit=10):
    """Search CVEs by semantic similarity to query text"""
    conn = psycopg2.connect(
        dbname="langcve",
        user="postgres",
        password="postgres",
        host="localhost"
    )
    cur = conn.cursor()
    
    # Generate embedding for query
    query_embedding = model.encode(query_text)
    
    # Search using vector similarity - note the vector type cast
    cur.execute("""
        SELECT cve_id, description, date_published, vendor, product,
               1 - (description_embedding <-> %s::vector) as similarity
        FROM cves
        ORDER BY description_embedding <-> %s::vector
        LIMIT %s
    """, (query_embedding.tolist(), query_embedding.tolist(), limit))
    
    results = cur.fetchall()
    cur.close()
    conn.close()
    return results

def populate_db():
    setup_db()
    model = init_model()
    for cve in tqdm(cve_json_iter(), total=278908):
        insert_cve(model, cve)

def example_search(model):
    results = semantic_search(model, """
    XSS vulnerabilities in PHP web applications
    """)
    for r in results:
        print(f"CVE: {r[0]}, Similarity: {r[5]:.3f}")
        print(f"Description: {r[1]}")
        print()

def get_cve_with_references(cve_id, model=None):
    """Get CVE details along with its references and their content"""
    
    conn = psycopg2.connect(
        dbname="langcve",
        user="postgres",
        password="postgres",
        host="localhost"
    )
    cur = conn.cursor()
    
    # Get CVE details
    cur.execute("""
        SELECT cve_id, description, date_published, vendor, product
        FROM cves WHERE cve_id = %s
    """, (cve_id,))
    
    cve_data = cur.fetchone()
    cur.close()
    conn.close()
    
    if not cve_data:
        return None
        
    # If model provided, update any unfetched references
    if model:
        reference_util.update_reference_content(model, cve_id)
    
    # Get references with content
    references = reference_util.get_references_with_content(cve_id)
    
    return {
        'cve_id': cve_data[0],
        'description': cve_data[1],
        'date_published': cve_data[2],
        'vendor': cve_data[3],
        'product': cve_data[4],
        'references': [
            {
                'url': ref[0],
                'tags': ref[1],
                'content': ref[2],
                'fetched_at': ref[3]
            }
            for ref in references
        ]
    }

if __name__ == "__main__":
    model = init_model()
    populate_db()
    example_search(model)