import requests
from bs4 import BeautifulSoup
import psycopg2
from urllib.parse import urlparse
import logging
from datetime import datetime
from sentence_transformers import SentenceTransformer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create a session to reuse across requests
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
})

def get_db_connection():
    return psycopg2.connect(
        dbname="cvelang",
        user="postgres",
        password="postgres",
        host="localhost"
    )

def fetch_github_content(url):
    """Fetch content from GitHub repositories"""
    try:
        response = session.get(url)
        response.raise_for_status()
        
        if 'raw.githubusercontent.com' in url:
            return response.text
        
        soup = BeautifulSoup(response.text, 'html.parser')
        readme = soup.find('article', class_='markdown-body')
        return readme.get_text() if readme else None
            
    except Exception as e:
        logger.error(f"Error fetching GitHub content from {url}: {e}")
        return None

def fetch_exploit_db_content(url):
    """Fetch proof of concept from Exploit-DB"""
    try:
        response = session.get(url)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        poc_content = soup.find('pre', id='code-preview')
        return poc_content.get_text() if poc_content else None
        
    except Exception as e:
        logger.error(f"Error fetching Exploit-DB content from {url}: {e}")
        return None

def fetch_reference_content(url):
    """Fetch and extract relevant content from reference URLs"""
    parsed_url = urlparse(url)
    
    if 'github.com' in parsed_url.netloc:
        return fetch_github_content(url)
    elif 'exploit-db.com' in parsed_url.netloc:
        return fetch_exploit_db_content(url)
    
    return None

def update_reference_content(model, cve_id=None, batch_size=100):
    """Update reference content for CVEs that haven't been fetched yet"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Build query based on whether we're updating a specific CVE or batch processing
        if cve_id:
            cur.execute("""
                SELECT id, url FROM cve_references 
                WHERE cve_id = %s AND (last_fetched IS NULL OR content IS NULL)
            """, (cve_id,))
        else:
            cur.execute("""
                SELECT id, url FROM cve_references 
                WHERE last_fetched IS NULL OR content IS NULL
                LIMIT %s
            """, (batch_size,))
        
        for ref_id, url in cur.fetchall():
            content = fetch_reference_content(url)
            if content:
                # Generate embedding for the content
                embedding = model.encode(content)
                
                cur.execute("""
                    UPDATE cve_references 
                    SET content = %s, 
                        content_embedding = %s,
                        last_fetched = %s
                    WHERE id = %s
                """, (content, embedding.tolist(), datetime.now(), ref_id))
                
                conn.commit()
                logger.info(f"Updated content for reference {ref_id} ({url})")
            else:
                # Mark as fetched even if no content to avoid repeated attempts
                cur.execute("""
                    UPDATE cve_references 
                    SET last_fetched = %s
                    WHERE id = %s
                """, (datetime.now(), ref_id))
                conn.commit()
                
    except Exception as e:
        logger.error(f"Error updating references: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

def get_references_with_content(cve_id):
    """Get all references and their content for a CVE"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT url, tags, content, last_fetched
        FROM cve_references 
        WHERE cve_id = %s AND content IS NOT NULL
    """, (cve_id,))
    
    results = cur.fetchall()
    cur.close()
    conn.close()
    return results 