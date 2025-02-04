import os
import logging
from datetime import datetime
from pathlib import Path
import psycopg2
from github import Github
import requests
from tqdm import tqdm

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_db_connection():
    return psycopg2.connect(
        dbname="langcve",
        user="postgres",
        password="postgres",
        host="localhost"
    )

def find_github_repos(cve_data):
    """Extract potential GitHub repository URLs from CVE data"""
    repos = set()
    
    # Check product name for GitHub references
    product = cve_data.get('product', '').lower()
    if 'github.com' in product:
        repos.add(product)
    
    # Check references for GitHub links
    for ref in cve_data.get('references', []):
        url = ref.get('url', '').lower()
        if 'github.com' in url and not url.endswith(('.pdf', '.txt', '.html')):
            # Convert to raw repo URL if possible
            if '/blob/' in url:
                url = url.replace('/blob/', '/').replace('github.com', 'raw.githubusercontent.com')
            repos.add(url)
    
    return list(repos)

def extract_code_snippet(file_content, query, context_lines=5):
    """Extract relevant code snippet around matching text"""
    lines = file_content.split('\n')
    matches = []
    
    query = query.lower()
    for i, line in enumerate(lines):
        if query in line.lower():
            start = max(0, i - context_lines)
            end = min(len(lines), i + context_lines + 1)
            snippet = '\n'.join(lines[start:end])
            matches.append({
                'content': snippet,
                'start_line': start + 1,
                'end_line': end
            })
    
    return matches

def detect_language(file_path):
    """Simple language detection based on file extension"""
    ext = Path(file_path).suffix.lower()
    extensions = {
        '.py': 'Python',
        '.js': 'JavaScript',
        '.java': 'Java',
        '.cpp': 'C++',
        '.c': 'C',
        '.go': 'Go',
        '.rs': 'Rust',
        '.php': 'PHP',
        '.rb': 'Ruby'
    }
    return extensions.get(ext, 'Unknown')

def store_code_snippet(cur, cve_id, repo_url, file_path, snippet, model):
    """Store a code snippet with its embedding in the database"""
    try:
        # Generate embedding for the code content
        embedding = model.encode(snippet['content'])
        
        cur.execute("""
            INSERT INTO code_snippets 
            (cve_id, repo_url, file_path, code_content, code_embedding, 
             language, start_line, end_line, last_fetched)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (cve_id, repo_url, file_path, start_line) 
            DO UPDATE SET
                code_content = EXCLUDED.code_content,
                code_embedding = EXCLUDED.code_embedding,
                last_fetched = EXCLUDED.last_fetched
        """, (
            cve_id, repo_url, file_path, snippet['content'], 
            embedding.tolist(), detect_language(file_path),
            snippet['start_line'], snippet['end_line'], datetime.now()
        ))
        
    except Exception as e:
        logger.error(f"Error storing code snippet: {e}")

def fetch_and_process_code(model, cve_id, description):
    """Fetch and process code for a CVE"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Get CVE data including references
        cur.execute("""
            SELECT c.*, array_agg(r.url) as refs
            FROM cves c
            LEFT JOIN cve_references r ON c.cve_id = r.cve_id
            WHERE c.cve_id = %s
            GROUP BY c.id
        """, (cve_id,))
        
        cve_data = cur.fetchone()
        if not cve_data:
            return
            
        # Find potential GitHub repositories
        repos = find_github_repos({
            'product': cve_data[8],  # product field
            'references': [{'url': url} for url in cve_data[-1]]  # refs array
        })
        
        for repo_url in repos:
            try:
                # Fetch raw file content
                response = requests.get(repo_url)
                if response.status_code == 200:
                    content = response.text
                    
                    # Extract relevant snippets using description as query
                    snippets = extract_code_snippet(content, description)
                    
                    # Store each snippet
                    for snippet in snippets:
                        store_code_snippet(
                            cur, cve_id, repo_url, 
                            repo_url.split('/')[-1],  # filename
                            snippet, model
                        )
                    
                    conn.commit()
                    
            except Exception as e:
                logger.error(f"Error processing repo {repo_url}: {e}")
                continue
                
    finally:
        cur.close()
        conn.close()

def get_code_snippets(cve_id):
    """Get all code snippets for a CVE"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT repo_url, file_path, code_content, 
               language, start_line, end_line, last_fetched
        FROM code_snippets 
        WHERE cve_id = %s
        ORDER BY last_fetched DESC
    """, (cve_id,))
    
    results = cur.fetchall()
    cur.close()
    conn.close()
    
    return [
        {
            'repo_url': r[0],
            'file_path': r[1],
            'content': r[2],
            'language': r[3],
            'start_line': r[4],
            'end_line': r[5],
            'fetched_at': r[6]
        }
        for r in results
    ]

def semantic_search_code(model, query_text, limit=10):
    """Search code snippets by semantic similarity to query text"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Generate embedding for query
    query_embedding = model.encode(query_text)
    
    # Search using vector similarity
    cur.execute("""
        SELECT cve_id, repo_url, file_path, code_content, language,
               1 - (code_embedding <-> %s::vector) as similarity
        FROM code_snippets
        ORDER BY code_embedding <-> %s::vector
        LIMIT %s
    """, (query_embedding.tolist(), query_embedding.tolist(), limit))
    
    results = cur.fetchall()
    cur.close()
    conn.close()
    return results
