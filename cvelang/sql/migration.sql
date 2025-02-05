-- Enable vector extension if not already enabled
CREATE EXTENSION IF NOT EXISTS vector;

-- Create references table (using cve_references instead of references)
CREATE TABLE IF NOT EXISTS cve_references (
    id SERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL,
    url TEXT NOT NULL,
    tags TEXT[],
    content TEXT,
    content_embedding vector(384),
    last_fetched TIMESTAMP,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);

-- Create indices for references
CREATE INDEX IF NOT EXISTS idx_ref_cve_id ON cve_references(cve_id);
CREATE INDEX IF NOT EXISTS idx_ref_url ON cve_references(url);

-- Populate references table from existing CVE data
INSERT INTO cve_references (cve_id, url, tags)
SELECT 
    c.cve_id,
    r->>'url' as url,
    ARRAY(SELECT jsonb_array_elements_text(r->'tags')) as tags
FROM cves c,
LATERAL jsonb_array_elements(
    jsonb_extract_path(
        c.data::jsonb, 
        'containers', 
        'cna', 
        'references'
    )
) as r
ON CONFLICT (cve_id, url) DO NOTHING; 