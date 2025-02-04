-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "vector";

-- Create tables for CVE records
CREATE TABLE cve_records (
    cve_id TEXT PRIMARY KEY,
    published_date TIMESTAMP NOT NULL,
    last_modified_date TIMESTAMP NOT NULL,
    title TEXT,
    description TEXT NOT NULL,
    description_vector vector(1536), -- For semantic similarity search
    status TEXT NOT NULL,
    cvss_v3_vector TEXT,
    cvss_v3_base_score NUMERIC(3,1),
    cvss_v3_base_severity TEXT,
    cvss_v2_vector TEXT,
    cvss_v2_base_score NUMERIC(3,1),
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for references/links from CVE records
CREATE TABLE cve_references (
    id SERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cve_records(cve_id),
    url TEXT NOT NULL,
    source TEXT,
    tags TEXT[],
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for affected products/versions
CREATE TABLE cve_affected_products (
    id SERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cve_records(cve_id),
    product TEXT NOT NULL,
    vendor TEXT,
    version TEXT,
    package_name TEXT,
    ecosystem TEXT,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indices for common queries
CREATE INDEX idx_cve_records_description_vector ON cve_records USING ivfflat (description_vector vector_cosine_ops);
CREATE INDEX idx_cve_references_cve_id ON cve_references(cve_id);
CREATE INDEX idx_cve_affected_products_cve_id ON cve_affected_products(cve_id);
CREATE INDEX idx_cve_affected_products_product ON cve_affected_products(product);
CREATE INDEX idx_cve_affected_products_vendor ON cve_affected_products(vendor);

-- Create a view for easy querying of complete CVE information
CREATE VIEW cve_details AS
SELECT 
    r.cve_id,
    r.published_date,
    r.last_modified_date,
    r.title,
    r.description,
    r.status,
    r.cvss_v3_vector,
    r.cvss_v3_base_score,
    r.cvss_v3_base_severity,
    r.cvss_v2_vector,
    r.cvss_v2_base_score,
    array_agg(DISTINCT ref.url) as references,
    array_agg(DISTINCT ap.product) as affected_products,
    array_agg(DISTINCT ap.vendor) as vendors
FROM cve_records r
LEFT JOIN cve_references ref ON r.cve_id = ref.cve_id
LEFT JOIN cve_affected_products ap ON r.cve_id = ap.cve_id
GROUP BY r.cve_id, r.published_date, r.last_modified_date, r.title, r.description, r.status,
         r.cvss_v3_vector, r.cvss_v3_base_score, r.cvss_v3_base_severity, r.cvss_v2_vector, r.cvss_v2_base_score; 