import logging
from sentence_transformers import SentenceTransformer
from cve_util import get_cve_with_references, semantic_search
from reference_util import update_reference_content

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_reference_fetching():
    """Test fetching and displaying reference content for CVEs"""
    
    # Initialize the model once
    model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
    
    # First, let's find some interesting CVEs to test with
    print("\n=== Finding CVEs with likely PoCs ===")
    results = semantic_search(model, "proof of concept exploit available on GitHub", limit=5)
    
    for result in results:
        cve_id = result[0]
        print(f"\n=== Testing {cve_id} ===")
        print(f"Description: {result[1]}")
        
        # Get CVE details and fetch any missing reference content
        cve_data = get_cve_with_references(cve_id, model)
        
        if not cve_data:
            print("No CVE data found!")
            continue
            
        print("\nReferences found:")
        for ref in cve_data['references']:
            print(f"\nURL: {ref['url']}")
            print(f"Tags: {ref['tags']}")
            print(f"Fetched at: {ref['fetched_at']}")
            if ref['content']:
                print("Content preview (first 200 chars):")
                print(ref['content'][:200] + "...")
            else:
                print("No content fetched")

def test_batch_update():
    """Test batch updating of reference content"""
    print("\n=== Testing batch reference updates ===")
    
    model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
    
    # Update a batch of references
    update_reference_content(model, batch_size=5)

if __name__ == "__main__":
    print("Starting reference fetching tests...")
    
    # Test individual CVE reference fetching
    test_reference_fetching()
    
    # Test batch updates
    test_batch_update() 