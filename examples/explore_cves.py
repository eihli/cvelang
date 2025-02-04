import logging
from sentence_transformers import SentenceTransformer
from cvelang import cve_util, reference_util, code_util

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    # Initialize the embedding model
    logger.info("Initializing embedding model...")
    model = cve_util.init_model()

    # Ensure database is set up
    logger.info("Setting up database...")
    cve_util.setup_db()

    # Example 1: Search for Log4j vulnerabilities
    logger.info("\n=== Example 1: Semantic Search for Log4j ===")
    results = cve_util.semantic_search(model, """
        Log4j remote code execution vulnerabilities
    """, limit=3)
    
    for r in results:
        print(f"\nCVE: {r[0]}, Similarity: {r[5]:.3f}")
        print(f"Description: {r[1]}")
        
        # Get full details including references and code
        details = cve_util.get_cve_with_references(r[0], model)
        if details:
            print("\nReferences with content:")
            for ref in details['references']:
                if ref['content']:
                    print(f"- {ref['url'][:100]}...")
                    
            print("\nCode snippets:")
            for snippet in details['code_snippets']:
                print(f"\nFrom {snippet['repo_url']}")
                print(f"Language: {snippet['language']}")
                print("Content preview:")
                preview = snippet['content'].split('\n')[:5]
                print('\n'.join(preview))
                if len(snippet['content'].split('\n')) > 5:
                    print("...")

    # Example 2: Search specifically for code examples
    logger.info("\n=== Example 2: Semantic Code Search ===")
    code_results = code_util.semantic_search_code(model, """
        SQL injection vulnerability example
    """, limit=3)
    
    for r in code_results:
        print(f"\nCVE: {r[0]}")
        print(f"Repository: {r[1]}")
        print(f"Language: {r[4]}")
        print(f"Similarity: {r[5]:.3f}")
        print("Code preview:")
        preview = r[3].split('\n')[:5]
        print('\n'.join(preview))
        if len(r[3].split('\n')) > 5:
            print("...")

if __name__ == "__main__":
    main()
