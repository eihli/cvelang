import pytest
from cvelang import cve_util, reference_util, code_util

@pytest.fixture
def model():
    return cve_util.init_model()

def test_semantic_search(model):
    results = cve_util.semantic_search(model, "buffer overflow vulnerability", limit=5)
    assert len(results) > 0
    assert all(isinstance(r[0], str) for r in results)  # CVE IDs
    assert all(isinstance(r[5], float) for r in results)  # Similarity scores
    assert all(0 <= r[5] <= 1 for r in results)  # Scores should be normalized

def test_get_cve_with_references():
    cve_id = "CVE-2024-55637"  # Arbitrary Drupal example
    result = cve_util.get_cve_with_references(cve_id)
    assert result is not None
    assert result['cve_id'] == cve_id
    assert 'description' in result
    assert 'references' in result
    assert 'code_snippets' in result

def test_code_search(model):
    results = code_util.semantic_search_code(model, "SQL injection example", limit=5)
    assert len(results) >= 0  # May be 0 if no code snippets yet
    if results:
        assert all(isinstance(r[0], str) for r in results)  # CVE IDs
        assert all(isinstance(r[5], float) for r in results)  # Similarity scores
