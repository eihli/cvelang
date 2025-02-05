import logging
import os
from typing import List

from anthropic import Anthropic
from bs4 import BeautifulSoup
from markdownify import markdownify as md
from openai import OpenAI
import psycopg2
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.firefox import GeckoDriverManager

from cvelang import cve_util

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


conn = psycopg2.connect(**cve_util.DB_CONFIG)

def get_cves_with_references(conn: psycopg2.extensions.connection, cve_ids: List[str]) -> List[str]:
    cursor = conn.cursor()
    cursor.execute("""
        SELECT cve.cve_id, cve.description, cve.references FROM cve_details as cve
        WHERE cve.cve_id IN %s
    """, (tuple(cve_ids),))
    cve_details = cursor.fetchall()
    return cve_details

def create_driver():
    """Create and return a configured Firefox WebDriver instance."""
    firefox_options = Options()
    firefox_options.add_argument("--headless")  # Run in headless mode
    
    service = Service(GeckoDriverManager().install())
    driver = webdriver.Firefox(service=service, options=firefox_options)
    return driver

def fetch_text_content(url: str, timeout: int = 10) -> str:
    """
    Fetch content from a URL using Selenium with Firefox, with support for JavaScript rendering.
    Extracts code blocks separately to maintain their formatting.
    
    Args:
        url: The URL to fetch content from
        timeout: Maximum time to wait for page load in seconds
        
    Returns:
        Combined content with markdown text and preserved code blocks
    """
    driver = create_driver()
    try:
        driver.get(url)
        
        try:
            WebDriverWait(driver, timeout).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
        except TimeoutException:
            logger.warning(f"Timeout waiting for page to load: {url}")
        
        # First extract all code blocks and replace them with placeholders
        code_blocks = []
        html_content = driver.page_source
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Find all pre and code elements
        code_elements = soup.find_all(['pre', 'code'])
        
        for i, elem in enumerate(code_elements):
            # Store the original code block
            code_blocks.append(elem.get_text())
            # Replace with a unique placeholder
            placeholder = f"CODEBLOCK_PLACEHOLDER_{i}"
            elem.string = placeholder
        
        # Convert the main content to markdown
        modified_html = str(soup)
        text_content = md(modified_html)
        
        # Replace placeholders with original code blocks wrapped in markdown code fences
        for i, code_block in enumerate(code_blocks):
            placeholder = f"CODEBLOCK_PLACEHOLDER_{i}"
            code_fence = f"```\n{code_block}\n```"
            text_content = text_content.replace(placeholder, code_fence)
        
        return text_content
    
    except Exception as e:
        logger.error(f"Error fetching content from {url}: {str(e)}")
        return ""
    
    finally:
        driver.quit()

cves = get_cves_with_references(conn, ['CVE-2024-5555'])
text_content = fetch_text_content(cves[0][2][0])

cves
print(text_content)


class AIClient:
    """Wrapper class for different AI providers"""
    def __init__(self, provider="openai", api_key=None, base_url=None):
        self.provider = provider.lower()
        api_key = api_key or os.getenv(f"{provider.upper()}_API_KEY")
        if not api_key:
            raise ValueError(f"No API key provided for {provider} and none found in environment")
            
        if self.provider == "openai":
            self.client = OpenAI(api_key=api_key, base_url=base_url)
        elif self.provider == "anthropic":
            self.client = Anthropic(api_key=api_key)
        else:
            raise ValueError(f"Unsupported AI provider: {provider}")

    def apply_chat_template(self, prompt: str, model: str = None, temperature: float = 0.3) -> str:
        """Apply a chat template to the prompt"""
        template = """< | begin_of_sentence | >You are an expert in cybersecurity and software engineering and you have been hired to help secure some software.
You care about safe and secure code. You pare careful attention to how you can improve code to make it safer.
In order for your team to improve and secure the code, it is important to describe the vulnerabilities in detail.
You are given a text content and asked to summarize any content relevant to cybersecurity vulnerabilities and exploits.
If there are no vulnerabilities in the <content>...</content> section, you should simply say that you found no vulnerabilities.
You will only describe vulnerabilities that you specifically see in the <content>...</content> section.
When you identify a vulnerability, you should include the content of the line(s) in your summary.
You will be given the text content in chunks and asked to summarize each chunk.
You will be subsequently be given your previous summary and the next chunk of text and asked to amend your summary to include the new chunk.
### Instruction:
{{prompt}}"""
        return template.replace("{{prompt}}", prompt)
    
    def get_completion(self, prompt: str, model: str = None, temperature: float = 0.3) -> str:
        """Get completion from the selected AI provider"""
        try:
            if self.provider == "openai":
                model = model or "deepseek-ai/deepseek-coder-6.7b-instruct"
                response = self.client.chat.completions.create(
                    model=model,
                    temperature=temperature,
                    messages=[
                        {"role": "system", "content": """You are an expert in cybersecurity and software engineering and you have been hired to help secure some software.
You care about safe and secure code. You pare careful attention to how you can improve code to make it safer.
In order for your team to improve and secure the code, it is important to describe the vulnerabilities in detail.
You are given a text content and asked to summarize any content relevant to cybersecurity vulnerabilities and exploits.
If there are no vulnerabilities in the <content>...</content> section, you should simply say that you found no vulnerabilities.
You will only describe vulnerabilities that you specifically see in the <content>...</content> section.
When you identify a vulnerability, you should include the content of the line(s) in your summary.
You will be given the text content in chunks and asked to summarize each chunk.
You will be subsequently be given your previous summary and the next chunk of text and asked to amend your summary to include the new chunk."""},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=2048,
                )
                return response.choices[0].message.content
                # response = self.client.completions.create(
                #     model=model,
                #     temperature=temperature,
                #     prompt=self.apply_chat_template(prompt),
                #     max_tokens=2048,
                # )
                # return response.choices[0].text
                
            elif self.provider == "anthropic":
                model = model or "claude-3-haiku-20240307"
                response = self.client.messages.create(
                    model=model,
                    temperature=temperature,
                    max_tokens=500,
                    messages=[{
                        "role": "user",
                        "content": prompt
                    }]
                )
                return response.content[0].text

        except Exception as e:
            logger.error(f"Error getting completion from {self.provider}: {str(e)}")
            return ""

def summarize_content(client: AIClient, text_content: str, model: str = None, temperature: float = 0.3) -> str:
    """
    Summarize the text content using the configured AI provider.
    
    Args:
        client: The AIClient instance
        text_content: The text content to summarize
        model: The model to use for summarization (provider-specific)
        temperature: Controls randomness in the response (0.0-1.0)
        
    Returns:
        A string containing the summarized content
    """
    if not text_content.strip():
        logger.warning("Empty text content provided for summarization")
        return ""
    summary = ""
    i, j = 0, 16384
    prompt = f"Please summarize your findings related to cybersecurity vulnerabilities and exploits in the following text content:\n\n{text_content[i:j]}"    
    summary = client.get_completion(prompt, model, temperature)
    i, j = j, j + 14336
    while i < len(text_content):
        prompt = f"""You previously summarized your findings related to cybersecurity vulnerabilities and exploits in the first part of this content as:
{summary}
Please amend that summary to include your findings related to cybersecurity vulnerabilities and exploits in the <content>...</content> section below:
<content>
{text_content[i:j]}
</content>
As I said earlier, you are helping a team to write secure software. You previously summarized your findings related to cybersecurity vulnerabilities and exploits in the first part of this content as:
<summary>
{summary}
</summary>
Please amend that summary to include your findings how to ensure the code is secure from vulnerabilities in the <content>...</content. section above."""
        summary = client.get_completion(prompt, model, temperature)
        i, j = j, j + 14336
    return summary

def __test():
    # Example usage:
    client = AIClient(provider="anthropic")  # Will use ANTHROPIC_API_KEY from environment
    summarized = summarize_content(client, text_content)
    print(summarized)

    client = AIClient(provider="openai", base_url="http://localhost:8000/v1")
    summarized = summarize_content(client, text_content)

    print(summarized)