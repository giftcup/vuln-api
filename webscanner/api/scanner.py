import requests
from .models import Vulnerability

SQLI_PAYLOADS = ["' OR '1'='1", "' OR '1'='1' --", "' OR 1=1 --"]

def perform_sql_injection_scan(url_instance):
    for payload in SQLI_PAYLOADS:
        vulnerable, response_content = test_sql_injection(url_instance.url, payload)
        if vulnerable:
            create_vulnerability(url_instance, payload, response_content)
            break

def test_sql_injection(url, payload):
    test_url = f"{url}?id={payload}"
    response = requests.get(test_url)
    if "syntax error" in response.text or "unexpected" in response.text:
        return True, response.text
    return False, response.text

def create_vulnerability(url_instance, payload, response_content):
    vulnerability = Vulnerability.objects.create(
        url=url_instance,
        type="SQL Injection",
        description=f"SQL Injection vulnerability found using payload: {payload}",
        severity="high",
        proof_of_concept=response_content
    )
    vulnerability.save()

