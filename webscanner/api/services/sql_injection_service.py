import requests
from bs4 import BeautifulSoup
from ..models import Scan_Url, Vulnerability, Request, Response as ResponseModel

class SQLInjectionService:
    SQL_INJECTION_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' ({",
        "' OR '1'='1' /*",
    ]

    SQL_ERROR_PATTERNS = [
        'SQL syntax',
        'mysql_fetch',
        'You have an error in your SQL syntax',
        'Warning: mysql',
        'Unclosed quotation mark',
        'quoted string not properly terminated',
    ]

    @staticmethod
    def find_input_points(html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = soup.find_all('form')
        input_points = []

        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            for input_tag in inputs:
                input_name = input_tag.get('name')
                input_points.append({
                    'action': action,
                    'method': method,
                    'input_name': input_name
                })

        return input_points

    @staticmethod
    def inject_payloads(scan_url):
        input_points = SQLInjectionService.find_input_points(scan_url.html_content)
        vulnerabilities = []

        for point in input_points:
            url = point['action']
            if not url.startswith('http'):
                url = scan_url.url + url

            method = point['method']

            for payload in SQLInjectionService.SQL_INJECTION_PAYLOADS:
                data = {point['input_name']: payload}

                if method == 'post':
                    response = requests.post(url, data=data)
                else:
                    response = requests.get(url, params=data)

                # Store the request and response
                request_obj = Request.objects.create(
                    scan_url=scan_url,
                    method=method.upper(),
                    payload=str(data),
                    headers=str(response.request.headers)
                )
                response_obj = ResponseModel.objects.create(
                    request=request_obj,
                    status_code=response.status_code,
                    headers=str(response.headers),
                    content=response.text
                )

                # Check if the response contains SQL error patterns
                if any(error in response.text for error in SQLInjectionService.SQL_ERROR_PATTERNS):
                    vulnerability = Vulnerability.objects.create(
                        scan_url=scan_url,
                        type='SQL Injection Vulnerability',
                        description=f'Detected potential SQL injection vulnerability with payload: {payload}',
                        severity='high',
                        proof_of_concept=f'SQL error pattern matched in response: {response.text[:200]}'
                    )
                    vulnerabilities.append(vulnerability)

        return vulnerabilities

    @staticmethod
    def scan_for_vulnerabilities(scan):
        scan_urls = Scan_Url.objects.filter(scan=scan)
        all_vulnerabilities = []
        for scan_url in scan_urls:
            vulnerabilities = SQLInjectionService.inject_payloads(scan_url)
            all_vulnerabilities.extend(vulnerabilities)

        return all_vulnerabilities
