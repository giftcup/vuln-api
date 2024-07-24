import requests
from bs4 import BeautifulSoup
from ..models import Scan_Url, Vulnerability, Request, Response as ResponseModel

class SQLInjectionService:
    SQL_INJECTION_PAYLOADS = [
        "' OR '1'=",
        "' OR '1'=1' --",
        "' OR '1'='1 ({",
        "' OR ='1' /*",
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
            action = form.get('action', '#')  # Use the form's action or default to the current page if none
            method = form.get('method', 'get').lower()
            inputs = {input_tag.get('name'): '' for input_tag in form.find_all(['input', 'textarea', 'select']) if input_tag.get('name')}
            input_points.append({'action': action, 'method': method, 'inputs': inputs})

        return input_points

    @staticmethod
    def inject_payloads(scan_url):
        input_points = SQLInjectionService.find_input_points(scan_url.html_content)
        vulnerabilities = []

        for point in input_points:
            for payload in SQLInjectionService.SQL_INJECTION_PAYLOADS:
                data = point['inputs'].copy()  # Copy existing input fields
                for input_name in data.keys():
                    data[input_name] = payload  # Inject payload into each field one by one

                url = point['action'] if point['action'].startswith('http') else scan_url.scan_url + point['action']
                method = point['method']

                # Send the request with the payload
                if method == 'post':
                    response = requests.post(url, data=data)
                else:
                    response = requests.get(url, params=data)

                # Check response for indications of SQL injection
                if any(error in response.text for error in SQLInjectionService.SQL_ERROR_PATTERNS) or response.status_code != 200:
                    vulnerability = Vulnerability.objects.create(
                        scan_url=scan_url,
                        type='SQLi',
                        description=f'Detected potential SQL injection vulnerability with payload: {payload}',
                        severity='high',
                        proof_of_concept=f'SQL error pattern matched in response: {response.text[:200]}',
                        recommendation = """Developers can prevent SQL Injection vulnerabilities in web applications by utilizing parameterized database queries with bound, typed parameters and careful use of parameterized stored procedures in the database."""
                    )
                    vulnerability.save()
                    vulnerabilities.append(vulnerability)
                    break  # Stop testing other payloads if a vulnerability is found

        return vulnerabilities

    
    @staticmethod
    def scan_for_vulnerabilities(scan):
        scan_urls = Scan_Url.objects.filter(scan=scan)
        all_vulnerabilities = []
        for scan_url in scan_urls:
            vulnerabilities = SQLInjectionService.inject_payloads(scan_url)
            all_vulnerabilities.extend(vulnerabilities)

        return all_vulnerabilities
