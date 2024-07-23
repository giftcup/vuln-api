import requests
from bs4 import BeautifulSoup
from ..models import Vulnerability, Scan_Url, Request as RequestModel, Response as ResponseModel

class XSSService:
    # Common XSS payloads to test
    UNIQUE_IDENTIFIER ="XSS Vulnerability Found"

    XSS_PAYLOADS = [
        f"<script>alert({UNIQUE_IDENTIFIER})</script>",
        f"<img src=x onerror=alert({UNIQUE_IDENTIFIER})>",
        f"<body onload=alert({UNIQUE_IDENTIFIER})>",
        f"<svg/onload=alert({UNIQUE_IDENTIFIER})>",
        f"';alert(String.fromCharCode(88,83,83))//",
        f"\"><script>alert({UNIQUE_IDENTIFIER})</script>",
        f"</script><script>alert({UNIQUE_IDENTIFIER})</script>",
        f"<input type=\"text\" value=\"\"><script>alert({UNIQUE_IDENTIFIER})</script>"
    ]

    @staticmethod
    def find_input_points(html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        input_points = []
        # Including forms and inputs
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '#')  # Use the form's action or default to current page
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input') + form.find_all('textarea')
            for input_tag in inputs:
                input_name = input_tag.get('name')
                input_points.append({'action': action, 'method': method, 'input_name': input_name})
        
        # Extend to other inputs not within forms if necessary
        standalone_inputs = soup.find_all(['input', 'textarea'])
        for input_tag in standalone_inputs:
            if input_tag not in forms:
                input_points.append({'action': '#', 'method': 'get', 'input_name': input_tag.get('name')})

        return input_points

    @staticmethod
    def inject_payloads(scan_url):
        input_points = XSSService.find_input_points(scan_url.html_content)
        vulnerabilities = []

        for point in input_points:
            url = point['action'] if point['action'].startswith('http') else scan_url.scan_url + point['action']
            method = point['method']

            for payload in XSSService.XSS_PAYLOADS:
                data = {point['input_name']: payload}
                
                # req = requests.Request(method, url, params=data)
                # prepared = req.prepare()

                if method == 'post':
                    response = requests.post(url, data=data)
                    req = requests.Request(method, url, data=data)
                else:
                    response = requests.get(url, params=data)
                    req = requests.Request(method, url, params=data)
                
                prepared = req.prepare()

                
                request_obj = RequestModel.objects.create(
                        scan_url=scan_url,
                        method=method.upper(),
                        payload=str(prepared.url),
                        headers=str(response.request.headers)
                    )
                response_obj = ResponseModel.objects.create(
                        request=request_obj,
                        status_code=response.status_code,
                        headers=str(response.headers),
                        content=response.text
                    )

                # Check for the unique identifier in the response
                if XSSService.UNIQUE_IDENTIFIER in response.text:
                    
                    vulnerability = Vulnerability.objects.create(
                        scan_url=scan_url,
                        type='XSS',
                        description=f'Detected potential XSS vulnerability. Cross-site scripting vulnerabilities allows attackers to inject malicious scripts into webpages viewed by other users. An XSS vulnerability can enable attackers to bypass access controls such as the same-origin policy',
                        severity='high',
                        proof_of_concept=f"Payload injected: {str(data)} \n Response: {str(response.text)}",
                        recommendation=f"""
                        - Ensure that all user inputs are properly validated on both the client-side and server-side.
                        - Allow only expected and safe input values. For example, if a field expects an email, ensure the input matches the email format.
                        - Encode data before rendering it to the browser. This prevents the browser from interpreting the data as executable code. """
                    )

                    vulnerabilities.append(vulnerability)

                    break  # Stop testing other payloads for this input point
        return vulnerabilities

    @staticmethod
    def scan_for_vulnerabilities(scan):
        scan_urls = Scan_Url.objects.filter(scan=scan)
        all_vulnerabilities = []
        for scan_url in scan_urls:
            vulnerabilities = XSSService.inject_payloads(scan_url)
            all_vulnerabilities.extend(vulnerabilities)
        
        return all_vulnerabilities
