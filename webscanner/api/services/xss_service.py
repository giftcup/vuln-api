import requests
from bs4 import BeautifulSoup
from ..models import Vulnerability, Scan_Url, Request, Response as ResponseModel

class XSSService:
    XSS_PAYLOAD = '<script>alert("XSS")</script>'

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
        input_points = XSSService.find_input_points(scan_url.html_content)
        vulnerabilities = []

        for point in input_points:
            url = point['action']
            if not url.startswith('http'):
                url = scan_url.scan_url + url

            method = point['method']
            payload = {point['input_name']: XSSService.XSS_PAYLOAD}

            if method == 'post':
                response = requests.post(url, data=payload)
            else:
                response = requests.get(url, params=payload)

            # Store the request and response
            request_obj = Request.objects.create(
                scan_url=scan_url,
                method=method.upper(),
                payload=str(payload),
                headers=str(response.request.headers)
            )
            response_obj = ResponseModel.objects.create(
                request=request_obj,
                status_code=response.status_code,
                headers=str(response.headers),
                content=response.text
            )

            # Check if the payload is reflected in the response content
            if XSSService.XSS_PAYLOAD in response.text:
                vulnerability = Vulnerability.objects.create(
                    scan_url=scan_url,
                    type='XSS Vulnerability',
                    description='Detected potential XSS vulnerability.',
                    severity='high',
                    proof_of_concept=f'XSS payload reflected: {XSSService.XSS_PAYLOAD}'
                )
                vulnerabilities.append(vulnerability)

        return vulnerabilities

    @staticmethod
    def scan_for_vulnerabilities(scan):
        scan_urls = Scan_Url.objects.filter(scan=scan)
        all_vulnerabilities = []
        for scan_url in scan_urls:
            vulnerabilities = XSSService.inject_payloads(scan_url)
            all_vulnerabilities.extend(vulnerabilities)

        return all_vulnerabilities
