from bs4 import BeautifulSoup
from ..models import Scan_Url, Vulnerability

class CSRFService:
    @staticmethod
    def check_for_csrf(scan_url):
        html_content = scan_url.html_content
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = soup.find_all('form')
        vulnerabilities = []

        for form in forms:
            if 'csrfmiddlewaretoken' not in str(form):
                # No CSRF token found in form
                vulnerability = Vulnerability(
                    scan_url=scan_url,
                    type='CSRF',
                    description="Missing CSRF token in form. A Cross-Site Request Forgery (CSRF) attack can force an end user to execute unwanted actions on a web application in which they’re currently authenticated.",
                    severity='high',
                    proof_of_concept=f"Form action: {form.get('action')}",
                    recommendation='Ensure that all forms include a CSRF token to protect against cross-site request forgery attacks. This can be achieved by adding a CSRF token field to the form and validating it on the server side.'
                )
                vulnerability.save()
                vulnerabilities.append(vulnerability)

        return vulnerabilities

    @staticmethod
    def scan_for_vulnerabilities(scan):
        scan_urls = Scan_Url.objects.filter(scan=scan)
        all_vulnerabilities = []
        for scan_url in scan_urls:
            vulnerabilities = CSRFService.check_for_csrf(scan_url)
            all_vulnerabilities.extend(vulnerabilities)
        
        return all_vulnerabilities
