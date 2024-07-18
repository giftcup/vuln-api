from ..models import Vulnerability, Scan_Url

class SecurityHeaderService:
    SECURITY_HEADERS = {
        'Content-Security-Policy': 'Content Security Policy (CSP) helps to prevent various types of attacks, including Cross-Site Scripting (XSS) and data injection attacks.',
        'Strict-Transport-Security': 'HTTP Strict Transport Security (HSTS) ensures that browsers only connect to your site using HTTPS, preventing downgrade attacks.',
        'X-Content-Type-Options': 'X-Content-Type-Options prevents browsers from interpreting files as a different MIME type, which can lead to security vulnerabilities.',
        'X-Frame-Options': 'X-Frame-Options prevents your site from being embedded in an iframe, which can help prevent clickjacking attacks.',
        'X-XSS-Protection': 'X-XSS-Protection helps prevent some types of Cross-Site Scripting (XSS) attacks by instructing the browser to block the page or sanitize the script.',
        'Referrer-Policy': 'Referrer Policy controls how much referrer information should be included with requests. It helps to prevent information leakage.',
        'Permissions-Policy': 'Permissions Policy (formerly known as Feature Policy) allows you to control which web platform features can be used in the browser.'
    }

    @staticmethod
    def check_missing_security_headers(scan_url):
        headers = scan_url.headers
        headers_dict = {k.strip(): v.strip() for k, v in (header.split(':', 1) for header in headers.split('\n') if ':' in header)}
        missing_headers = [header for header in SecurityHeaderService.SECURITY_HEADERS if header not in headers_dict]

        vulnerabilities = []
        for missing_header in missing_headers:
            vulnerability = Vulnerability(
                scan_url=scan_url,
                type='Missing Security Header',
                description=SecurityHeaderService.SECURITY_HEADERS[missing_header],
                severity='high',
                proof_of_concept=f'Missing security header: {missing_header}'
            )
            vulnerability.save()
            vulnerabilities.append(vulnerability)

        return vulnerabilities

    @staticmethod
    def scan_for_vulnerabilities(scan):
        scan_urls = Scan_Url.objects.filter(scan=scan)
        all_vulnerabilities = []
        for scan_url in scan_urls:
            vulnerabilities = SecurityHeaderService.check_missing_security_headers(scan_url)
            all_vulnerabilities.extend(vulnerabilities)

        return all_vulnerabilities
