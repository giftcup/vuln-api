import requests
from ..models import Scan, Scan_Url
from django.utils import timezone
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

options = Options()
options.add_argument('--headless')
options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')


class ScanService:
    @staticmethod
    def fetch_and_parse_links(target_url):
        try:
            response = requests.get(target_url)
            response.raise_for_status()  # Raises an HTTPError for bad responses
            soup = BeautifulSoup(response.text, 'html.parser')
            links = [link.get('href') for link in soup.find_all('a') if link.get('href')]
            print(f"links: {links}")
            # Filter and normalize the links
            # links = [link for link in links if link.startswith('http')]  # Simple filter to ignore mailto: and javascript: links
            # print(f"setlinks: {links}")
            return set(links)  # Use set to avoid duplicates
        except requests.RequestException as e:
            print(f"Failed to fetch URL {target_url}: {str(e)}")
            return set()

    @staticmethod
    def create_scan_with_urls(target_url):
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

        # Start the Scan instance
        scan = Scan.objects.create(
            scanner_ip='127.0.0.1',  # Hypothetical value
            target_url=target_url
        )
        
        related_links = ScanService.fetch_and_parse_links(target_url)
        
        # Create ScanURL objects for each related link
        scan_urls = []
        for link in related_links:
            link = link if link.startswith('http') else target_url + link
            response = requests.get(link)
            driver.get(link)
            # Fetch all related links from the target URL
            scan_url = Scan_Url.objects.create(
                scan=scan,
                scan_url=link,
                status_code=response.status_code,
                headers=response.headers,
                html_content=driver.page_source
            )
            scan_urls.append(scan_url)
        
        driver.close()
        
        return scan, scan_urls 