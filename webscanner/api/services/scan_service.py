import requests
from ..models import Scan, Scan_Url
from django.utils import timezone
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
    def create_scan_with_url(user, target_url):
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        # Create a new Scan
        scan = Scan.objects.create(
            user=user,
            start_time=timezone.now(),
            end_time=None,
            scanner_ip='127.0.0.1',
            target_url=target_url
        )
        
        # Fetch the target URL
        response = requests.get(target_url)
        driver.get(target_url)
        
        # Create a ScanURL entry
        scan_url = Scan_Url.objects.create(
            scan=scan,
            scan_url=target_url,
            status_code=response.status_code,
            headers=response.headers,
            html_content=driver.page_source
        )
        
        driver.close()
        
        return scan, scan_url