from threading import Thread

from inspect import getsource
from utils.download import download
from utils import get_logger
import scraper
import time

class TrapDetector: #moved to worker so I can detect before sending requests to get rid of a bunch of them at a time without dling
    def __init__(self):
        self.pattern_counts = {}
        self.logged_traps = set()  # keep track of logged trap URLs
        self.TRAP_THRESHOLD = 10  # Currently set to 10, but can be adjusted up/down

    def simplify_url(self, url):
        # Remove numbers, parameters, and trailing slashes
        simple_url = re.sub(r'\d+', '', url)  # remove numbers
        simple_url = re.sub(r'\?.*$', '', simple_url)  # remove query params
        simple_url = re.sub(r'[/]+$', '', simple_url)  # remove trailing slash
        return simple_url

    def count_pattern(self, url):
        """Increments the count for a URL's simplified pattern."""
        simple_url = self.simplify_url(url)
        self.pattern_counts[simple_url] = self.pattern_counts.get(simple_url, 0) + 1

    def is_trap(self, url):
        """Checks if a URL is a trap without modifying the count."""
        simple_url = self.simplify_url(url)
        
        if self.pattern_counts.get(simple_url, 0) > self.TRAP_THRESHOLD:
            # Only log once for each URL flagged as a trap
            if simple_url not in self.logged_traps:
                self.logged_traps.add(simple_url)
            return True
        return False

class Worker(Thread):
    def __init__(self, worker_id, config, frontier):
        self.logger = get_logger(f"Worker-{worker_id}", "Worker")
        self.config = config
        self.frontier = frontier
        self.trap_detector = TrapDetector()
        # basic check for requests in scraper
        assert {getsource(scraper).find(req) for req in {"from requests import", "import requests"}} == {-1}, "Do not use requests in scraper.py"
        assert {getsource(scraper).find(req) for req in {"from urllib.request import", "import urllib.request"}} == {-1}, "Do not use urllib.request in scraper.py"
        super().__init__(daemon=True)
        
    def run(self):
        while True:
            tbd_url = self.frontier.get_tbd_url()
            if not tbd_url:
                self.logger.info("Frontier is empty. Stopping Crawler.")
                break
                
            # Check for traps before downloading the URL
            if self.trap_detector.is_trap(tbd_url):
                self.logger.warning(f"Potential trap detected at URL: {tbd_url}. Skipping.")
                continue
            
            resp = download(tbd_url, self.config, self.logger)
            self.logger.info(
                f"Downloaded {tbd_url}, status <{resp.status}>, "
                f"using cache {self.config.cache_server}.")
            scraped_urls = scraper.scraper(tbd_url, resp, self.trap_detector)
            for scraped_url in scraped_urls:
                self.frontier.add_url(scraped_url)
            self.frontier.mark_url_complete(tbd_url)
            time.sleep(self.config.time_delay)
