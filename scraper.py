import re
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup
from robotexclusionrulesparser import RobotExclusionRulesParser
from collections import deque
from datetime import datetime, timedelta
from utils import get_urlhash, normalize, get_logger
import json

MAX_HASHES_STORED = 100
visited_content_hashes = deque(maxlen=MAX_HASHES_STORED)
robot_parsers = {} #extra credit implement this yourself
visited_subdomains = {} #the ics.uci.edu subdomains
visited_urls = set() #valid pages we visited
error_urls = set() #pages we visited that gave us an error
MAX_CONTENT_SIZE = 5 * 1024 * 1024  # 5 MB file limit
word_frequencies = {}
longest_page = {"url": None, "word_count": 0}
logger = get_logger("SCRAPER")

data_lock = threading.Lock() #multithreading for saving, could be more multithreaded though

try:
    with open("common_words.txt", "r") as file:
        STOP_WORDS = set(file.read().splitlines())
except FileNotFoundError:
    logger.error("The 'common_words.txt' file was not found.")
    STOP_WORDS = set()  # default to an empty set
except Exception as e:
    logger.error(f"Error reading 'common_words.txt': {e}")
    STOP_WORDS = set()  # default to an empty set
    
def get_robots_parser(domain): 
    current_time = datetime.now()
    parser = None
    fetch_required = False
    
    with data_lock:
        if domain not in robot_parsers or (current_time - robot_parsers[domain]['timestamp']) > timedelta(days=1):
            fetch_required = True
            
    if fetch_required:
        rerp = RobotExclusionRulesParser()
        rerp.user_agent = "Group75Scraper"
        try:
            rerp.fetch(f"{domain}/robots.txt")
            with data_lock:
                robot_parsers[domain] = {'parser': rerp, 'timestamp': current_time}
            logger.info(f"Fetched robots.txt for domain: {domain}")
        except Exception as e:
            logger.warning(f"Failed to fetch robots.txt from {domain}. Error: {e}. Assuming all paths are allowed.")
    else:
        with data_lock:
            parser = robot_parsers[domain]['parser']
    
    return parser


def tokenize_text(content):
    content = content.lower()
    tokens = re.findall(r'\b[a-z0-9]+(?=\b|_)|(?<=_)[a-z0-9]+', content)
    return [token for token in tokens if token not in STOP_WORDS]
    
def generate_ngrams(content, n=3):
    return [content[i:i+n] for i in range(len(content) - n + 1)]
    
def hash_mod_ngrams(ngrams, modulo=1000):
    return [hash(ngram) % modulo for ngram in ngrams]
    
def check_and_update_recent_hashes(content_hash):
    # If the content hash is in the set, it's similar to recent content
    if content_hash in visited_content_hashes:
        return True

    # If the deque is full, remove the oldest hash from both the deque and the set
    if len(visited_content_hashes) == MAX_HASHES_STORED:
        oldest_hash = visited_content_hashes.popleft()

    # Add the new hash to both the deque and the set
    visited_content_hashes.append(content_hash)

    return False

def hash_content(content, n=3, modulo=1000):
    ngrams = generate_ngrams(content, n)
    ngram_hashes = hash_mod_ngrams(ngrams, modulo)
    combined_hash = hash(tuple(ngram_hashes))
    return combined_hash
   
class TrapDetector:
    def __init__(self):
        self.pattern_counts = {}
        self.logged_traps = set()  # keep track of logged trap URLs
        self.TRAP_THRESHOLD = 10  # Currently 10 maybe should be higher

    def simplify_url(self, url):
        # Remove numbers, parameters, and trailing slashes
        simple_url = re.sub(r'\d+', '', url)  # remove numbers
        simple_url = re.sub(r'\?.*$', '', simple_url)  # remove query params
        simple_url = re.sub(r'[/]+$', '', simple_url)  # remove trailing slash
        return simple_url

    def is_trap(self, url):
        simple_url = self.simplify_url(url)
        self.pattern_counts[simple_url] = self.pattern_counts.get(simple_url, 0) + 1
        
        if self.pattern_counts[simple_url] > self.TRAP_THRESHOLD:
            # Only log once for each URL flagged as a trap
            if simple_url not in self.logged_traps:
                logger.warning(f"Potential trap detected at URL: {url}. Skipping.")
                self.logged_traps.add(simple_url)
            return True
        return False

trap_detector = TrapDetector()

def is_ascii_url(url):
    try:
        url.encode('ascii')
    except UnicodeEncodeError:
        logger.warning(f"URL contains non-ASCII characters: {url}")
        return False
    return True

def scraper(url, resp):
    global visited_urls
    #checks if page sent actual data? Not sure this is good because it'll hide all the errors I think
    #if not hasattr(resp, 'raw_response') or not hasattr(resp.raw_response, 'content'):
    #    logger.warning(f"Either 'raw_response' or 'content' attribute missing for URL: {url}. Skipping.")
    #    return []

    #gonna check this instead not sure if best
    
    if not hasattr(resp, 'raw_response') or resp.raw_response is None:
        logger.warning(f"'raw_response' attribute missing or None for URL: {url}. Skipping.")
        return []
        
    if 400 <= resp.status < 700:
        logger.error(f"Error {resp.status} encountered at URL: {resp.url}")
        with data_lock:
            error_urls.add(resp.url)
            return []
        
    if not hasattr(resp.raw_response, 'content'):
        logger.warning(f"'content' attribute missing for URL: {url}. Skipping further processing but logging the issue.")
        return []


    # Check for redirects
    if resp.raw_response.history:
        if len(resp.raw_response.history) > 5:
            logger.warning(f"URL: {url} had more than 5 redirects. Skipping.")
            return []

        final_url = resp.raw_response.url
        if url != final_url:
            logger.info(f"URL: {url} was redirected to {final_url}")
            url = normalize(final_url)  # Update the url variable to the final URL after redirection
            # Check for traps using the final URL (not sure if will help tbh)
            if trap_detector.is_trap(url):
                logger.warning(f"Trap detected after redirecting to URL: {url}. Skipping.")
                return []
            if not is_valid(url):
                logger.warning(f"Redirected URL: {url} is not valid. Skipping.")
                return []
                
    
    # AVOIDS BeautifulSoup processing on big files apparently slow
    if len(resp.raw_response.content) > MAX_CONTENT_SIZE: 
        logger.warning(f"Content size for URL: {url} exceeds the threshold. Skipping.")
        return []
        
    page_content = BeautifulSoup(resp.raw_response.content, 'lxml').get_text()
    tokens = tokenize_text(page_content)
    content_hash = hash_content(page_content)
    if check_and_update_recent_hashes(content_hash):
        logger.warning(f"Similar content detected for URL: {url}. Skipping.")
        return []
        
    # currently keeping the length of the longest page in terms of tokens WITHOUT the stop words, maybe change
    with data_lock:
        if len(tokens) > longest_page["word_count"]:
            longest_page["url"] = url
            longest_page["word_count"] = len(tokens)

    with data_lock:
        for token in tokens:
            word_frequencies[token] = word_frequencies.get(token, 0) + 1
        
    if resp.status == 200:
        # Successfully processed the URL
        logger.info(f"Successfully scraped content from URL: {url}")
        links = extract_next_links(url, resp)
        # Add the URL to the visited urls
        with data_lock:
            if url not in visited_urls:
                visited_urls.add(url)

        # Check and keep track of how many subdomains there are in the ics.uci.edu domain
        parsed = urlparse(url)  # Use the current URL
        if "ics.uci.edu" in parsed.netloc:
            subdomain = parsed.netloc.split(".")[0]
            with data_lock:
                visited_subdomains[subdomain] = visited_subdomains.get(subdomain, 0) + 1 #use dictionary
        #don't put links you already visited before or traps, maybe kinda clunky CHECK IF FRONTIER FILTERS OUT VISITED
        with data_lock:
            return [link for link in links
            if is_valid(link) and link not in visited_urls and link not in error_urls
            and not trap_detector.is_trap(link)]
    else:
        return []

def extract_next_links(url, resp): #added ability to parse json files although not sure we should
    links = []

    content_type = resp.raw_response.headers.get('Content-Type', '')

    # If the content type is JSON
    if 'application/json' in content_type:
        try:
            json_data = json.loads(resp.raw_response.content)
            # Extract URLs from JSON. Here, we'll look for 'href' values.
            def extract_urls_from_json(json_obj):
                if isinstance(json_obj, dict):
                    for key, value in json_obj.items():
                        if key == 'href':
                            # Normalize and append URL
                            links.append(normalize(value))
                        else:
                            extract_urls_from_json(value)
                elif isinstance(json_obj, list):
                    for item in json_obj:
                        extract_urls_from_json(item)

            extract_urls_from_json(json_data)

        except json.JSONDecodeError:
            # If there's an error parsing the JSON content, log it and move on.
            logger.error(f"Error parsing JSON content from URL: {url}")

    # If the content type is HTML or something else
    else:
        soup = BeautifulSoup(resp.raw_response.content, 'lxml')
        for tag in soup.find_all(['a', 'link'], href=True):
            href_value = tag['href'].strip()
            
            # Check if the href value is already an absolute URL
            if re.match(r'^https?://', href_value):
                absolute_url = normalize(href_value)
            else:
                absolute_url = normalize(urljoin(url, href_value))
            
            # Check for ASCII URLs before adding to links
            if not is_ascii_url(absolute_url):
                continue

            links.append(absolute_url)

    return links


def is_valid(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        if not re.match(
            r".*(\.ics\.uci\.edu|\.cs\.uci\.edu|\.informatics\.uci\.edu|\.stat\.uci\.edu)/.*",
            url):
            return False
        # Check to filter out URLs ending with (4 numbers)/revisions or /revisions/(4 numbers)
        if re.search(r'/\d{4}/revisions$', url) or re.search(r'/revisions/\d{4}$', url):
            return False
        #removes repeated directories in a link, not sure if it's really needed for UCI sites
        if re.search(r'^.*?(/.+?/).*?\1.*$|^.*?/(.+?/)\2.*$', url):
            return False
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|mpg"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())
            
        parsed_domain = f"{parsed.scheme}://{parsed.netloc}"
        parser = get_robots_parser(parsed_domain)
        if not parser.is_allowed("Group75Scraper", url):
            logger.warning(f"URL {url} is disallowed by robots.txt.")
            return False
            
        return True

    except TypeError:
        print ("TypeError for ", parsed)
        logger.error(f"TypeError encountered for URL: {url}.")  # <-- Log the error
        raise

def get_unique_visited_count():
    with data_lock:
        return len(visited_urls)
    
def get_sorted_subdomains():
    with data_lock:
        # Sort the dictionary by its keys (subdomains) in alphabetical order
        sorted_subdomains = sorted(visited_subdomains.items(), key=lambda x: x[0])
        return sorted_subdomains
    
def get_longest_page():
    with data_lock:
        return longest_page

def get_top_50_words():
    with data_lock:
        sorted_words = sorted(word_frequencies.items(), key=lambda x: x[1], reverse=True)
        return sorted_words[:50]