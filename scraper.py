import re
from urllib.parse import urlparse, urljoin, urldefrag, urlsplit
from bs4 import BeautifulSoup 
from robotexclusionrulesparser import RobotExclusionRulesParser
from collections import deque
from datetime import datetime, timedelta
import urllib.error
from utils import get_urlhash, normalize, get_logger
import threading
import json
import faulthandler
import string
faulthandler.enable()

MAX_HASHES_STORED = 100
visited_content_fingerprints = deque(maxlen=MAX_HASHES_STORED)
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
    tokens = re.findall(r'\b[a-z0-9]+(?=\b|_)|(?<=_)[a-z0-9]+', content) #filter out the numbers later myself
    #tokens = re.findall(r'\b[a-z]+(?=\b|_)|(?<=_)[a-z]+', content) #I GOT NUMBERS OTHERWISE I WANT WORDS ONLY
    return [token for token in tokens if token not in STOP_WORDS]

def jaccard_similarity(set_a, set_b): # As seen in lecture, you take the intersection / union of the sets
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return intersection / union if union != 0 else 0

def make_fingerprint(tokens, n=3, modulus_value=4):
    # making my fingerprint
    ngrams = [tokens[i:i+n] for i in range(len(tokens) - n + 1)]
    hashed_ngrams = [hash(tuple(ng)) for ng in ngrams]
    fingerprint = set([h for h in hashed_ngrams if h % modulus_value == 0])
    return fingerprint

def check_and_update_recent_fingerprint(content_hash):
    for stored_fingerprint in visited_content_fingerprints:
        similarity = jaccard_similarity(content_hash, stored_fingerprint)
        if similarity >= 0.9:  # threshold
            return True
    visited_content_fingerprints.append(content_hash)
    return False

def scraper(url, resp, trap_detector):
    logger.debug(f"Entering scraper with URL: {url}")
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
            if not is_valid(url):
                logger.warning(f"Redirected URL: {url} is not valid. Skipping.")
                return []
                
    trap_detector.count_pattern(url)
    if trap_detector.is_trap(url): # I need to detect traps after VISITING the page
        logger.warning(f"Potential trap detected at URL: {url}. Skipping.")
        return []

    # AVOIDS BeautifulSoup processing on big files apparently slow
    if len(resp.raw_response.content) > MAX_CONTENT_SIZE: 
        logger.warning(f"Content size for URL: {url} exceeds the threshold. Skipping.")
        return []
    
    page_content = BeautifulSoup(resp.raw_response.content, 'lxml').get_text()
    tokens = tokenize_text(page_content)
    content_hash = make_fingerprint(tokens) #it's a set of hashes
    if check_and_update_recent_fingerprint(content_hash):
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
        logger.debug(f"Processing content for URL: {url}")
        # Successfully processed the URL
        logger.info(f"Successfully scraped content from URL: {url}")
        links = extract_next_links(url, resp)
        # Add the URL to the visited urls
        with data_lock:
            if url not in visited_urls:
                visited_urls.add(url)
                logger.debug(f"URL added to visited_urls: {url}. Total visited: {len(visited_urls)}")

        # Check and keep track of how many subdomains there are in the ics.uci.edu domain
        parsed = urlparse(url)  # Use the current URL
        if "ics.uci.edu" in parsed.netloc:
            subdomain = parsed.netloc.split(".ics.uci.edu")[0] #changed the logic cuz it wasn't quite right
            with data_lock:
                visited_subdomains[subdomain] = visited_subdomains.get(subdomain, 0) + 1

        #don't put links you already visited before or traps, kinda clunky especially since the frontier filters out as well
        with data_lock:
            return [link for link in links
            if is_valid(link, resp, visited_urls) and link not in visited_urls and link not in error_urls
            and not trap_detector.is_trap(link)]
    else:
        logger.debug(f"Exiting scraper for URL: {url} with non-200 status")
        return []
        
def is_ascii_url(url):
    try:
        url.encode('ascii')
    except UnicodeEncodeError:
        logger.warning(f"URL contains non-ASCII characters: {url}")
        return False
    return True
    
def extract_next_links(url, resp): #added ability to parse json files although not sure we should
    logger.debug(f"Extracting next links from URL: {url}")
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
            
    logger.debug(f"Extracted {len(links)} links from URL: {url}")
    return links


def is_valid(url, resp, visited_sets):
    logger.debug(f"Checking if URL is valid: {url}")
    try:
        parsed = urlparse(url)

        #attempt comain without subdomain
        try:
            test = urlsplit(url).netloc.split(".")[-4:]
        except:
            return False
        domain = ".".join(test[-3:])

        # split path
        sPath = url.split("/")
        sPathLast = sPath[-1]

        if url in visited_urls:
            return False
        
        if 'wics' in parsed.netloc and 'events' in sPath:
            return False
        if 'page' in sPath:
            return False
        # jpg file catch 
        if "wp-" in parsed.path:
            return False
        if "?" in url:
            return False

        if parsed.scheme not in set(["http", "https"]):
            return False
        
        if not re.match(
            r".*(\.ics\.uci\.edu|\.cs\.uci\.edu|\.informatics\.uci\.edu|\.stat\.uci\.edu)/.*",
            url):
            return False
        
        # Check for WordPress API endpoints like https://ngs.ics.uci.edu/wp-json/wp/v2/posts?tags=97
        # or https://ngs.ics.uci.edu/wp-json/oembed/1.0/embed?url=https%3a%2f%2fngs.ics.uci.edu%2fextreme-stories-12%2f&format=xml
        if 'wp-json' in url:
            return False
        # because of wiki.ics.uci.edu/doku I have a bunch of queries I'm guessing that's not interesting to scrape
        if '?do=' in url:
            return False
        # Check to filter out URLs ending with (4 numbers)/revisions or /revisions/(4 numbers)
        if re.search(r'/\d{4}/revisions$', url) or re.search(r'/revisions/\d{4}$', url):
            return False
        #removes repeated directories in a link, not sure if it's really needed for UCI sites
        if re.search(r'^.*?(/.+?/).*?\1.*$|^.*?/(.+?/)\2.*$', url):
            return False
        #filters out .html files that are on the ics.uci.edu domain
        if re.search(r'.*ics\.uci\.edu.*\.(html|xhtml)$', url):
            return False
        #filter out xmlrpc.php and $url and ~eppstein/pix and /page/ and php?format
        if re.search(r'xmlrpc\.php|\$url|~eppstein/pix|/page/|php\?format', url):
            return False
        # Check if URL ends with .txt and is not robots.txt
        if parsed.path.endswith('.txt') and not parsed.path.endswith('robots.txt'):
            return False
        #remove mailto links
        if re.match(r'^mailto:', url):
            return False
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico|bam" #wtf is a bam file https://cbcl.ics.uci.edu/public_data/tree-hmm-sample-data/
            + r"|png|tiff?|mid|mp2|mp3|mp4|lisp|" #removing lisp files
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|mpg"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|odp|svg" #similarly wtf is an odp
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|bat"
            + r"|epub|dll|cnf|tgz|sha1|col"
            + r"|thmx|mso|arff|rtf|jar|csv|sql|test|train|theory"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz|z|tar)$", parsed.path.lower())
            
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
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
    



def get_unique_visited_count():
    return len(visited_urls)
    
def get_sorted_subdomains():
    # Sort the dictionary by its keys (subdomains) in alphabetical order
    sorted_subdomains = sorted(visited_subdomains.items(), key=lambda x: x[0])
    return sorted_subdomains
    
def get_top_50_words():
    # Filter out items where the word is just a number
    filtered_words = {word: freq for word, freq in word_frequencies.items() if not word.isnumeric()}
    
    # Sort the remaining words by their frequency in descending order
    sorted_words = sorted(filtered_words.items(), key=lambda x: x[1], reverse=True)
    
    return sorted_words[:50]
