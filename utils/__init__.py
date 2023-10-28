import os
import logging
from hashlib import sha256
from urllib.parse import urlparse, urldefrag
import re

def get_logger(name, filename=None):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO) #logger.setLevel(logging.DEBUG) 
    if not os.path.exists("Logs"):
        os.makedirs("Logs")
    fh = logging.FileHandler(f"Logs/{filename if filename else name}.log")
    fh.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO) #ch.setLevel(logging.DEBUG) 
    formatter = logging.Formatter(
       "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    # add the handlers to the logger
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


def get_urlhash(url):
    parsed = urlparse(url)
    # everything other than scheme.
    return sha256(
        f"{parsed.netloc}/{parsed.path}/{parsed.params}/"
        f"{parsed.query}/{parsed.fragment}".encode("utf-8")).hexdigest()
    
def normalize(url):
    url = urldefrag(url)[0].lower()
    
    # Handle links that are like "www.ics.uci.edu" by prefixing them with a scheme.
    if url.startswith("www."):
        url = "https://" + url
    
    # Remove trailing slash after a filename (like .php/)
    if re.search(r'\.\w+/$', url):
        url = url[:-1]

    return url
