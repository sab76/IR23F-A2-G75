import json
import threading
from scraper import visited_urls, visited_subdomains, word_frequencies, longest_page, get_longest_page, get_top_50_words, get_unique_visited_count#, data_lock

SAVE_INTERVAL = 300  # 5 minutes

def save_data():
    #with data_lock:
    data = {
        "word_frequencies": word_frequencies,
        "longest_page": get_longest_page(),
        "top_50_words": get_top_50_words(),
        "unique_visited_count": get_unique_visited_count()
    }

    with open("saved_data.json", "w") as f:
        json.dump(data, f)

def load_data():
    #with data_lock:
    try:
        with open("saved_data.json", "r") as f:
            data = json.load(f)
        
        visited_urls.update(data["visited_urls"])
        visited_subdomains.update(data["visited_subdomains"])
        word_frequencies.update(data["word_frequencies"])
        longest_page.update(data["longest_page"])

    except FileNotFoundError:
        print("No saved data found. Starting from scratch.")