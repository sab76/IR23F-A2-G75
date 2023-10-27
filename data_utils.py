import json
import threading

SAVE_INTERVAL = 300  # 5 minutes

visited_urls = set()
visited_subdomains = set()
word_frequencies = {}
longest_page = {"url": None, "word_count": 0}

def save_data():
    data = {
        "visited_urls": list(visited_urls),
        "visited_subdomains": list(visited_subdomains),
        "word_frequencies": word_frequencies,
        "longest_page": longest_page,
    }

    with open("saved_data.json", "w") as f:
        json.dump(data, f)

    # Schedule the next save
    threading.Timer(SAVE_INTERVAL, save_data).start()

def load_data():
    try:
        with open("saved_data.json", "r") as f:
            data = json.load(f)
        
        visited_urls.update(data["visited_urls"])
        visited_subdomains.update(data["visited_subdomains"])
        word_frequencies.update(data["word_frequencies"])
        longest_page.update(data["longest_page"])

    except FileNotFoundError:
        print("No saved data found. Starting from scratch.")
