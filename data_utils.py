import json
import threading
from scraper import visited_urls, visited_subdomains, word_frequencies, longest_page, get_top_50_words, get_unique_visited_count, data_lock
from utils import get_logger

logger = get_logger("SAVING")

def save_data():
    logger.info("ENTERING SAVE_DATA.")
    with data_lock:
        data = {
            "visited_urls": list(visited_urls),
            "error_urls": list(error_urls),
            "visited_subdomains": visited_subdomains,
            "word_frequencies": word_frequencies,
            "longest_page": longest_page,
            "top_50_words": get_top_50_words(),
            "unique_visited_count": get_unique_visited_count()
        }

        try:
            logger.info("STARTING.")
            with open("saved_data.json", "w") as f:
                json.dump(data, f)
            logger.info("Data successfully saved to 'saved_data.json'.")
        except Exception as e:
            logger.error(f"Error while saving data to 'saved_data.json': {e}")

def load_data():
    with data_lock:
        try:
            with open("saved_data.json", "r") as f:
                data = json.load(f)

            visited_urls.update(set(data["visited_urls"]))
            error_urls.update(set(data["error_urls"]))
            visited_subdomains.update(data["visited_subdomains"])
            word_frequencies.update(data["word_frequencies"])
            longest_page.update(data["longest_page"])

            logger.info("Data successfully loaded from 'saved_data.json'.")
        except FileNotFoundError:
            logger.warning("No saved data found. Starting from scratch.")
        except Exception as e:
            logger.error(f"Error while loading data from 'saved_data.json': {e}")