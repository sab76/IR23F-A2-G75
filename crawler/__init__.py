from utils import get_logger
from crawler.frontier import Frontier
from crawler.worker import Worker
from data_utils import save_data, load_data
import threading


class Crawler(object):
    def __init__(self, config, restart, frontier_factory=Frontier, worker_factory=Worker):
        self.config = config
        self.logger = get_logger("CRAWLER")
        self.frontier = frontier_factory(config, restart)
        self.workers = list()
        self.worker_factory = worker_factory
        self.is_crawling = True  # Trying to detect when I stop crawling so that I can stop saving info
        
        # Load saved data if it's a restart
        if restart:
            load_data()

        # Schedule saving
        self.schedule_data_saving()

    def start_async(self):
        self.workers = [
            self.worker_factory(worker_id, self.config, self.frontier)
            for worker_id in range(self.config.threads_count)]
        for worker in self.workers:
            worker.start()

    def schedule_data_saving(self):
        SAVE_INTERVAL = 60  # 1 minute
        threading.Timer(SAVE_INTERVAL, self.periodic_save).start()

    def periodic_save(self):
        if self.is_crawling:  # Only save and reschedule if still crawling
            save_data()
            self.schedule_data_saving()

    def start(self):
        self.start_async()
        self.join()
        self.is_crawling = False  # Set the flag to False once crawling is done

    def join(self):
        for worker in self.workers:
            worker.join()
