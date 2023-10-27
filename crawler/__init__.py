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
        
        # Load saved data if it's a restart
        if restart:
            load_data()

    def start_async(self):
        self.schedule_data_saving()
   
        self.workers = [
            self.worker_factory(worker_id, self.config, self.frontier)
            for worker_id in range(self.config.threads_count)]
        for worker in self.workers:
            worker.start()

    def schedule_data_saving(self):
        SAVE_INTERVAL = 300  # 5 minutes
        threading.Timer(SAVE_INTERVAL, self.periodic_save).start()

    def periodic_save(self):
        save_data()
        self.schedule_data_saving()  # schedule the next save

    def start(self):
        self.start_async()
        self.join()

    def join(self):
        for worker in self.workers:
            worker.join()
