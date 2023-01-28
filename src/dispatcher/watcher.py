import multiprocessing
from multiprocessing.managers import DictProxy

from network.sessions import AbstractPacketFilter


class Watcher:
    def __init__(
        self,
        queue: multiprocessing.Queue,
        filters: DictProxy[int, AbstractPacketFilter],
    ):
        self.queue = queue
        self.process = multiprocessing.Process(target=self.run)
        self.process.daemon = True
        self.filters = filters
        self.current_priority = 0

    def get_priority(self) -> int:
        priority = self.current_priority
        self.current_priority += 1
        return priority

    def run(self) -> None:
        while True:
            item: int = self.queue.get()
            self.filters.pop(item - 1).stop()
            assert len(self.filters) == 1

    def start(self) -> None:
        self.process.start()

    def stop(self) -> None:
        self.process.terminate()
