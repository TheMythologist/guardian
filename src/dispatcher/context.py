from multiprocessing import Process
from multiprocessing.connection import Connection

from network.sessions import AbstractPacketFilter


class OverrideFilterNotAllowed(Exception):
    """Do not allow overriding of filters via priority."""


class Context:
    _current_priority = 0
    filters: dict[int, AbstractPacketFilter] = {}

    def __init__(self, queue: Connection):
        self.queue = queue
        self.process = Process(target=self.run)
        self.process.daemon = True

    @property
    def priority(self) -> int:
        priority = self._current_priority
        self._current_priority += 1
        return priority

    def start(self) -> None:
        self.process.run()

    def stop(self) -> None:
        self.process.terminate()

    def run(self) -> None:
        while True:
            self.queue.recv()
            self.kill_old_filters()

    def add_filter(
        self, filter: AbstractPacketFilter, start_immediately: bool = False
    ) -> None:
        if filter.priority in self.filters:
            raise OverrideFilterNotAllowed(f"Duplicate priority {filter.priority}")
        self.filters[filter.priority] = filter
        if start_immediately:
            self.start_latest_filter()

    def kill_old_filters(self) -> None:
        if len(self.filters) > 1:
            # Kill other filters
            for priority_identifier in list(self.filters)[:-1]:
                self.filters.pop(priority_identifier).stop()

    def start_latest_filter(self) -> None:
        self.filters[list(self.filters)[-1]].start()
        self.kill_old_filters
