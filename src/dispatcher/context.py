import logging
from multiprocessing import Process
from multiprocessing.connection import PipeConnection

from network.sessions import AbstractPacketFilter

debug_logger = logging.getLogger("debugger")


class OverrideFilterNotAllowed(Exception):
    """Do not allow overriding of filters via priority."""


class Context:
    _current_priority = 0
    filters: dict[int, AbstractPacketFilter] = {}

    def __init__(self, connection: PipeConnection):
        self.queue = connection
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
            debug_logger.debug("Received signal")
            self.kill_old_filters()

    def add_filter(
        self, filter: AbstractPacketFilter, start_immediately: bool = False
    ) -> None:
        debug_logger.debug(f"Adding {filter}")
        if filter.priority in self.filters:
            raise OverrideFilterNotAllowed(f"Duplicate priority {filter.priority}")
        self.filters[filter.priority] = filter
        if start_immediately:
            self.start_latest_filter()

    def kill_old_filters(self) -> None:
        if len(self.filters) > 1:
            debug_logger.debug(f"Killing {len(self.filters) - 1} filters")
            # Kill other filters
            for priority_identifier in list(self.filters)[:-1]:
                debug_logger.debug(f"Killing {self.filters[priority_identifier]}")
                self.filters.pop(priority_identifier).stop()

    def start_latest_filter(self) -> None:
        self.filters[list(self.filters)[-1]].start()
        self.kill_old_filters()
