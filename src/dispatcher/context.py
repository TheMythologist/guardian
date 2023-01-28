from multiprocessing import Process

from network.sessions import AbstractPacketFilter


class Context:
    filters: dict[int, Process] = {}

    def set_filter(
        self, filter: AbstractPacketFilter, start_immediately: bool = True
    ) -> None:
        self.filters[filter.priority] = filter.process
        if start_immediately:
            self.reload()

    def reload(self) -> None:
        if len(self.filters) > 1:
            # Start latest filter
            self.filters[list(self.filters)[-1]].start()

            # Kill other filters
            for priority_identifier in list(self.filters)[:-1]:
                self.filters.pop(priority_identifier).terminate()
