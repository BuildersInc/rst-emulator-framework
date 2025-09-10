
from typing import List

from rst_testcase.io_event import IOEvent


class Testcase:
    def __init__(self):
        self.event_list: List[IOEvent] = []

    def attach_event(self, event: IOEvent):
        self.event_list.append(event)

    def attach_multiple_events(self, event_list: List[IOEvent]):
        for event in event_list:
            self.attach_event(event)

    def all_failed(self) -> bool:
        return all([x.failed for x in self])

    def all_passed(self) -> bool:
        return all([x.passed for x in self])

    def __iter__(self):
        return iter(self.event_list)
