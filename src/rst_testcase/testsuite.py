from pathlib import Path
import logging
from typing import List

from junit_xml import TestSuite, to_xml_report_file

from rst_testcase.io_event import IOEvent


class Testsuite:
    def __init__(self, test_name: str):
        self.test_name = test_name
        self.event_list: List[IOEvent] = []

    def attach_event(self, event: IOEvent):
        logging.debug("Attach event %s", event.event_name)
        self.event_list.append(event)

    def attach_multiple_events(self, event_list: List[IOEvent]):
        for event in event_list:
            self.attach_event(event)

    def write_testresult_file(self, path_to_file: Path):
        path_to_file.parent.mkdir(parents=True, exist_ok=True)
        test_cases = [x.testcase for x in self.event_list]
        # test_cases = [TestCase('Test1', 'some.class.name', 123.345, 'I am stdout!', 'I am stderr!')]
        ts = TestSuite(self.test_name, test_cases)
        with path_to_file.open("w", encoding="utf-8") as file:
            to_xml_report_file(file, [ts])
        # path_to_file.write_text(TestSuite.to_xml_report_string())

    def all_failed(self) -> bool:
        return all([x.failed for x in self])

    def all_passed(self) -> bool:
        return all([x.passed for x in self])

    def __iter__(self):
        return iter(self.event_list)
