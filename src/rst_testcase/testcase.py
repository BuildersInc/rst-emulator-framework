from junit_xml import TestCase


class Testcase:
    def __init__(self, name: str):
        self.test_name = name
        self.testcase = TestCase(self.test_name)

    def message_success(self, reason: str | None = None) -> str:
        return f"Test passed {reason if reason is not None else ""}"

    def message_fail(self, reason: str | None = None) -> str:
        return f"Test Failed {reason if reason is not None else ""}"

    def message_skip(self, reason: str | None = None) -> str:
        return f"Test skipped {reason if reason is not None else ""}"

    def hint(self, hint_level) -> str:
        if hint_level == 1:
            return "Hint 1"
        if hint_level == 2:
            return "Hint 2"
        if hint_level == 3:
            return "Hint 3"
        return "Hint 4"
