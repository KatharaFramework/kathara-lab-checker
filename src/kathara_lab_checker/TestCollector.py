from .model.CheckResult import CheckResult


class TestCollector:
    def __init__(self):
        self.tests = {}

    def add_check_result(self, lab_name: str, check_result: CheckResult) -> None:
        if lab_name not in self.tests:
            self.tests[lab_name] = []
        self.tests[lab_name].append(check_result)

    def add_check_results(self, lab_name: str, check_results: list[CheckResult]) -> None:
        for result in check_results:
            self.add_check_result(lab_name, result)

    def get_failed(self, test_name: str):
        return list(filter(lambda x: not x.passed, self.tests[test_name]))

    def get_passed(self, test_name: str):
        return list(filter(lambda x: x.passed, self.tests[test_name]))
