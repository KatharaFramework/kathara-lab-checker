from checks import CheckResult as CheckResultPackage


class TestCollector:
    def __init__(self):
        self.tests = {}

    def add_check_result(self, test_name, check_result: 'CheckResultPackage.CheckResult') -> None:
        if test_name not in self.tests:
            self.tests[test_name] = []
        self.tests[test_name].append(check_result)

    def get_failed(self, test_name: str):
        return list(filter(lambda x: not x.passed, self.tests[test_name]))

    def get_passed(self, test_name: str):
        return list(filter(lambda x: x.passed, self.tests[test_name]))