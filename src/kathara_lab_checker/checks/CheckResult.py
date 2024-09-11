from kathara_lab_checker.utils import green, red


class CheckResult:

    def __init__(self, description: str, passed: bool, reason: str) -> None:
        self.description: str = description
        self.passed: bool = passed
        self.reason: str = reason

    def __str__(self) -> str:
        return f"{self.description}: {green(self.reason) if self.passed else red(self.reason)}"
