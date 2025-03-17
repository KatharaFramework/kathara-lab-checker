from ..foundation.model.CheckResult import CheckResult


class FailedCheck(CheckResult):
    def __init__(self, description: str, reason: str):
        super().__init__(description, False, reason)
