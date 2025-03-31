from ..foundation.model.CheckResult import CheckResult


class SuccessfulCheck(CheckResult):
    def __init__(self, description: str, reason: str = "OK"):
        super().__init__(description, True, reason)
