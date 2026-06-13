from .FailedCheck import FailedCheck


class TimedoutCheck(FailedCheck):
    def __init__(self, description: str, timeout: float):
        super().__init__(description, f"Timed out after {timeout}s")
