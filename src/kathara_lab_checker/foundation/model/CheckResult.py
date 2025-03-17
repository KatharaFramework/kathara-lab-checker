import logging
from abc import ABC

from ...utils import green, red


class CheckResult(ABC):

    def __init__(self, description: str, passed: bool, reason: str) -> None:
        self.description: str = description
        self.passed: bool = passed
        self.reason: str = reason
        logging.getLogger("kathara-lab-checker").info(self)

    def __str__(self) -> str:
        return f"{self.description}: {green(self.reason) if self.passed else red(self.reason)}"
