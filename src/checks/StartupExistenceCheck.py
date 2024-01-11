from Kathara.model.Lab import Lab

from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


class StartupExistenceCheck(AbstractCheck):

    def run(self, device_name: str, lab: Lab) -> CheckResult:
        if lab.fs.exists(device_name + ".startup"):
            return CheckResult(self.description, True, "OK")
        else:
            return CheckResult(self.description, False, f"{device_name}.startup file not found")