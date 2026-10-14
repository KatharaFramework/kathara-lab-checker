from Kathara.model.Lab import Lab

from ..foundation.checks.AbstractCheck import AbstractCheck
from ..foundation.model.CheckResult import CheckResult
from ..model.FailedCheck import FailedCheck
from ..model.SuccessfulCheck import SuccessfulCheck
from ..utils import key_exists


class StartupExistenceCheck(AbstractCheck):

    def __init__(self, lab: Lab, description: str = None):
        super().__init__(lab, description=description, priority=20)

    def check(self, device_name: str) -> CheckResult:
        if device_name.startswith("!"):
            device_name = device_name[1:]
            self.description = f"Check absence of `{device_name}.startup` file"
            invert = True
        else:
            self.description = f"Check existence of `{device_name}.startup` file"
            invert = False

        if self.lab.fs.exists(device_name + ".startup") ^ invert:
            return SuccessfulCheck(self.description)
        else:
            reason = f"{device_name}.startup file {'found' if invert else 'not found'}"
            return FailedCheck(self.description, reason)

    def run(self, machines_to_check: list[str]) -> list[CheckResult]:
        results = []
        for device_name in machines_to_check:
            check_result = self.check(device_name)
            results.append(check_result)
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "requiring_startup"], configuration):
            self.logger.info("Checking that all required startup files exist...")
            results.extend(self.run(configuration["test"]["requiring_startup"]))
        return results
