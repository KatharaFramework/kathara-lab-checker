from Kathara.exceptions import MachineNotFoundError
from Kathara.model.Lab import Lab

from ..foundation.checks.AbstractCheck import AbstractCheck
from ..foundation.model.CheckResult import CheckResult
from ..model.FailedCheck import FailedCheck
from ..model.SuccessfulCheck import SuccessfulCheck


class DeviceExistenceCheck(AbstractCheck):

    def __init__(self, lab: Lab, description: str = None):
        super().__init__(lab, description=description, priority=0)


    def check(self, device_name: str) -> CheckResult:
        self.description = f"Check existence of `{device_name}`"
        try:
            self.lab.get_machine(device_name)
        except MachineNotFoundError as e:
            return FailedCheck(self.description, str(e))

        return SuccessfulCheck(self.description)

    def run(self, template_machines: list[str]) -> list[CheckResult]:
        results = []
        for device_name in template_machines:
            check_result = self.check(device_name)
            results.append(check_result)
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        self.logger.info("Checking devices existence...")
        return self.run(configuration['template_lab'].machines.keys())
