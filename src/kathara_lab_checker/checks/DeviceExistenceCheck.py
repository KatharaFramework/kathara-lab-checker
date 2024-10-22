from Kathara.exceptions import MachineNotFoundError
from Kathara.model.Lab import Lab

from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


class DeviceExistenceCheck(AbstractCheck):

    def check(self, device_name: str, lab: Lab) -> CheckResult:
        self.description = f'Check existence of `{device_name}`'
        try:
            lab.get_machine(device_name)
        except MachineNotFoundError as e:
            return CheckResult(self.description, False, str(e))

        return CheckResult(self.description, True, "OK")

    def run(self, template_machines: list[str], lab: Lab) -> list[CheckResult]:
        results = []
        for device_name in template_machines:
            check_result = self.check(device_name, lab)
            results.append(check_result)
        return results
