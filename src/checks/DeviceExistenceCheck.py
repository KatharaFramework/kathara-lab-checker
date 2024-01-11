from Kathara.exceptions import MachineNotFoundError
from Kathara.model.Lab import Lab

from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


class DeviceExistenceCheck(AbstractCheck):
    def run(self, device_name: str, lab: Lab) -> CheckResult:
        try:
            lab.get_machine(device_name)
        except MachineNotFoundError as e:
            return CheckResult(self.description, False, str(e))

        return CheckResult(self.description, True, "OK")
