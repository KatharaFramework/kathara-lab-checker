from Kathara.exceptions import MachineNotFoundError
from Kathara.model.Lab import Lab

from ..foundation.checks.AbstractCheck import AbstractCheck
from ..foundation.model.CheckResult import CheckResult
from ..model.FailedCheck import FailedCheck
from ..model.SuccessfulCheck import SuccessfulCheck
from ..utils import key_exists


class IPv6EnabledCheck(AbstractCheck):

    def __init__(self, lab: Lab, description: str = None):
        super().__init__(lab, description=description, priority=30)

    def check(self, device_name: str) -> CheckResult:
        self.description = f"Checking the IPv6 is enabled on `{device_name}`"

        try:
            device = self.lab.get_machine(device_name)
            if "ipv6" in device.meta and device.is_ipv6_enabled():
                return SuccessfulCheck(self.description)
            else:
                return FailedCheck(self.description, f"IPv6 not enabled on `{device_name}`")
        except MachineNotFoundError as e:
            return FailedCheck(self.description, str(e))

    def run(self, ipv6_devices: list[str]) -> list[CheckResult]:
        results = []
        for device_name in ipv6_devices:
            check_result = self.check(device_name)
            results.append(check_result)
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "ipv6_enabled"], configuration):
            self.logger.info(f"Checking that IPv6 is enabled on devices: {configuration['test']['ipv6_enabled']}")
            results.extend(self.run(configuration["test"]["ipv6_enabled"]))
        return results
