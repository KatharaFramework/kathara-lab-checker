from Kathara.exceptions import MachineNotFoundError
from Kathara.model.Lab import Lab

from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


class IPv6EnabledCheck(AbstractCheck):
    def check(self, device_name: str, lab: Lab) -> CheckResult:
        self.description = f"Checking the IPv6 is enabled on `{device_name}`"

        try:
            device = lab.get_machine(device_name)
            if "ipv6" in device.meta and device.is_ipv6_enabled():
                return CheckResult(self.description, True, "OK")
            else:
                return CheckResult(self.description, False, f"IPv6 not enabled on `{device_name}`")
        except MachineNotFoundError as e:
            return CheckResult(self.description, False, str(e))

    def run(self, ipv6_devices: list[str], lab: Lab) -> list[CheckResult]:
        results = []
        for device_name in ipv6_devices:
            check_result = self.check(device_name, lab)
            self.logger.info(check_result)
            results.append(check_result)
        return results
