from Kathara.exceptions import MachineNotFoundError
from Kathara.model.Lab import Lab

from ..foundation.checks.AbstractCheck import AbstractCheck
from ..model.FailedCheck import FailedCheck
from ..model.SuccessfulCheck import SuccessfulCheck
from ..utils import key_exists


class IPv6EnabledCheck(AbstractCheck):

    def __init__(self, lab: Lab, configuration: dict, description: str = None):
        super().__init__(lab, configuration, description=description, priority=30)

    def check(self, device_name: str):
        self.description = f"Checking the IPv6 is enabled on `{device_name}`"

        try:
            device = self.lab.get_machine(device_name)
            if "ipv6" in device.meta and device.is_ipv6_enabled():
                self.results.append(SuccessfulCheck(self.description))
            else:
                self.results.append(FailedCheck(self.description, f"IPv6 not enabled on `{device_name}`"))
        except MachineNotFoundError as e:
            self.results.append(FailedCheck(self.description, str(e)))

    def run(self, ipv6_devices: list[str]):
        for device_name in ipv6_devices:
            self.check_with_timeout(device_name)

    def run_from_configuration(self):
        if key_exists(["test", "ipv6_enabled"], self.configuration):
            self.logger.info(f"Checking that IPv6 is enabled on devices: {self.configuration['test']['ipv6_enabled']}")
            self.run(self.configuration["test"]["ipv6_enabled"])
