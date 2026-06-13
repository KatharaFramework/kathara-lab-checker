from Kathara.exceptions import MachineNotFoundError
from Kathara.model.Lab import Lab

from ..foundation.checks.AbstractCheck import AbstractCheck
from ..model.FailedCheck import FailedCheck
from ..model.SuccessfulCheck import SuccessfulCheck
from ..utils import key_exists


class SysctlCheck(AbstractCheck):

    def __init__(self, lab: Lab, configuration: dict, description: str = None):
        super().__init__(lab, configuration, description=description, priority=40)

    def check(self, device_name: str, sysctl_to_check: str):
        self.description = f"Checking that sysctl `{sysctl_to_check}` is set on `{device_name}`"

        try:
            device = self.lab.get_machine(device_name)
            split = sysctl_to_check.split("=")
            sysctl_to_check, value_to_check = split[0], int(split[1])

            device_sysctls = device.get_sysctls()

            if sysctl_to_check in device_sysctls:
                if value_to_check == device_sysctls[sysctl_to_check]:
                    self.results.append(SuccessfulCheck(self.description))
                else:
                    self.results.append(FailedCheck(
                        self.description,
                        f"Sysctl `{sysctl_to_check}` set on `{device_name}` with wrong "
                        f"value `{device_sysctls[sysctl_to_check]}` (instead of `{value_to_check}`)",
                    ))
            else:
                self.results.append(FailedCheck(self.description, f"Sysctl `{sysctl_to_check}` not set on `{device_name}`"))
        except MachineNotFoundError as e:
            self.results.append(FailedCheck(self.description, str(e)))

    def run(self, devices_sysctls: dict[str, list[str]]):
        for device_name, sysctls in devices_sysctls.items():
            for sysctl in sysctls:
                self.check_with_timeout(device_name, sysctl)

    def run_from_configuration(self):
        if key_exists(["test", "sysctls"], self.configuration):
            self.logger.info(f"Checking sysctl configurations on devices...")
            self.run(self.configuration["test"]["sysctls"])
