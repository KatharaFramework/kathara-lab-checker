from Kathara.model.Lab import Lab

from ..foundation.checks.AbstractCheck import AbstractCheck
from ..model.FailedCheck import FailedCheck
from ..model.SuccessfulCheck import SuccessfulCheck
from ..utils import key_exists


class StartupExistenceCheck(AbstractCheck):

    def __init__(self, lab: Lab, configuration: dict, description: str = None):
        super().__init__(lab, configuration, description=description, priority=20)

    def check(self, device_name: str):
        self.description = f"Check existence of `{device_name}.startup` file"

        if self.lab.fs.exists(device_name + ".startup"):
            self.results.append(SuccessfulCheck(self.description))
        else:
            self.results.append(FailedCheck(self.description, f"{device_name}.startup file not found"))

    def run(self, machines_to_check: list[str]):
        for device_name in machines_to_check:
            self.check_with_timeout(device_name)

    def run_from_configuration(self):
        if key_exists(["test", "requiring_startup"], self.configuration):
            self.logger.info("Checking that all required startup files exist...")
            self.run(self.configuration["test"]["requiring_startup"])
