from Kathara.model.Lab import Lab

from ..foundation.checks.AbstractCheck import AbstractCheck
from ..foundation.model.CheckResult import CheckResult
from ..model.FailedCheck import FailedCheck
from ..model.SuccessfulCheck import SuccessfulCheck
from ..utils import key_exists


class FolderExistenceCheck(AbstractCheck):

    def __init__(self, lab: Lab, description: str = None):
        super().__init__(lab, description=description, priority=25)

    def check(self, device_name: str) -> CheckResult:
        if device_name.startswith("!"):
            device_name = device_name[1:]
            self.description = f"Check absence of `{device_name}` folder"
            invert = True
        else:
            self.description = f"Check existence of `{device_name}` folder"
            invert = False

        if self.lab.fs.isdir(device_name) ^ invert:
            return SuccessfulCheck(self.description)
        else:
            reason = f"{device_name} folder {'found' if invert else 'not found'}"
            return FailedCheck(self.description, reason)

    def run(self, machines_to_check: list[str]) -> list[CheckResult]:
        results = []
        for device_name in machines_to_check:
            check_result = self.check(device_name)
            results.append(check_result)

        mentioned_folders = {device_name.lstrip("!") for device_name in machines_to_check}
        for folder_name in sorted(self.lab.fs.listdir(".")):
            if folder_name == "shared" or folder_name in mentioned_folders or not self.lab.fs.isdir(folder_name):
                continue
            self.description = "Check for unexpected folders"
            results.append(FailedCheck(self.description, f"Unexpected {folder_name} folder found"))
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "requiring_folder"], configuration):
            self.logger.info("Checking that all required device folders exist...")
            results.extend(self.run(configuration["test"]["requiring_folder"]))
        return results
