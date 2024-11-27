from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


class StartupExistenceCheck(AbstractCheck):

    def check(self, device_name: str) -> CheckResult:
        self.description = f"Check existence of `{device_name}.startup` file"

        if self.lab.fs.exists(device_name + ".startup"):
            return CheckResult(self.description, True, "OK")
        else:
            return CheckResult(self.description, False, f"{device_name}.startup file not found")

    def run(self, machines_to_check: list[str]) -> list[CheckResult]:
        results = []
        for device_name in machines_to_check:
            check_result = self.check(device_name)
            results.append(check_result)
        return results
