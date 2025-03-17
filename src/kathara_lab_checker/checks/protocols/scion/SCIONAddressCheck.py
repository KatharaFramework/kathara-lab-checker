from Kathara.exceptions import MachineNotRunningError
from Kathara.model.Lab import Lab

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....model.CheckResult import CheckResult
from ....utils import key_exists


class SCIONAddressCheck(AbstractCheck):

    def __init__(self, lab: Lab, description: str = None):
        super().__init__(lab, description=description, priority=1090)

    def check(self, device_name: str, expected_address: str) -> CheckResult:
        """
        Executes 'scion address' on the device and compares the output to expected_address.
        Expected format example: "42-ffaa:1:1,127.0.0.1"
        """
        self.description = f"Checking SCION address on {device_name}"
        try:
            stdout, stderr, exit_code = self.kathara_manager.exec(
                machine_name=device_name,
                command="scion address",
                lab_hash=self.lab.hash,
                stream=False
            )
        except MachineNotRunningError as e:
            return CheckResult(self.description, False, str(e))
        output = stdout.decode("utf-8").strip() if stdout else ""
        if stderr or exit_code != 0:
            err_msg = stderr.decode("utf-8") if stderr else f"Exit code: {exit_code}"
            return CheckResult(self.description, False, err_msg)
        if output == expected_address:
            return CheckResult(self.description, True, "OK")
        else:
            return CheckResult(self.description, False, f"Expected '{expected_address}', got '{output}'")

    def run(self, device_to_expected: dict[str, str]) -> list[CheckResult]:
        """
        Expects a mapping: { device_name: expected_scion_address }
        """
        results = []
        for device_name, expected in device_to_expected.items():
            results.append(self.check(device_name, expected))
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "protocols", "sciond", "address"], configuration):
            self.logger.info("Checking SCION addresses...")
            results.extend(self.run(configuration["test"]["protocols"]['sciond']['address']))
        return results
