from Kathara.exceptions import MachineNotRunningError
from Kathara.model.Lab import Lab

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....model.FailedCheck import FailedCheck
from ....model.SuccessfulCheck import SuccessfulCheck
from ....utils import key_exists


class SCIONAddressCheck(AbstractCheck):

    def __init__(self, lab: Lab, configuration: dict, description: str = None):
        super().__init__(lab, configuration, description=description, priority=1090)

    def check(self, device_name: str, expected_address: str):
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
            self.results.append(FailedCheck(self.description, str(e)))
            return
        output = stdout.decode("utf-8").strip() if stdout else ""
        if stderr or exit_code != 0:
            err_msg = stderr.decode("utf-8") if stderr else f"Exit code: {exit_code}"
            self.results.append(FailedCheck(self.description, err_msg))
            return
        if output == expected_address:
            self.results.append(SuccessfulCheck(self.description))
        else:
            self.results.append(FailedCheck(self.description, f"Expected '{expected_address}', got '{output}'"))

    def run(self, device_to_expected: dict[str, str]):
        """
        Expects a mapping: { device_name: expected_scion_address }
        """
        for device_name, expected in device_to_expected.items():
            self.check_with_timeout(device_name, expected)

    def run_from_configuration(self):
        if key_exists(["test", "protocols", "sciond", "address"], self.configuration):
            self.logger.info("Checking SCION addresses...")
            self.run(self.configuration["test"]["protocols"]['sciond']['address'])
