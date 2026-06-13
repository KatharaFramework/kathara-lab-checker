import re

from Kathara.model.Lab import Lab

from ...foundation.checks.AbstractCheck import AbstractCheck
from ...model.FailedCheck import FailedCheck
from ...model.SuccessfulCheck import SuccessfulCheck
from ...utils import get_output, key_exists


class ProtocolRedistributionCheck(AbstractCheck):

    def __init__(self, lab: Lab, configuration: dict, description: str = None):
        super().__init__(lab, configuration, description=description, priority=1120)

    def check(self, device_name: str, protocol_to_check: str, injected_protocol: str):

        if injected_protocol.startswith("!"):
            injected_protocol = injected_protocol[1:]
            self.description = f"Checking that {injected_protocol} routes are not redistributed to {protocol_to_check} on device `{device_name}`"
            invert = True
        else:
            self.description = f"Checking that {injected_protocol} routes are redistributed to {protocol_to_check} on device `{device_name}`"
            invert = False

        try:
            exec_output_gen = self.kathara_manager.exec(
                machine_name=device_name,
                command=f"vtysh -e 'show running-config {protocol_to_check}'",
                lab_hash=self.lab.hash,
            )
        except Exception as e:
            self.results.append(FailedCheck(self.description, str(e)))
            return

        output = get_output(exec_output_gen).split("\n")
        found = False
        for line in output:
            if re.search(rf"^\s*redistribute\s*{injected_protocol}", line):
                found = True
                break
        if found ^ invert:
            self.results.append(SuccessfulCheck(self.description))
        else:
            reason = f"{injected_protocol} routes are {'' if invert else 'not '}injected into `{protocol_to_check}` on `{device_name}`."
            self.results.append(FailedCheck(self.description, reason))

    def run(self, daemon, devices_to_redistributed: dict[str, list[str]]):
        for device_name, injected_protocols in devices_to_redistributed.items():
            for injected_protocol in injected_protocols:
                self.check_with_timeout(device_name, daemon, injected_protocol)

    def run_from_configuration(self):
        if key_exists(["test", "protocols"], self.configuration):
            for daemon_name in self.configuration["test"]["protocols"]:
                if key_exists(["test", "protocols", daemon_name, "injections"], self.configuration):
                    self.logger.info(f"Checking {daemon_name} protocols' redistribution...")
                    self.run(daemon_name, self.configuration["test"]["protocols"][daemon_name]["injections"])
