import re

from Kathara.model.Lab import Lab

from ...foundation.checks.AbstractCheck import AbstractCheck
from ...model.CheckResult import CheckResult
from ...utils import get_output, key_exists


class AnnouncedNetworkCheck(AbstractCheck):

    def __init__(self, lab: Lab, description: str = None):
        super().__init__(lab, description=description, priority=1110)

    def check(self, device_name: str, protocol: str, network: str) -> CheckResult:
        self.description = f"Check {protocol} network ({network}) for {device_name}"

        try:
            exec_output_gen = self.kathara_manager.exec(
                machine_name=device_name, command=f"vtysh -e 'show running-config {protocol}'", lab_hash=self.lab.hash
            )
        except Exception as e:
            return CheckResult(self.description, False, str(e))

        output = list(filter(lambda x: "network" in x, get_output(exec_output_gen).split("\n")))
        for line in output:
            if re.search(rf"\s*network\s*{network}", line):
                return CheckResult(self.description, True, "OK")
        reason = f"Network {network} is not announced in {protocol}."
        return CheckResult(self.description, False, reason)

    def run(self, protocol: str, devices_to_networks: dict[str, list[str]]) -> list[CheckResult]:
        results = []
        for device_name, networks in devices_to_networks.items():
            self.logger.info(f"Checking {device_name} {protocol} announces...")
            for network in networks:
                check_result = self.check(device_name, protocol, network)
                results.append(check_result)
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "protocols"], configuration):
            for daemon_name in configuration["test"]["protocols"]:
                if key_exists(["test", "protocols", daemon_name, "networks"], configuration):
                    self.logger.info(f"Checking announced networks for {daemon_name}...")
                    results.extend(self.run(daemon_name, configuration["test"]["protocols"][daemon_name]["networks"]))
        return results
