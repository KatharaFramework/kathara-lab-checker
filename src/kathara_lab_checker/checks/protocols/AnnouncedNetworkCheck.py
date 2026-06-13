import re

from Kathara.model.Lab import Lab

from ...foundation.checks.AbstractCheck import AbstractCheck
from ...model.FailedCheck import FailedCheck
from ...model.SuccessfulCheck import SuccessfulCheck
from ...utils import get_output, key_exists


class AnnouncedNetworkCheck(AbstractCheck):

    def __init__(self, lab: Lab, configuration: dict, description: str = None):
        super().__init__(lab, configuration, description=description, priority=1110)

    def check(self, device_name: str, protocol: str, network: str):
        self.description = f"Check {protocol} network ({network}) for {device_name}"

        try:
            exec_output_gen = self.kathara_manager.exec(
                machine_name=device_name, command=f"vtysh -e 'show running-config {protocol}'", lab_hash=self.lab.hash
            )
        except Exception as e:
            self.results.append(FailedCheck(self.description, str(e)))
            return

        output = list(filter(lambda x: "network" in x, get_output(exec_output_gen).split("\n")))
        for line in output:
            if re.search(rf"\s*network\s*{network}", line):
                self.results.append(SuccessfulCheck(self.description))
                return
        reason = f"Network {network} is not announced in {protocol}."
        self.results.append(FailedCheck(self.description, reason))

    def run(self, protocol: str, devices_to_networks: dict[str, list[str]]):
        for device_name, networks in devices_to_networks.items():
            self.logger.info(f"Checking {device_name} {protocol} announces...")
            for network in networks:
                self.check_with_timeout(device_name, protocol, network)

    def run_from_configuration(self):
        if key_exists(["test", "protocols"], self.configuration):
            for daemon_name in self.configuration["test"]["protocols"]:
                if key_exists(["test", "protocols", daemon_name, "networks"], self.configuration):
                    self.logger.info(f"Checking announced networks for {daemon_name}...")
                    self.run(daemon_name, self.configuration["test"]["protocols"][daemon_name]["networks"])
