import re

from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

from ..AbstractCheck import AbstractCheck
from ..CheckResult import CheckResult
from ...utils import get_output


class AnnouncedNetworkCheck(AbstractCheck):
    def check(self, device_name: str, protocol: str, network: str, lab: Lab) -> CheckResult:
        self.description = f"Check {protocol} network ({network}) for {device_name}"

        kathara_manager: Kathara = Kathara.get_instance()

        try:
            exec_output_gen = kathara_manager.exec(
                machine_name=device_name, command=f"vtysh -e 'show running-config {protocol}'", lab_hash=lab.hash
            )
        except Exception as e:
            return CheckResult(self.description, False, str(e))

        output = list(filter(lambda x: "network" in x, get_output(exec_output_gen).split("\n")))
        for line in output:
            if re.search(rf"\s*network\s*{network}", line):
                return CheckResult(self.description, True, "OK")
        reason = f"Network {network} is not announced in {protocol}."
        return CheckResult(self.description, False, reason)

    def run(self, protocol: str, devices_to_networks: dict[str, list[str]], lab: Lab) -> list[CheckResult]:
        results = []
        for device_name, networks in devices_to_networks.items():
            self.logger.info(f"Checking {device_name} BGP announces...")
            for network in networks:
                check_result = self.check(device_name, protocol, network, lab)
                results.append(check_result)
        return results
