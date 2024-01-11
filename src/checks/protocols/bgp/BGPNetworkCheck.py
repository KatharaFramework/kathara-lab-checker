import re

from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

from checks.AbstractCheck import AbstractCheck
from checks.CheckResult import CheckResult
from utils import get_output


class BGPNetworkCheck(AbstractCheck):
    def run(self, device_name: str, network: str, lab: Lab) -> CheckResult:
        kathara_manager: Kathara = Kathara.get_instance()

        try:
            exec_output_gen = kathara_manager.exec(
                machine_name=device_name, command="vtysh -e 'show running-config bgp'", lab_hash=lab.hash
            )
        except Exception as e:
            return CheckResult(self.description, False, str(e))

        output = list(filter(lambda x: "network" in x, get_output(exec_output_gen).split("\n")))
        for line in output:
            if re.search(rf"\s*network\s*{network}", line):
                return CheckResult(self.description, True, "OK")
        reason = f"Network {network} is not announced in BGP."
        return CheckResult(self.description, False, reason)
