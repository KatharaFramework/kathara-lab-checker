import json

from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

from checks.AbstractCheck import AbstractCheck
from checks.CheckResult import CheckResult
from utils import get_output


class BGPPeeringCheck(AbstractCheck):
    def run(self, device_name: str, neighbor: str, lab: Lab) -> CheckResult:
        kathara_manager: Kathara = Kathara.get_instance()

        exec_output_gen = kathara_manager.exec(
            machine_name=device_name, command="vtysh -e 'show ip bgp summary json'", lab_hash=lab.hash
        )
        output = get_output(exec_output_gen)

        if output.startswith("ERROR:") or "exec failed" in output:
            return CheckResult(self.description, False, output)
        output = json.loads(output)
        try:
            for peer in output["ipv4Unicast"]["peers"]:
                if neighbor == peer:
                    return CheckResult(self.description, True, "OK")
        except KeyError:
            pass
        reason = f"The peering between {device_name} and {neighbor} is not up."

        return CheckResult(self.description, False, reason)
