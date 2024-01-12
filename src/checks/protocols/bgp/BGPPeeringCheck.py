import json

from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

from checks.AbstractCheck import AbstractCheck
from checks.CheckResult import CheckResult
from utils import get_output


class BGPPeeringCheck(AbstractCheck):
    def check(self, device_name: str, neighbor: str, lab: Lab) -> CheckResult:
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

    def run(self, device_to_neighbours: dict[str, list[str]], lab: Lab) -> list[CheckResult]:
        results = []
        for device_name, neighbors in device_to_neighbours.items():
            self.logger.info(f"Checking {device_name} BGP peerings...")
            for neighbor in neighbors:
                self.description = f"{device_name} has bgp peer {neighbor}"
                check_result = self.check(device_name, neighbor, lab)
                self.logger.info(check_result)
                results.append(check_result)
        return results
