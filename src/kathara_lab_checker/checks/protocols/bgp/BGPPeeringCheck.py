import json

from Kathara.exceptions import MachineNotRunningError
from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

from ...AbstractCheck import AbstractCheck
from ...CheckResult import CheckResult
from ....utils import get_output


class BGPPeeringCheck(AbstractCheck):
    def check(self, device_name: str, neighbor_ip: str, neighbor_asn: int, lab: Lab) -> list[CheckResult]:
        results = []
        kathara_manager: Kathara = Kathara.get_instance()
        try:
            exec_output_gen = kathara_manager.exec(
                machine_name=device_name, command="vtysh -e 'show bgp summary json'", lab_hash=lab.hash
            )
        except MachineNotRunningError as e:
            results.append(CheckResult(self.description, False, str(e)))
            return results
        output = get_output(exec_output_gen)

        if output.startswith("ERROR:") or "exec failed" in output:
            results.append(CheckResult(self.description, False, output))
            return results
        output = json.loads(output)
        try:
            for peer_name, peer in output["ipv4Unicast"]["peers"].items():
                if neighbor_ip == peer_name:
                    if peer["remoteAs"] != neighbor_asn:
                        results.append(
                            CheckResult(
                                self.description,
                                False,
                                f"{device_name} has neighbor {neighbor_ip} with ASN: {peer["remoteAs"]}",
                            )
                        )
                    else:
                        results.append(
                            CheckResult(
                                self.description,
                                True,
                                f"{device_name} has neighbor {neighbor_ip} with ASN: {peer["remoteAs"]}",
                            )
                        )
                    if peer["state"] == "Established":
                        results.append(CheckResult(self.description, True, "OK"))
                    else:
                        results.append(
                            CheckResult(
                                self.description,
                                False,
                                f"The session is configured but is in the {peer['state']} state",
                            )
                        )
                    return results
        except KeyError:
            pass
        reason = f"The peering between {device_name} and {neighbor_ip} is not up."
        results.append(CheckResult(self.description, False, reason))
        return results

    def run(self, device_to_neighbours: dict[str, list[str]], lab: Lab) -> list[CheckResult]:
        results = []
        for device_name, neighbors in device_to_neighbours.items():
            self.logger.info(f"Checking {device_name} BGP peerings...")
            for neighbor in neighbors:
                neighbor_ip = neighbor["ip"]
                neighbor_asn = neighbor["asn"]
                self.description = f"{device_name} has bgp neighbor {neighbor_ip}"
                check_result = self.check(device_name, neighbor_ip, neighbor_asn, lab)
                results.extend(check_result)
        return results
