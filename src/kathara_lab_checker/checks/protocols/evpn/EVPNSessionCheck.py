import json

from Kathara.exceptions import MachineNotRunningError
from Kathara.model.Lab import Lab

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....foundation.model.CheckResult import CheckResult
from ....model.FailedCheck import FailedCheck
from ....model.SuccessfulCheck import SuccessfulCheck
from ....utils import get_output, key_exists


class EVPNSessionCheck(AbstractCheck):

    def __init__(self, lab: Lab, description: str = None):
        super().__init__(lab, description=description, priority=1030)

    def check(self, device_name: str, neighbor: str) -> CheckResult:

        try:
            exec_output_gen = self.kathara_manager.exec(
                machine_name=device_name, command="vtysh -e 'show bgp summary json'", lab_hash=self.lab.hash
            )
        except MachineNotRunningError as e:
            return FailedCheck(self.description, str(e))

        output = get_output(exec_output_gen)

        if output.startswith("ERROR:") or "exec failed" in output:
            return FailedCheck(self.description, output)
        output = json.loads(output)
        if "l2VpnEvpn" in output:
            try:
                for peer_name, peer in output["l2VpnEvpn"]["peers"].items():
                    if neighbor == peer_name:
                        if peer["state"] == "Established":
                            return SuccessfulCheck(self.description)
                        else:
                            return FailedCheck(
                                self.description,
                                f"The session is configured but is in the {peer['state']} state",
                            )
            except KeyError:
                pass
            reason = f"The evpn session between {device_name} and {neighbor} is not up."

            return FailedCheck(self.description, reason)

        else:
            return FailedCheck(
                self.description, f"`l2VpnEvpn` address family not active for bgp on {device_name}"
            )

    def run(self, device_to_neighbours: dict[str, list[str]]) -> list[CheckResult]:
        results = []
        for device_name, neighbors in device_to_neighbours.items():
            self.logger.info(f"Checking that {device_name} has `address-family l2vpn evpn` activated...")
            for neighbor in neighbors:
                self.description = f"{device_name} has bgp peer {neighbor}"
                check_result = self.check(device_name, neighbor)
                results.append(check_result)
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "protocols", "bgpd", "evpn_sessions"], configuration):
            self.logger.info("Checking EVPN sessions configuration...")
            results.extend(self.run(configuration["test"]["protocols"]['bgpd']['evpn_sessions']))
        return results
