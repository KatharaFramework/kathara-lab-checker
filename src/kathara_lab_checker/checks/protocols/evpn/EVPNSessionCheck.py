import json

from Kathara.exceptions import MachineNotRunningError
from Kathara.model.Lab import Lab

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....model.FailedCheck import FailedCheck
from ....model.SuccessfulCheck import SuccessfulCheck
from ....utils import get_output, key_exists


class EVPNSessionCheck(AbstractCheck):

    def __init__(self, lab: Lab, configuration: dict, description: str = None):
        super().__init__(lab, configuration, description=description, priority=1030)

    def check(self, device_name: str, neighbor: str):

        try:
            exec_output_gen = self.kathara_manager.exec(
                machine_name=device_name, command="vtysh -e 'show bgp summary json'", lab_hash=self.lab.hash
            )
        except MachineNotRunningError as e:
            self.results.append(FailedCheck(self.description, str(e)))
            return

        output = get_output(exec_output_gen)

        if output.startswith("ERROR:") or "exec failed" in output:
            self.results.append(FailedCheck(self.description, output))
            return
        output = json.loads(output)
        if "l2VpnEvpn" in output:
            try:
                for peer_name, peer in output["l2VpnEvpn"]["peers"].items():
                    if neighbor == peer_name:
                        if peer["state"] == "Established":
                            self.results.append(SuccessfulCheck(self.description))
                        else:
                            self.results.append(FailedCheck(
                                self.description,
                                f"The session is configured but is in the {peer['state']} state",
                            ))
                        return
            except KeyError:
                pass
            reason = f"The evpn session between {device_name} and {neighbor} is not up."
            self.results.append(FailedCheck(self.description, reason))

        else:
            self.results.append(FailedCheck(
                self.description, f"`l2VpnEvpn` address family not active for bgp on {device_name}"
            ))

    def run(self, device_to_neighbours: dict[str, list[str]]):
        for device_name, neighbors in device_to_neighbours.items():
            self.logger.info(f"Checking that {device_name} has `address-family l2vpn evpn` activated...")
            for neighbor in neighbors:
                self.description = f"{device_name} has bgp peer {neighbor}"
                self.check_with_timeout(device_name, neighbor)

    def run_from_configuration(self):
        if key_exists(["test", "protocols", "bgpd", "evpn_sessions"], self.configuration):
            self.logger.info("Checking EVPN sessions configuration...")
            self.run(self.configuration["test"]["protocols"]['bgpd']['evpn_sessions'])
