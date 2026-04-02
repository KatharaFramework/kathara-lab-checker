import json
import ipaddress

from Kathara.exceptions import MachineNotRunningError, MachineBinaryError
from Kathara.model.Lab import Lab

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....foundation.model.CheckResult import CheckResult
from ....model.FailedCheck import FailedCheck
from ....model.SuccessfulCheck import SuccessfulCheck
from ....utils import key_exists


class BGPNeighborCheck(AbstractCheck):

    def __init__(self, lab: Lab, description: str = None):
        super().__init__(lab, description=description, priority=1010)

    def check(self, device_name: str, neighbors: list) -> list[CheckResult]:
        results = []

        try:
            stdout, stderr, exit_code = self.kathara_manager.exec(
                machine_name=device_name,
                command="vtysh -e 'show bgp summary json'",
                lab_hash=self.lab.hash,
                stream=False,
            )
        except MachineNotRunningError as e:
            results.append(FailedCheck(f"Checking {device_name} BGP neighbors", str(e)))
            return results
        except MachineBinaryError as e:
            results.append(FailedCheck(f"Checking {device_name} BGP neighbors", str(e)))
            return results
        except Exception as e:
            results.append(FailedCheck(f"Checking {device_name} BGP neighbors", str(e)))
            return results

        command_output = stdout.decode("utf-8") if stdout else None

        if stderr or exit_code != 0:
            results.append(
                FailedCheck(
                    f"Checking {device_name} BGP neighbors",
                    stderr.decode("utf-8") if stderr else f"Exit code: {exit_code}",
                )
            )
            return results
        command_output = json.loads(command_output)

        # Determine which address-family needs to be checked
        check_ipv4 = False
        check_ipv6 = False
        for neighbor in neighbors:
            if "eth" in neighbor["ip"]:
                check_ipv4 = True
                continue
            if ipaddress.ip_address(neighbor["ip"]).version == 4:
                check_ipv4 = True
            else:
                check_ipv6 = True

        output = {4: None, 6: None}
        if "ipv4Unicast" in command_output and "peers" in command_output["ipv4Unicast"]:
            output[4] = command_output["ipv4Unicast"]["peers"]

        if "ipv6Unicast" in command_output and "peers" in command_output["ipv6Unicast"]:
            output[6] = command_output["ipv6Unicast"]["peers"]

        ipv4_peerings = check_ipv4
        if check_ipv4 and output[4] is None:
            # if we expected to find IPv4 peerings but the output doesn't contain any
            results.append(
                FailedCheck(
                    f"Checking {device_name} BGP neighbors",
                    f"{device_name} has no IPv4 BGP neighbors",
                )
            )
            ipv4_peerings = False

        ipv6_peerings = check_ipv6
        if check_ipv6 and output[6] is None:
            # if we expected to find IPv6 peerings but the output doesn't contain any
            results.append(
                FailedCheck(
                    f"Checking {device_name} BGP neighbors",
                    f"{device_name} has no IPv6 BGP neighbors",
                )
            )
            ipv6_peerings = False

        router_neighbors = (set(output[4].keys()) if output[4] else set()) | (
            set(output[6].keys()) if output[6] else set()
        )
        expected_neighbors = set(neighbor["ip"] for neighbor in neighbors)

        extra_neighbors = router_neighbors - expected_neighbors

        if extra_neighbors:
            results.append(
                FailedCheck(
                    f"Checking {device_name} BGP neighbors",
                    f"{device_name} has extra BGP neighbors {extra_neighbors}",
                )
            )

        missing_neighbors = expected_neighbors - router_neighbors

        if missing_neighbors:
            results.append(
                FailedCheck(
                    f"Checking {device_name} BGP neighbors",
                    f"{device_name} is missing BGP neighbors {missing_neighbors}",
                )
            )

        # If there are no peerings configured or to verify, we can skip the rest of the checks
        if not ipv4_peerings and not ipv6_peerings:
            return results

        for neighbor in neighbors:
            neighbor_ip = neighbor["ip"]
            neighbor_ip_version = None
            try:
                neighbor_ip_version = ipaddress.ip_address(neighbor_ip).version
            except ValueError:
                neighbor_ip_version = 4
            neighbor_asn = neighbor["asn"]

            if not output[neighbor_ip_version]:
                continue

            if not neighbor_ip in output[neighbor_ip_version]:
                results.append(
                    FailedCheck(
                        f"Checking {device_name} BGP neighbors",
                        f"The peering between {device_name} and {neighbor_ip} is not configured.",
                    )
                )
                continue

            peer = output[neighbor_ip_version][neighbor_ip]

            check_description = f"{device_name} has bgp neighbor {neighbor_ip} AS{neighbor_asn}"
            if peer["remoteAs"] != neighbor_asn:
                results.append(
                    FailedCheck(
                        check_description,
                        f"{device_name} has neighbor {neighbor_ip} with ASN: {peer['remoteAs']} instead of {neighbor_asn}",
                    )
                )
            else:
                results.append(SuccessfulCheck(check_description))

            if peer["state"] == "Established":
                results.append(
                    SuccessfulCheck(
                        f"{device_name} has bgp neighbor {neighbor_ip} AS{neighbor_asn} established",
                    )
                )
            else:
                results.append(
                    FailedCheck(
                        f"{device_name} has bgp neighbor {neighbor_ip} AS{neighbor_asn}",
                        f"The session is configured but is in the {peer['state']} state",
                    )
                )

        return results

    def run(self, device_to_neighbours: dict[str, list[str]]) -> list[CheckResult]:
        results = []
        for device_name, neighbors in device_to_neighbours.items():
            self.logger.info(f"Checking {device_name} BGP peerings...")
            check_result = self.check(device_name, neighbors)
            results.extend(check_result)
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "protocols", "bgpd", "neighbors"], configuration):
            self.logger.info(f"Checking BGP neighbors...")
            results.extend(self.run(configuration["test"]["protocols"]["bgpd"]["neighbors"]))
        return results
