import json

from Kathara.exceptions import MachineNotRunningError

from ...AbstractCheck import AbstractCheck
from ....model.CheckResult import CheckResult


class BGPNeighborCheck(AbstractCheck):
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
            results.append(CheckResult(f"Checking {device_name} BGP neighbors", False, str(e)))
            return results

        output = stdout.decode("utf-8") if stdout else None

        if stderr or exit_code != 0:
            results.append(
                CheckResult(
                    f"Checking {device_name} BGP neighbors",
                    False,
                    stderr.decode("utf-8") if stderr else f"Exit code: {exit_code}",
                )
            )
            return results
        output = json.loads(output)

        if "ipv4Unicast" in output:
            output = output["ipv4Unicast"]
        else:
            results.append(
                CheckResult(
                    f"Checking {device_name} BGP neighbors",
                    False,
                    f"{device_name} has no IPv4 BGP peerings",
                )
            )
            return results

        if "peers" in output:
            output = output["peers"]
        else:
            results.append(
                CheckResult(
                    f"Checking {device_name} BGP neighbors",
                    False,
                    f"{device_name} has no IPv4 BGP neighbors",
                )
            )
            return results

        router_neighbors = output.keys()
        expected_neighbors = set(neighbor["ip"] for neighbor in neighbors)

        if len(router_neighbors) > len(expected_neighbors):
            results.append(
                CheckResult(
                    f"Checking {device_name} BGP neighbors",
                    False,
                    f"{device_name} has {len(output)-len(neighbors)} extra BGP neighbors {router_neighbors - expected_neighbors}",
                )
            )

        diff_neighbors = router_neighbors - expected_neighbors

        if diff_neighbors:
            results.append(
                CheckResult(
                    f"Checking {device_name} BGP neighbors",
                    False,
                    f"{device_name} has extra BGP neighbors {diff_neighbors}",
                )
            )

        for neighbor in neighbors:
            neighbor_ip = neighbor["ip"]
            neighbor_asn = neighbor["asn"]

            if not neighbor_ip in output:
                results.append(
                    CheckResult(
                        f"Checking {device_name} BGP neighbors",
                        False,
                        f"The peering between {device_name} and {neighbor_ip} is not configured.",
                    )
                )
                continue

            peer = output[neighbor_ip]

            if peer["remoteAs"] != neighbor_asn:
                results.append(
                    CheckResult(
                        f"{device_name} has bgp neighbor {neighbor_ip} AS{neighbor_asn}",
                        False,
                        f"{device_name} has neighbor {neighbor_ip} with ASN: {peer['remoteAs']} instead of {neighbor_asn}",
                    )
                )
            else:
                results.append(
                    CheckResult(
                        f"{device_name} has bgp neighbor {neighbor_ip} AS{neighbor_asn}",
                        True,
                        f"{device_name} has neighbor {neighbor_ip} with ASN: {peer['remoteAs']}",
                    )
                )
            if peer["state"] == "Established":
                results.append(
                    CheckResult(
                        f"{device_name} has bgp neighbor {neighbor_ip} AS{neighbor_asn} established",
                        True,
                        "OK",
                    )
                )
            else:
                results.append(
                    CheckResult(
                        f"{device_name} has bgp neighbor {neighbor_ip} AS{neighbor_asn}",
                        False,
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
