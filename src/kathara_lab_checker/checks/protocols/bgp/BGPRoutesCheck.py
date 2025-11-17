import json
from collections import Counter

from Kathara.model.Lab import Lab

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....foundation.model.CheckResult import CheckResult
from ....model.FailedCheck import FailedCheck
from ....model.SuccessfulCheck import SuccessfulCheck
from ....utils import key_exists


class BGPRoutesCheck(AbstractCheck):

    def __init__(self, lab: Lab, description: str = None):
        super().__init__(lab, description=description, priority=1020)

    def check(self, device_name: str, networks: list) -> list[CheckResult]:
        results = []

        self.description = f"Check BGP routes for {device_name}"

        try:
            stdout, stderr, exit_code = self.kathara_manager.exec(
                machine_name=device_name, command=f"vtysh -e 'show ip bgp json'", lab_hash=self.lab.hash, stream=False
            )
        except Exception as e:
            results.append(FailedCheck(self.description, str(e)))
            return results

        output = stdout.decode("utf-8") if stdout else None

        if stderr or exit_code != 0:
            results.append(
                FailedCheck(
                    self.description,
                    stderr.decode("utf-8").strip() if stderr else f"Exit code: {exit_code}",
                )
            )
            return results

        output = json.loads(output)

        if not "routes" in output:
            results.append(
                FailedCheck(
                    self.description,
                    f"BGP routes not found in {device_name}",
                )
            )
            return results

        router_routes = output["routes"]

        for network in networks:
            if network["route"] not in router_routes:
                results.append(
                    FailedCheck(self.description,
                                f"Network {network['route']} is not in BGP routing table.")
                )
                continue

            router_route = router_routes[network["route"]]

            if len(router_route) != len(network["aspath"]):
                results.append(
                    FailedCheck(
                        self.description,
                        f"BGP network {network['route']} has a different number of alternatives. Expected: {len(network['aspath'])} Actual: {len(router_route)}",
                    )
                )

            supposed_aspaths = list(tuple(inner) for inner in network['aspath'])
            router_aspaths = list(
                tuple((int(num) if num else "") for num in inner["path"].split(" ")) for inner in router_route
            )

            count = Counter(supposed_aspaths)
            count.subtract(router_aspaths)
            dict_count = count.items()
            dict_count = {key: value for key, value in dict_count if value != 0}

            if not dict_count:
                results.append(SuccessfulCheck(self.description))
            else:
                results.append(
                    FailedCheck(
                        self.description,
                        f"BGP network {network['route']} have not correct AS Paths (supposed-actual): {dict_count}",
                    )
                )

        return results

    def run(self, devices_to_networks: dict[str, list[str]]) -> list[CheckResult]:
        results = []
        for device_name, networks in devices_to_networks.items():
            self.logger.info(f"Checking {device_name} BGP routes...")
            check_result = self.check(device_name, networks)
            results.extend(check_result)
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "protocols", "bgpd", "routes"], configuration):
            self.logger.info("Checking BGP routes...")
            results.extend(self.run(configuration["test"]["protocols"]['bgpd']['routes']))
        return results
