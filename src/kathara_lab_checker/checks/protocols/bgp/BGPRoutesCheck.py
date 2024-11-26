import json

from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

from ...AbstractCheck import AbstractCheck
from ...CheckResult import CheckResult
from ....utils import get_output


class BGPRoutesCheck(AbstractCheck):

    def check(self, device_name: str, networks: list, lab: Lab) -> list[CheckResult]:
        results = []

        self.description = f"Check BGP routes for {device_name}"

        kathara_manager: Kathara = Kathara.get_instance()

        try:
            exec_output_gen = kathara_manager.exec(
                machine_name=device_name, command=f"vtysh -e 'show ip bgp json'", lab_hash=lab.hash
            )
        except Exception as e:
            results.append(CheckResult(self.description, False, str(e)))
            return results

        output = get_output(exec_output_gen)
        output = json.loads(output)

        router_routes = output["routes"]

        for network in networks:
            if network["route"] not in router_routes:
                results.append(
                    CheckResult(self.description, False, f"Network {network["route"]} is not in BGP routing table.")
                )
                continue

            router_route = router_routes[network["route"]]

            if len(router_route) != len(network["aspath"]):
                results.append(
                    CheckResult(
                        self.description,
                        False,
                        f"BGP network {network["route"]} has a different number of alternatives.",
                    )
                )
                continue

            supposed_aspaths = {tuple(inner) for inner in network["aspath"]}
            router_aspaths = {tuple(int(num) for num in inner["path"].split(" ")) for inner in router_route}

            if supposed_aspaths == router_aspaths:
                results.append(CheckResult(self.description, True, "OK"))
            else:
                symmetric_difference = supposed_aspaths ^ router_aspaths
                results.append(
                    CheckResult(
                        self.description,
                        False,
                        f"BGP network {network["route"]} have not correct AS Paths: {symmetric_difference}",
                    )
                )

        return results

    def run(self, devices_to_networks: dict[str, list[str]], lab: Lab) -> list[CheckResult]:
        results = []
        for device_name, networks in devices_to_networks.items():
            self.logger.info(f"Checking {device_name} BGP routes...")
            check_result = self.check(device_name, networks, lab)
            results.extend(check_result)
        return results
