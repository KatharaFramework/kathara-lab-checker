import ipaddress
import json
from typing import Union, Any

from Kathara.exceptions import MachineNotRunningError

from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


def load_routes_from_expected(expected_routes: list) -> dict[str, set]:
    routes = {}
    for route in expected_routes:
        if type(route) is list:
            routes[route[0]] = set(route[1])
        else:
            routes[route] = set()
    return routes


def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


class KernelRouteCheck(AbstractCheck):
    def check(self, device_name: str, expected_routing_table: list) -> list[CheckResult]:
        self.description = f"Checking the routing table of {device_name}"
        actual_routing_table = dict(
            filter(
                lambda item: not any("d.c." in elem for elem in item[1]),
                self.load_routes_from_device(device_name).items(),
            )
        )
        expected_routing_table = load_routes_from_expected(expected_routing_table)

        results = []

        if len(expected_routing_table) != len(actual_routing_table):
            check_result = CheckResult(
                self.description,
                False,
                f"The routing table of {device_name} have the wrong number of routes: {len(actual_routing_table)}, expected: {len(expected_routing_table)}",
            )
            results.append(check_result)

        for dst, nexthops in expected_routing_table.items():
            if not dst in actual_routing_table:
                check_result = CheckResult(
                    self.description, False, f"The routing table of {device_name} is missing route {dst}"
                )
                results.append(check_result)
                continue
            if nexthops:
                actual_nh = actual_routing_table[dst]
                if len(nexthops) != len(actual_nh):
                    check_result = CheckResult(
                        self.description,
                        False,
                        f"The routing table of {device_name} about route {dst} have the wrong number of next-hops: {len(actual_nh)}, expected: {len(nexthops)}",
                    )
                    results.append(check_result)
                    continue
                for nh in nexthops:
                    valid_ip = is_valid_ip(nh)
                    if (valid_ip and not any(item[0] == nh for item in actual_nh)) or (
                        not valid_ip and not any(item[1] == nh for item in actual_nh)
                    ):
                        check_result = CheckResult(
                            self.description,
                            False,
                            f"The routing table of {device_name} about route {dst} does not contain next-hop: {nh}, actual: {actual_nh}",
                        )
                        results.append(check_result)

        for dst, nexthops in actual_routing_table.items():
            if not dst in expected_routing_table.keys():
                check_result = CheckResult(
                    self.description,
                    False,
                    f"The routing table of {device_name} contains route {dst} that should not be there",
                )
                results.append(check_result)
                continue

        if not results:
            check_result = CheckResult(self.description, True, f"OK")
            results.append(check_result)

        return results

    def run(self, devices_to_routes: dict[str, list[Union[str, list[str]]]]) -> list[CheckResult]:
        results = []
        for device_name, expected_routes in devices_to_routes.items():
            self.logger.info(f"Checking kernel routes for `{device_name}`...")
            try:
                check_result = self.check(device_name, expected_routes)
                results = results + check_result
            except MachineNotRunningError:
                self.logger.warning(f"`{device_name}` is not running. Skipping checks...")
        return results

    def get_kernel_routes(self, device_name: str) -> list[dict[str, Any]]:
        try:
            stdout, _, _ = self.kathara_manager.exec(
                machine_name=device_name, lab_hash=self.lab.hash, command="ip -j route", stream=False
            )
            stdout = stdout.decode("utf-8").strip()
        except MachineNotRunningError:
            return []
        return json.loads(stdout)

    def get_nexthops(self, device_name: str) -> list[dict[str, Any]]:

        try:
            stdout, _, _ = self.kathara_manager.exec(
                machine_name=device_name, lab_hash=self.lab.hash, command="ip -j nexthop", stream=False
            )
            stdout = stdout.decode("utf-8").strip()
        except MachineNotRunningError:
            return []

        return json.loads(stdout)

    def load_routes_from_device(self, device_name: str) -> dict[str, set]:
        ip_route_output = self.get_kernel_routes(device_name)
        routes = {}
        kernel_nexthops = None

        for route in ip_route_output:

            dst = route["dst"]
            if dst == "default":
                dst = "0.0.0.0/0"
            nexthops = None
            if "scope" in route and route["scope"] == "link":
                nexthops = [("d.c.", route["dev"])]
            elif "nexthops" in route:
                nexthops = list(map(lambda x: x["dev"], route["nexthops"]))
            elif "gateway" in route:
                nexthops = [(route["gateway"], route["dev"])]
            elif "via" in route:
                nexthops = [(route["via"]["host"], route["dev"])]
            elif "nhid" in route:
                # Lazy load nexthops
                kernel_nexthops = self.get_nexthops(device_name) if kernel_nexthops is None else kernel_nexthops

                current_nexthop = [obj for obj in kernel_nexthops if obj["id"] == route["nhid"]][0]
                if "gateway" in current_nexthop:
                    nexthops = [(current_nexthop["gateway"], current_nexthop["dev"])]
                elif "group" in current_nexthop:
                    nexthops = [
                        (obj["gateway"], obj["dev"])
                        for obj in kernel_nexthops
                        if obj["id"] in (nhid["id"] for nhid in current_nexthop["group"])
                    ]
                else:
                    raise Exception("Strange nexthop: ", current_nexthop)
            routes[dst] = set(nexthops)
        return routes
