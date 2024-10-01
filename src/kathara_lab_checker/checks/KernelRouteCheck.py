from typing import Union

from Kathara.exceptions import MachineNotRunningError
from Kathara.model.Lab import Lab

from kathara_lab_checker.utils import is_valid_ip, load_routes_from_device, load_routes_from_expected
from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


class KernelRouteCheck(AbstractCheck):
    def check(self, device_name: str, expected_routing_table: list, lab: Lab) -> list[CheckResult]:
        self.description = f"Checking the routing table of {device_name}"
        actual_routing_table = load_routes_from_device(device_name, lab)
        expected_routing_table = load_routes_from_expected(expected_routing_table)

        results = []

        for dst, nexthops in expected_routing_table.items():
            if not dst in actual_routing_table:
                check_result = CheckResult(
                    self.description, False, f"The routing table of {device_name} is missing route {dst}"
                )
                results.append(check_result)
                self.logger.info(check_result)
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
                    self.logger.info(check_result)
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
                        self.logger.info(check_result)

        if not results:
            check_result = CheckResult(self.description, True, f"OK")
            results.append(check_result)
            self.logger.info(check_result)

        return results

    def run(self, devices_to_routes: dict[str, list[Union[str, list[str]]]], lab: Lab) -> list[CheckResult]:
        results = []
        for device_name, expected_routes in devices_to_routes.items():
            self.logger.info(f"Checking kernel routes for `{device_name}`...")
            try:
                check_result = self.check(device_name, expected_routes, lab)
                results = results + check_result
            except MachineNotRunningError:
                self.logger.warning(f"`{device_name}` is not running. Skipping checks...")
        return results
