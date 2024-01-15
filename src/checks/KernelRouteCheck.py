from typing import Union

from Kathara.exceptions import MachineNotRunningError
from Kathara.model.Lab import Lab

from utils import get_kernel_routes, load_routes_from_ip_route, load_routes_from_expected
from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


class KernelRouteCheck(AbstractCheck):

    def check(self, device_name: str, expected_routing_table: list, lab: Lab) -> CheckResult:
        self.description = f"Checking the routing table of {device_name}"
        actual_routing_table = load_routes_from_ip_route(get_kernel_routes(device_name, lab))
        expected_routing_table = load_routes_from_expected(expected_routing_table)

        if actual_routing_table == expected_routing_table:
            return CheckResult(self.description, True, "OK")
        else:
            return CheckResult(self.description, False,
                               f"The routing table of device `{device_name}` is different from the expected one.\n" +
                               f"Actual:\t\t{actual_routing_table}\n" +
                               f"Expected:\t{expected_routing_table}"
                               )

    def run(self, devices_to_routes: dict[str, list[Union[str, list[str]]]], lab: Lab) -> list[CheckResult]:
        results = []
        for device_name, expected_routes in devices_to_routes.items():
            self.logger.info(f"Checking kernel routes for `{device_name}`...")
            try:
                check_result = self.check(device_name, expected_routes, lab)
                self.logger.info(check_result)
                results.append(check_result)
            except MachineNotRunningError:
                self.logger.warning(f"`{device_name}` is not running. Skipping checks...")
        return results
