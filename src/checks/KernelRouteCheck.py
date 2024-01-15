from typing import Union

from Kathara.exceptions import MachineNotRunningError
from Kathara.model.Lab import Lab

from utils import get_kernel_routes
from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


class KernelRouteCheck(AbstractCheck):

    def check_negative_route(self, device_name: str, route_to_check_original: str, next_hop: str,
                             routes: list[dict]) -> CheckResult:
        self.description = (
                f"Check that route {route_to_check_original} "
                + (f"with nexthop {next_hop} " if next_hop else "")
                + f"IS NOT in the routing table of device `{device_name}`"
        )

        if route_to_check_original == "0.0.0.0/0":
            route_to_check = "default"
        else:
            route_to_check = route_to_check_original

        for route in routes:
            if route["dst"] == route_to_check:
                reason = f"The route `{route_to_check_original}` IS in the routing table of `{device_name}`."
                return CheckResult(self.description, False, reason)

        return CheckResult(self.description, True, "OK")

    def check_positive_route(self, device_name: str, route_to_check_original: str, next_hop: str,
                             routes: list[dict]) -> CheckResult:
        self.description = (
                f"Check that route {route_to_check_original} "
                + (f"with nexthop {next_hop} " if next_hop else "")
                + f"IS in the routing table of device `{device_name}`"
        )

        if route_to_check_original == "0.0.0.0/0":
            route_to_check = "default"
        else:
            route_to_check = route_to_check_original

        for route in routes:
            if route["dst"] == route_to_check:
                if next_hop:
                    if route["gateway"] == next_hop:
                        return CheckResult(self.description, True, "OK")
                    else:
                        reason = f"The route is present with nexthop {route['gateway']}. Maybe some policies are misconfigured."
                        return CheckResult(self.description, False, reason)
                return CheckResult(self.description, True, "OK")
        reason = f"The route {route_to_check_original} IS NOT found in the routing table of `{device_name}`."
        return CheckResult(self.description, False, reason)

    def check(self, device_name: str, expected_routes: list[Union[str, list[str]]], lab) -> CheckResult:
        device_routes = get_kernel_routes(device_name, lab)
        device_routes = list(
            map(lambda x: [x['dst'], [nh['dev'] for nh in x['nexthops']]] if 'nexthops' in x else x['dst'],
                device_routes))
        if expected_routes == device_routes:
            return CheckResult(self.description, True, "OK")
        else:
            return CheckResult(self.description, False,
                               f"The routing table of device `{device_name}` is different from the expected one.\n" +
                               f"Actual: {device_routes}\n" +
                               f"Expected: {expected_routes}"
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
