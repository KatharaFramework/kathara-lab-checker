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

    def check(self, device_name: str, route: str, next_hop: str, kernel_routes: list[dict]) -> CheckResult:
        negative = False
        if route.startswith("!"):
            route = route[1:]
            negative = True
        if not negative:
            return self.check_positive_route(device_name, route, next_hop, kernel_routes)
        else:
            return self.check_negative_route(device_name, route, next_hop, kernel_routes)

    def run(self, devices_to_routes: dict[str, list[str]], lab: Lab) -> list[CheckResult]:
        results = []
        for device_name, routes_to_check in devices_to_routes.items():
            self.logger.info(f"Checking kernel routes for `{device_name}`...")
            try:
                device_routes = get_kernel_routes(device_name, lab)
                for route_to_check in routes_to_check:
                    next_hop = None
                    if type(route_to_check) == list:
                        next_hop = route_to_check[1]
                        route_to_check = route_to_check[0]
                    check_result = self.check(device_name, route_to_check, next_hop, device_routes)
                    self.logger.info(check_result)
                    results.append(check_result)
            except MachineNotRunningError:
                self.logger.warning(f"`{device_name}` is not running. Skipping checks...")
        return results
