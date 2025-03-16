import json

from Kathara.exceptions import MachineNotRunningError

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....model.CheckResult import CheckResult
from ....utils import key_exists


class OSPFRoutesCheck(AbstractCheck):
    def check(self, device_name: str, expected_routes: list[dict]) -> list[CheckResult]:
        results = []
        self.description = f"Checking OSPF routes on {device_name}"
        try:
            stdout, stderr, exit_code = self.kathara_manager.exec(
                machine_name=device_name,
                command="vtysh -e 'show ip ospf route json'",
                lab_hash=self.lab.hash,
                stream=False
            )
        except MachineNotRunningError as e:
            return [CheckResult(self.description, False, str(e))]
        output = stdout.decode("utf-8") if stdout else ""
        if stderr or exit_code != 0:
            err_msg = stderr.decode("utf-8") if stderr else f"Exit code: {exit_code}"
            return [CheckResult(self.description, False, err_msg)]
        try:
            data = json.loads(output)
        except Exception as e:
            return [CheckResult(self.description, False, f"JSON parse error: {str(e)}")]

        # If the JSON does not have a "routes" key, assume the top-level object is the routes dict.
        ospf_routes = data.get("routes", data)

        for expected in expected_routes:
            route = expected.get("route")
            check_desc = f"OSPF route {route} on {device_name}"
            if route not in ospf_routes:
                results.append(CheckResult(check_desc, False, f"Route {route} not found"))
            else:
                results.append(CheckResult(check_desc, True, "OK"))
        return results

    def run(self, devices_to_routes: dict[str, list[dict]]) -> list[CheckResult]:
        results = []
        for device_name, routes in devices_to_routes.items():
            self.logger.info(f"Checking OSPF routes for {device_name}...")
            results.extend(self.check(device_name, routes))
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "protocols", "ospfd", "routes"], configuration):
            self.logger.info("Checking OSPF routes...")
            results.extend(self.run(configuration["test"]["protocols"]['ospfd']['routes']))
        return results
