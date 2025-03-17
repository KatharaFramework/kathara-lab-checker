import json

from Kathara.exceptions import MachineNotRunningError
from Kathara.model.Lab import Lab

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....model.CheckResult import CheckResult
from ....utils import key_exists


class OSPFNeighborCheck(AbstractCheck):

    def __init__(self, lab: Lab, description: str = None):
        super().__init__(lab, description=description, priority=1060)

    def check(self, device_name: str, expected_neighbors: list[dict]) -> list[CheckResult]:
        results = []
        self.description = f"Checking OSPF neighbors on {device_name}"
        try:
            stdout, stderr, exit_code = self.kathara_manager.exec(
                machine_name=device_name,
                command="vtysh -e 'show ip ospf neighbor json'",
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

        # Expect data to be a dict with a "neighbors" key that is also a dict.
        if isinstance(data, dict) and "neighbors" in data:
            neighbors_data = data["neighbors"]
        else:
            neighbors_data = {}

        # For each expected neighbor, check presence and state.
        for expected in expected_neighbors:
            expected_id = expected.get("router_id")
            # Default expected state is FULL (we compare in uppercase)
            expected_state = expected.get("state", "FULL").upper()
            check_desc = f"OSPF neighbor {expected_id} on {device_name}"
            if expected_id not in neighbors_data:
                results.append(CheckResult(check_desc, False, f"Neighbor with router_id {expected_id} not found"))
                continue
            # Get the list of neighbor info objects.
            neighbor_entries = neighbors_data[expected_id]
            matched = False
            for entry in neighbor_entries:
                # Use the "converged" field as the operational state.
                actual_state = entry.get("converged", "").upper()
                if actual_state == expected_state:
                    results.append(CheckResult(check_desc, True, "OK"))
                    matched = True
                    break
            if not matched:
                first_state = neighbor_entries[0].get("converged", "UNKNOWN")
                results.append(CheckResult(check_desc, False, f"State is {first_state}, expected {expected_state}"))
        return results

    def run(self, device_to_neighbors: dict[str, list[dict]]) -> list[CheckResult]:
        results = []
        for device_name, neighbors in device_to_neighbors.items():
            self.logger.info(f"Checking OSPF neighbors for {device_name}...")
            results.extend(self.check(device_name, neighbors))
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "protocols", "ospfd", "neighbors"], configuration):
            self.logger.info("Checking OSPF neighbors...")
            results.extend(self.run(configuration["test"]["protocols"]['ospfd']['neighbors']))
        return results
