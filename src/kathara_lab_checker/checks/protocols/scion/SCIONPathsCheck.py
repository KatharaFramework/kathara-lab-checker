import json

from Kathara.exceptions import MachineNotRunningError

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....model.CheckResult import CheckResult
from ....utils import key_exists


class SCIONPathsCheck(AbstractCheck):
    def format_path(self, path: dict) -> str:
        """
        Formats a single path dictionary into a string representation 
        with departure/arrival in the X>Y notation.
        Collapses consecutive hops with the same 'isd_as'.
        """
        hops = path.get("hops", [])
        if not hops:
            return ""

        # We'll build up a list of "nodes," each with "isd_as" + single interface 
        # (both departure and arrival).
        nodes = []
        # Start with the first hop
        first = hops[0]
        nodes.append({
            "isd_as": first.get("isd_as", ""),
            "arr": first.get("interface"),
            "dep": first.get("interface"),
        })

        for hop in hops[1:]:
            current_as = hop.get("isd_as", "")
            iface = hop.get("interface")
            # If the last node is the same AS, update its 'dep'
            if nodes and nodes[-1]["isd_as"] == current_as:
                nodes[-1]["dep"] = iface
            else:
                nodes.append({
                    "isd_as": current_as,
                    "arr": iface,
                    "dep": iface
                })

        formatted = nodes[0]["isd_as"]
        for i in range(1, len(nodes)):
            prev_dep = nodes[i - 1]["dep"]
            curr_arr = nodes[i]["arr"]
            formatted += f" {prev_dep}>{curr_arr} {nodes[i]['isd_as']}"

        return formatted

    def check(self, device_name: str, destination: str, expected_paths: list[str]) -> list[CheckResult]:
        """
        Runs 'scion showpaths <destination> --format json' and checks that each 
        path in expected_paths is present in the returned list of actual paths.
        """
        desc_base = f"SCION paths from {device_name} to {destination}"
        results = []

        try:
            cmd = f"scion showpaths {destination} --refresh --format json"
            stdout, stderr, exit_code = self.kathara_manager.exec(
                machine_name=device_name,
                command=cmd,
                lab_hash=self.lab.hash,
                stream=False
            )
        except MachineNotRunningError as e:
            return [CheckResult(desc_base, False, str(e))]

        raw_output = stdout.decode("utf-8").strip() if stdout else ""
        if stderr or exit_code != 0:
            err_msg = stderr.decode("utf-8") if stderr else f"Exit code: {exit_code}"
            return [CheckResult(desc_base, False, err_msg)]

        try:
            data = json.loads(raw_output)
        except Exception as e:
            return [CheckResult(desc_base, False, f"JSON parse error: {str(e)}")]

        actual_paths = set()
        for path_obj in data.get("paths", []):
            formatted = self.format_path(path_obj)
            if formatted:
                actual_paths.add(formatted)

        # For each expected path, check if it exists
        for exp_path in expected_paths:
            desc = f"{desc_base}: '{exp_path}'"
            if exp_path in actual_paths:
                results.append(CheckResult(desc, True, "OK"))
            else:
                results.append(CheckResult(desc, False, f"Path '{exp_path}' not found"))
        return results

    def run(self, device_destinations: dict[str, dict[str, list[str]]]) -> list[CheckResult]:
        """
        device_destinations = {
          "device_name": {
             "destination_1": [ "expPath1", "expPath2" ],
             "destination_2": [ "expPath3" ],
             ...
          },
          ...
        }

        For each device, we loop over all destinations, run 'check(device, destination, expectedPaths)'
        for each, and aggregate results.
        """
        all_results = []
        for device_name, destinations in device_destinations.items():
            self.logger.info(f"Checking SCION showpaths for {device_name}...")
            for dest, exp_paths in destinations.items():
                all_results.extend(self.check(device_name, dest, exp_paths))
        return all_results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "protocols", "sciond", "paths"], configuration):
            self.logger.info("Checking SCION paths...")
            results.extend(self.run(configuration["test"]["protocols"]['sciond']['paths']))
        return results
