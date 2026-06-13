import jc
from Kathara.model.Lab import Lab

from ..foundation.checks.AbstractCheck import AbstractCheck
from ..foundation.model.CheckResult import CheckResult
from ..model.FailedCheck import FailedCheck
from ..model.SuccessfulCheck import SuccessfulCheck
from ..utils import get_output, key_exists


class ReachabilityCheck(AbstractCheck):

    def __init__(self, lab: Lab, configuration: dict, description: str = None):
        super().__init__(lab, configuration, description=description, priority=70)

    def check(self, device_name: str, destination: str):

        if destination.startswith("!"):
            destination = destination[1:]
            self.description = f"Verifying `{destination}` not reachable from device `{device_name}`"
            invert = True
        else:
            self.description = f"Verifying `{destination}` reachable from device `{device_name}`"
            invert = False

        try:
            exec_output_gen = self.kathara_manager.exec(
                machine_name=device_name,
                command=f"bash -c 'ping -q -n -c 1 {destination}'",
                lab_hash=self.lab.hash,
            )
        except Exception as e:
            self.results.append(CheckResult(self.description, invert ^ False, str(e)))
            return

        output = get_output(exec_output_gen).replace("ERROR: ", "")

        try:
            parsed_output = jc.parse("ping", output, quiet=True)
            if int(parsed_output["packets_received"]) > 0:
                if invert:
                    self.results.append(FailedCheck(self.description, f"`{device_name}` can reach `{destination}`."))
                else:
                    self.results.append(SuccessfulCheck(self.description))
            else:
                if invert:
                    self.results.append(SuccessfulCheck(self.description))
                else:
                    self.results.append(FailedCheck(self.description,
                                       f"`{device_name}` does not receive any answer from `{destination}`."))
        except Exception:
            self.results.append(CheckResult(self.description, invert ^ False, output.strip()))

    def run(self, devices_to_destinations: dict[str, list[str]]):
        for device_name, destinations in devices_to_destinations.items():
            for destination in destinations:
                self.check_with_timeout(device_name, destination)

    def run_from_configuration(self):
        if key_exists(["test", "reachability"], self.configuration):
            self.logger.info(f"Starting reachability test...")
            self.run(self.configuration["test"]["reachability"])
