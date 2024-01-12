from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

from utils import get_output
from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


class ReachabilityCheck(AbstractCheck):

    def check(self, device_name: str, destination: str, lab: Lab) -> CheckResult:
        self.description = f"Verifying `{destination}` reachability from device `{device_name}`"

        kathara_manager: Kathara = Kathara.get_instance()

        try:
            exec_output_gen = kathara_manager.exec(
                machine_name=device_name,
                command=f"bash -c 'ping -q -n -c 1 {destination}; echo $?'",
                lab_hash=lab.hash,
            )
        except Exception as e:
            return CheckResult(self.description, False, str(e))

        output = get_output(exec_output_gen)

        if output.splitlines()[-1] == "0":
            return CheckResult(self.description, True, "OK")
        else:
            reason = f"`{destination}` not reachable from device `{device_name}`."
            return CheckResult(self.description, False, reason)

    def run(self, devices_to_destinations: dict[str, list[str]], lab: Lab) -> list[CheckResult]:
        results = []
        for device_name, destinations in devices_to_destinations.items():
            for destination in destinations:
                check_result = self.check(device_name, destination, lab)
                self.logger.info(check_result)
                results.append(check_result)
        return results
