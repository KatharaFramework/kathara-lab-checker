import jc
from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

from kathara_lab_checker.utils import get_output
from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


class ReachabilityCheck(AbstractCheck):

    def check(self, device_name: str, destination: str, lab: Lab) -> CheckResult:
        kathara_manager: Kathara = Kathara.get_instance()

        if destination.startswith("!"):
            destination = destination[1:]
            self.description = f"Verifying `{destination}` not reachable from device `{device_name}`"
            invert = True
        else:
            self.description = f"Verifying `{destination}` reachable from device `{device_name}`"
            invert = False

        try:
            exec_output_gen = kathara_manager.exec(
                machine_name=device_name,
                command=f"bash -c 'ping -q -n -c 1 {destination}'",
                lab_hash=lab.hash,
            )
        except Exception as e:
            return CheckResult(self.description, invert ^ False, str(e))

        output = get_output(exec_output_gen).replace("ERROR: ", "")

        try:
            parsed_output = jc.parse("ping", output)
            if int(parsed_output['packets_received']) > 0:
                reason = f"`{device_name}` can reach `{destination}`." if invert else "OK"
                return CheckResult(self.description, invert ^ True, reason)
            else:
                reason = "OK" if invert else f"`{device_name}` does not receive any answer from `{destination}`."
                return CheckResult(self.description, invert ^ False, reason)
        except Exception:
            return CheckResult(self.description, False, output.strip())

    def run(self, devices_to_destinations: dict[str, list[str]], lab: Lab) -> list[CheckResult]:
        results = []
        for device_name, destinations in devices_to_destinations.items():
            for destination in destinations:
                check_result = self.check(device_name, destination, lab)
                self.logger.info(check_result)
                results.append(check_result)
        return results
