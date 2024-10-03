import re

from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

from kathara_lab_checker.checks.AbstractCheck import AbstractCheck
from kathara_lab_checker.checks.CheckResult import CheckResult
from kathara_lab_checker.utils import get_output


class ProtocolRedistributionCheck(AbstractCheck):

    def check(self, device_name: str, protocol_to_check: str, injected_protocol: str, lab: Lab) -> CheckResult:
        kathara_manager: Kathara = Kathara.get_instance()

        if injected_protocol.startswith("!"):
            injected_protocol = injected_protocol[1:]
            self.description = f"Checking that {injected_protocol} routes are not redistributed to {protocol_to_check} on device `{device_name}`"
            invert = True
        else:
            self.description = f"Checking that {injected_protocol} routes are redistributed to {protocol_to_check} on device `{device_name}`"
            invert = False

        try:
            exec_output_gen = kathara_manager.exec(
                machine_name=device_name,
                command=f"vtysh -e 'show running-config {protocol_to_check}'",
                lab_hash=lab.hash,
            )
        except Exception as e:
            return CheckResult(self.description, False, str(e))

        output = get_output(exec_output_gen).split("\n")
        found = False
        for line in output:
            if re.search(rf"^\s*redistribute\s*{injected_protocol}$", line):
                found = True
                break
        if found ^ invert:
            return CheckResult(self.description, True, "OK")
        else:
            reason = f"{injected_protocol} routes are {'' if invert else 'not '}injected into `{protocol_to_check}` on `{device_name}`."
        return CheckResult(self.description, False, reason)

    def run(self, protocol, devices_to_redistributed: dict[str, list[str]], lab: Lab) -> list[CheckResult]:
        results = []
        for device_name, injected_protocols in devices_to_redistributed.items():
            for injected_protocol in injected_protocols:
                check_result = self.check(device_name, protocol, injected_protocol, lab)
                self.logger.info(check_result)
                results.append(check_result)
        return results
