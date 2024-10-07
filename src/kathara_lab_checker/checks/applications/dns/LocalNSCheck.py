import re

from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

from kathara_lab_checker.checks.AbstractCheck import AbstractCheck
from kathara_lab_checker.checks.CheckResult import CheckResult
from kathara_lab_checker.utils import get_output


class LocalNSCheck(AbstractCheck):

    def check(self, local_ns_ip: str, device_name: str, lab: Lab) -> CheckResult:
        kathara_manager: Kathara = Kathara.get_instance()

        self.description = f"Checking that `{local_ns_ip}` is the local name server for device `{device_name}`"

        exec_output_gen = kathara_manager.exec(
            machine_name=device_name, command=f"cat /etc/resolv.conf", lab_hash=lab.hash
        )
        output = get_output(exec_output_gen)
        if output.startswith("ERROR:"):
            return CheckResult(self.description, False, output)

        lines = output.splitlines()
        if not lines:
            reason = f"`resolv.conf` file not found for device `{device_name}`"
            return CheckResult(self.description, False, reason)
        for line in lines:
            if re.search(rf"^nameserver {local_ns_ip}$", line):
                return CheckResult(self.description, True, "OK")
            else:
                reason = f"The local name server for device `{device_name}` has ip `{local_ns_ip}`"
                return CheckResult(self.description, False, reason)

    def run(self, local_nameservers_to_devices: dict[str, list[str]], lab: Lab) -> list[CheckResult]:
        results = []
        for local_ns, managed_devices in local_nameservers_to_devices.items():
            for device_name in managed_devices:
                check_result = self.check(local_ns, device_name, lab)
                results.append(check_result)
        return results
