import re

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....model.CheckResult import CheckResult
from ....utils import get_output, key_exists


class LocalNSCheck(AbstractCheck):

    def check(self, local_ns_ip: str, device_name: str) -> CheckResult:
        self.description = f"Checking that `{local_ns_ip}` is the local name server for device `{device_name}`"

        exec_output_gen = self.kathara_manager.exec(
            machine_name=device_name, command=f"cat /etc/resolv.conf", lab_hash=self.lab.hash
        )
        output = get_output(exec_output_gen)
        if output.startswith("ERROR:"):
            return CheckResult(self.description, False, output)

        lines = output.splitlines()
        if not lines:
            reason = f"`resolv.conf` file not found for device `{device_name}`"
            return CheckResult(self.description, False, reason)
        actual_ips = []
        for line in lines:
            match = re.search(rf"^nameserver (.*)$", line)
            if match:
                actual_ns_ip = match.group(1)
                if actual_ns_ip == local_ns_ip:
                    return CheckResult(self.description, True, "OK")
                actual_ips.append(actual_ns_ip)

        reason = (
            f"There is no local name server for device `{device_name}` with IP `{local_ns_ip}`. "
            f"Actual nameservers: {actual_ips}"
        )
        return CheckResult(self.description, False, reason)

    def run(self, local_nameservers_to_devices: dict[str, list[str]]) -> list[CheckResult]:
        results = []
        for local_ns, managed_devices in local_nameservers_to_devices.items():
            for device_name in managed_devices:
                check_result = self.check(local_ns, device_name)
                results.append(check_result)
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "applications", "dns", "local_ns"], configuration):
            self.logger.info("Checking local name servers configurations...")
            results.extend(self.run(configuration["test"]["applications"]["dns"]["local_ns"]))
        return results
