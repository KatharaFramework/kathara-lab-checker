import re

from Kathara.model.Lab import Lab

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....model.FailedCheck import FailedCheck
from ....model.SuccessfulCheck import SuccessfulCheck
from ....utils import get_output, key_exists


class LocalNSCheck(AbstractCheck):

    def __init__(self, lab: Lab, configuration: dict, description: str = None):
        super().__init__(lab, configuration, description=description, priority=3020)

    def check(self, local_ns_ip: str, device_name: str):
        self.description = f"Checking that `{local_ns_ip}` is the local name server for device `{device_name}`"

        exec_output_gen = self.kathara_manager.exec(
            machine_name=device_name, command=f"cat /etc/resolv.conf", lab_hash=self.lab.hash
        )
        output = get_output(exec_output_gen)
        if output.startswith("ERROR:"):
            self.results.append(FailedCheck(self.description, output))
            return

        lines = output.splitlines()
        if not lines:
            reason = f"`resolv.conf` file not found for device `{device_name}`"
            self.results.append(FailedCheck(self.description, reason))
            return
        actual_ips = []
        for line in lines:
            match = re.search(rf"^nameserver (.*)$", line)
            if match:
                actual_ns_ip = match.group(1)
                if actual_ns_ip == local_ns_ip:
                    self.results.append(SuccessfulCheck(self.description))
                    return
                actual_ips.append(actual_ns_ip)

        reason = (
            f"There is no local name server for device `{device_name}` with IP `{local_ns_ip}`. "
            f"Actual nameservers: {actual_ips}"
        )
        self.results.append(FailedCheck(self.description, reason))

    def run(self, local_nameservers_to_devices: dict[str, list[str]]):
        for local_ns, managed_devices in local_nameservers_to_devices.items():
            for device_name in managed_devices:
                self.check_with_timeout(local_ns, device_name)

    def run_from_configuration(self):
        if key_exists(["test", "applications", "dns", "local_ns"], self.configuration):
            self.logger.info("Checking local name servers configurations...")
            self.run(self.configuration["test"]["applications"]["dns"]["local_ns"])
