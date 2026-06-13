import json

from Kathara.exceptions import MachineNotRunningError
from Kathara.model.Lab import Lab

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....model.FailedCheck import FailedCheck
from ....model.SuccessfulCheck import SuccessfulCheck
from ....utils import get_output, key_exists


class VTEPCheck(AbstractCheck):

    def __init__(self, lab: Lab, configuration: dict, description: str = None):
        super().__init__(lab, configuration, description=description, priority=1040)

    def check(self, device_name: str, vni: str, vtep_ip: str):
        try:
            exec_output_gen = self.kathara_manager.exec(
                machine_name=device_name, command="ip -d -j link show type vxlan", lab_hash=self.lab.hash
            )
        except MachineNotRunningError as e:
            self.results.append(FailedCheck(self.description, str(e)))
            return

        output = get_output(exec_output_gen)

        if output.startswith("ERROR:") or "exec failed" in output:
            self.results.append(FailedCheck(self.description, output))
            return
        output = json.loads(output)

        for route in output:
            if route["linkinfo"]["info_data"]["id"] == int(vni):
                if route["linkinfo"]["info_data"]["local"] == vtep_ip:
                    self.results.append(SuccessfulCheck(self.description))
                else:
                    reason = (
                        f"VNI `{vni}` configured on device `{device_name}` with wrong "
                        f"VTEP IP {route['linkinfo']['info_data']['local']} (instead of {vtep_ip})"
                    )
                    self.results.append(FailedCheck(self.description, reason))
                return
        self.results.append(FailedCheck(self.description, f"VNI `{vni}` not configured on device `{device_name}`"))

    def run(self, device_to_vnis_info: dict[str, dict]):
        for device_name, vnis_info in device_to_vnis_info.items():
            self.logger.info(f"Checking {device_name} VTEP configuration...")
            vnis = vnis_info["vnis"]
            vtep_ip = vnis_info["ip"]
            for vni in vnis:
                self.description = f"Checking that `{device_name}` VTEP has vni `{vni}` with VTEP IP `{vtep_ip}`"
                self.check_with_timeout(device_name, vni, vtep_ip)

    def run_from_configuration(self):
        if key_exists(["test", "protocols", "bgpd", "vtep_devices"], self.configuration):
            self.logger.info("Checking VTEP devices configuration...")
            self.run(self.configuration["test"]["protocols"]['bgpd']['vtep_devices'])
