import re

from Kathara.model.Lab import Lab

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....model.FailedCheck import FailedCheck
from ....model.SuccessfulCheck import SuccessfulCheck
from ....utils import get_output, key_exists


class AnnouncedVNICheck(AbstractCheck):

    def __init__(self, lab: Lab, configuration: dict, description: str = None):
        super().__init__(lab, configuration, description=description, priority=1050)

    def check(self, device_name: str, invert: bool = False):
        if not invert:
            self.description = f"Check that {device_name} announces all VNIs"
        else:
            self.description = f"Check that {device_name} not announces any VNIs"

        try:
            exec_output_gen = self.kathara_manager.exec(
                machine_name=device_name, command=f"vtysh -e 'show running-config bgpd'", lab_hash=self.lab.hash
            )
        except Exception as e:
            self.results.append(FailedCheck(self.description, str(e)))
            return

        output = get_output(exec_output_gen).splitlines()
        for line in output:
            if re.search(rf"\s*advertise-all-vni\s*", line):
                if invert:
                    self.results.append(FailedCheck(
                        self.description, f"`advertise-all-vni` found in `{device_name}` bgpd configuration"
                    ))
                else:
                    self.results.append(SuccessfulCheck(self.description))
                return

        if invert:
            self.results.append(SuccessfulCheck(self.description))
        else:
            self.results.append(FailedCheck(
                self.description, f"`advertise-all-vni` not found in `{device_name}` bgpd configuration"
            ))

    def run(self, device_to_vnis_info: dict[str, dict], evpn_devices: list[str]):
        for device_name in device_to_vnis_info.keys():
            self.check_with_timeout(device_name)

        not_advertise = set(evpn_devices).difference(set(device_to_vnis_info.keys()))
        for device_name in not_advertise:
            self.check_with_timeout(device_name, invert=True)

    def run_from_configuration(self):
        if key_exists(["test", "protocols", "bgpd", "evpn_sessions"], self.configuration) and \
                key_exists(["test", "protocols", "bgpd", "vtep_devices"], self.configuration):
            self.logger.info("Checking BGP VNIs configurations...")
            self.run(self.configuration["test"]["protocols"]['bgpd']['vtep_devices'],
                     self.configuration["test"]["protocols"]['bgpd']['evpn_sessions'])
