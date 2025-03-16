import re

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....model.CheckResult import CheckResult
from ....utils import get_output, key_exists


class AnnouncedVNICheck(AbstractCheck):
    def check(self, device_name: str, invert: bool = False) -> CheckResult:
        if not invert:
            self.description = f"Check that {device_name} announces all VNIs"
        else:
            self.description = f"Check that {device_name} not announces any VNIs"

        try:
            exec_output_gen = self.kathara_manager.exec(
                machine_name=device_name, command=f"vtysh -e 'show running-config bgpd'", lab_hash=self.lab.hash
            )
        except Exception as e:
            return CheckResult(self.description, False, str(e))

        output = get_output(exec_output_gen).splitlines()
        for line in output:
            if re.search(rf"\s*advertise-all-vni\s*", line):
                if invert:
                    return CheckResult(
                        self.description, False, f"`advertise-all-vni` found in `{device_name}` bgpd configuration"
                    )
                else:
                    return CheckResult(self.description, True, "OK")

        if invert:
            return CheckResult(self.description, True, "OK")
        else:
            return CheckResult(
                self.description, False, f"`advertise-all-vni` not found in `{device_name}` bgpd configuration"
            )

    def run(self, device_to_vnis_info: dict[str, dict], evpn_devices: list[str]) -> list[CheckResult]:
        results = []
        for device_name in device_to_vnis_info.keys():
            check_result = self.check(device_name)
            results.append(check_result)

        not_advertise = set(evpn_devices).difference(set(device_to_vnis_info.keys()))
        for device_name in not_advertise:
            check_result = self.check(device_name, invert=True)
            results.append(check_result)

        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "protocols", "bgpd", "evpn_sessions"], configuration) and \
                key_exists(["test", "protocols", "bgpd", "vtep_devices"], configuration):
            self.logger.info("Checking BGP VNIs configurations...")
            results.extend(self.run(configuration["test"]["protocols"]['bgpd']['vtep_devices'],
                                    configuration["test"]["protocols"]['bgpd']['evpn_sessions']))
        return results
