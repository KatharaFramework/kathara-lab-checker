import json

from Kathara.exceptions import MachineNotRunningError

from ...AbstractCheck import AbstractCheck
from ....model.CheckResult import CheckResult
from ....utils import get_output


class VTEPCheck(AbstractCheck):
    def check(self, device_name: str, vni: str, vtep_ip: str) -> CheckResult:
        try:
            exec_output_gen = self.kathara_manager.exec(
                machine_name=device_name, command="ip -d -j link show type vxlan", lab_hash=self.lab.hash
            )
        except MachineNotRunningError as e:
            return CheckResult(self.description, False, str(e))

        output = get_output(exec_output_gen)

        if output.startswith("ERROR:") or "exec failed" in output:
            return CheckResult(self.description, False, output)
        output = json.loads(output)

        for route in output:
            if route["linkinfo"]["info_data"]["id"] == int(vni):
                if route["linkinfo"]["info_data"]["local"] == vtep_ip:
                    return CheckResult(self.description, True, "OK")
                else:
                    reason = (
                        f"VNI `{vni}` configured on device `{device_name}` with wrong "
                        f"VTEP IP {route['linkinfo']['info_data']['local']} (instead of {vtep_ip})"
                    )
                    return CheckResult(self.description, False, reason)
        return CheckResult(self.description, False, f"VNI `{vni}` not configured on device `{device_name}`")

    def run(self, device_to_vnis_info: dict[str, dict]) -> list[CheckResult]:
        results = []
        for device_name, vnis_info in device_to_vnis_info.items():
            self.logger.info(f"Checking {device_name} VTEP configuration...")
            vnis = vnis_info["vnis"]
            vtep_ip = vnis_info["ip"]
            for vni in vnis:
                self.description = f"Checking that `{device_name}` VTEP has vni `{vni}` with VTEP IP `{vtep_ip}`"
                check_result = self.check(device_name, vni, vtep_ip)
                results.append(check_result)
        return results
