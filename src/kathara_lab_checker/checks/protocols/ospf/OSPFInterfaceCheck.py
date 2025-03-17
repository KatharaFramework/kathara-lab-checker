import json

from Kathara.exceptions import MachineNotRunningError
from Kathara.model.Lab import Lab

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....model.CheckResult import CheckResult
from ....utils import key_exists


class OSPFInterfaceCheck(AbstractCheck):

    def __init__(self, lab: Lab, description: str = None):
        super().__init__(lab, description=description, priority=1080)

    def check(self, device_name: str, interface_name: str, expected: dict) -> list[CheckResult]:
        results = []
        base_desc = f"OSPF interface {interface_name} on {device_name}"
        try:
            stdout, stderr, exit_code = self.kathara_manager.exec(
                machine_name=device_name,
                command="vtysh -e 'show ip ospf interface json'",
                lab_hash=self.lab.hash,
                stream=False
            )
        except MachineNotRunningError as e:
            return [CheckResult(base_desc, False, str(e))]

        output = stdout.decode("utf-8") if stdout else ""
        if stderr or exit_code != 0:
            err_msg = stderr.decode("utf-8") if stderr else f"Exit code: {exit_code}"
            return [CheckResult(base_desc, False, err_msg)]

        try:
            data = json.loads(output)
        except Exception as e:
            return [CheckResult(base_desc, False, f"JSON parse error: {str(e)}")]

        interfaces = data.get("interfaces", {})
        if interface_name not in interfaces:
            results.append(CheckResult(base_desc, False, f"Interface {interface_name} not found"))
            return results

        iface = interfaces[interface_name]
        for key, expected_value in expected.items():
            actual_value = iface.get(key)
            desc = f"{base_desc}: {key}"
            if actual_value != expected_value:
                results.append(CheckResult(desc, False, f"Expected {expected_value}, got {actual_value}"))
            else:
                results.append(CheckResult(desc, True, "OK"))
        return results

    def run(self, device_to_interface_expected: dict[str, dict[str, dict]]) -> list[CheckResult]:
        results = []
        for device_name, iface_dict in device_to_interface_expected.items():
            self.logger.info(f"Checking OSPF interface parameters for {device_name}...")
            for iface_name, expected in iface_dict.items():
                results.extend(self.check(device_name, iface_name, expected))
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "protocols", "ospfd", "interfaces"], configuration):
            self.logger.info("Checking OSPF interface parameters...")
            results.extend(self.run(configuration["test"]["protocols"]['ospfd']['interfaces']))
        return results
