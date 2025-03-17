from Kathara.exceptions import MachineNotFoundError
from Kathara.model.Lab import Lab

from ..foundation.checks.AbstractCheck import AbstractCheck
from ..model.CheckResult import CheckResult
from ..utils import get_output, key_exists


class DaemonCheck(AbstractCheck):

    def __init__(self, lab: Lab, description: str = None):
        super().__init__(lab, description=description, priority=80)

    def check(self, device_name: str, daemon: str) -> CheckResult:

        if daemon.startswith("!"):
            daemon = daemon[1:]
            self.description = f"Checking that {daemon} is not running on device `{device_name}`"
            invert = True
        else:
            self.description = f"Checking that {daemon} is running on device `{device_name}`"
            invert = False

        try:
            device = self.lab.get_machine(device_name)
            output = get_output(
                self.kathara_manager.exec(machine_name=device.name, lab_hash=self.lab.hash, command=f"pgrep {daemon}")
            )
            if (output != "") ^ invert:
                return CheckResult(self.description, True, "OK")
            else:
                reason = f"Daemon {daemon} is {'' if invert else 'not '}running on device `{device_name}`"
                return CheckResult(self.description, False, reason)
        except MachineNotFoundError as e:
            return CheckResult(self.description, False, str(e))

    def run(self, devices_to_daemons: dict[str, list[str]]) -> list[CheckResult]:
        results = []
        for device_name, daemons in devices_to_daemons.items():
            self.logger.info(f"Checking running daemons on `{device_name}`...")
            for daemon_name in daemons:
                check_result = self.check(device_name, daemon_name)
                results.append(check_result)
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "daemons"], configuration):
            self.logger.info(f"Checking running daemons...")
            results.extend(self.run(configuration["test"]["daemons"]))
        return results
