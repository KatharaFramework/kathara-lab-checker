from Kathara.exceptions import MachineNotFoundError
from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

from utils import get_output
from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


class DaemonCheck(AbstractCheck):

    def check(self, device_name: str, daemon: str, lab: Lab) -> CheckResult:
        kathara_manager: Kathara = Kathara.get_instance()

        if daemon.startswith("!"):
            daemon = daemon[1:]
            self.description = f"Checking that {daemon} is not running on device `{device_name}`"
            invert = True
        else:
            self.description = f"Checking that {daemon} is running on device `{device_name}`"
            invert = False

        try:
            device = lab.get_machine(device_name)
            output = get_output(
                kathara_manager.exec(machine_name=device.name, lab_hash=lab.hash, command=f"pgrep {daemon}")
            )
            if (output != "") ^ invert:
                return CheckResult(self.description, True, "OK")
            else:
                reason = f"Daemon {daemon} is {'' if invert else 'not '}running on device `{device_name}`"
                return CheckResult(self.description, False, reason)
        except MachineNotFoundError as e:
            return CheckResult(self.description, False, str(e))

    def run(self, devices_to_daemons: dict[str, list[str]], lab: Lab) -> list[CheckResult]:
        results = []
        for device_name, daemons in devices_to_daemons.items():
            self.logger.info(f"Checking if daemons are running on {device_name}")
            for daemon_name in daemons:
                check_result = self.check(device_name, daemon_name, lab)
                self.logger.info(check_result)
                results.append(check_result)
        return results