from Kathara.exceptions import MachineNotFoundError
from Kathara.model.Lab import Lab

from ..foundation.checks.AbstractCheck import AbstractCheck
from ..model.FailedCheck import FailedCheck
from ..model.SuccessfulCheck import SuccessfulCheck
from ..utils import get_output, key_exists


class DaemonCheck(AbstractCheck):

    def __init__(self, lab: Lab, configuration: dict, description: str = None):
        super().__init__(lab, configuration, description=description, priority=80)

    def check(self, device_name: str, daemon: str):

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
                self.results.append(SuccessfulCheck(self.description))
            else:
                reason = f"Daemon {daemon} is {'' if invert else 'not '}running on device `{device_name}`"
                self.results.append(FailedCheck(self.description, reason))
        except MachineNotFoundError as e:
            self.results.append(FailedCheck(self.description, str(e)))

    def run(self, devices_to_daemons: dict[str, list[str]]):
        for device_name, daemons in devices_to_daemons.items():
            self.logger.info(f"Checking running daemons on `{device_name}`...")
            for daemon_name in daemons:
                self.check_with_timeout(device_name, daemon_name)

    def run_from_configuration(self):
        if key_exists(["test", "daemons"], self.configuration):
            self.logger.info(f"Checking running daemons...")
            self.run(self.configuration["test"]["daemons"])
