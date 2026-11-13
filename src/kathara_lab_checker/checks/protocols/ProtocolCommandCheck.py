from Kathara.model.Lab import Lab

from ...foundation.checks.AbstractCheck import AbstractCheck
from ...foundation.model.CheckResult import CheckResult
from ...model.FailedCheck import FailedCheck
from ...model.SuccessfulCheck import SuccessfulCheck
from ...utils import get_output, get_router_config_section, key_exists


def normalize(line: str) -> str:
    return " ".join(line.split())


class ProtocolCommandCheck(AbstractCheck):
    """
    Checks that a command is (or, with a leading `!`, is not) configured in the `router <protocol>` section
    of a device's running configuration. Lines are compared ignoring indentation and repeated whitespace.
    """

    def __init__(self, lab: Lab, description: str = None):
        super().__init__(lab, description=description, priority=1130)

    def check(self, device_name: str, daemon: str, command: str, section: list[str]) -> CheckResult:
        if command.startswith("!"):
            command = command[1:]
            invert = True
        else:
            invert = False
        command = normalize(command)
        self.description = (
            f"Checking that `{command}` is {'not ' if invert else ''}configured for {daemon} on `{device_name}`"
        )

        found = any(normalize(line) == command for line in section)
        if found ^ invert:
            return SuccessfulCheck(self.description)

        reason = f"`{command}` is {'' if invert else 'not '}configured in the {daemon} section of `{device_name}`."
        return FailedCheck(self.description, reason)

    def run(self, daemon: str, devices_to_commands: dict[str, list[str]]) -> list[CheckResult]:
        results = []
        for device_name, commands in devices_to_commands.items():
            self.logger.info(f"Checking {daemon} commands on {device_name}...")
            try:
                exec_output_gen = self.kathara_manager.exec(
                    machine_name=device_name,
                    command="vtysh -e 'show running-config'",
                    lab_hash=self.lab.hash,
                )
                section = get_router_config_section(get_output(exec_output_gen), daemon)
            except Exception as e:
                for command in commands:
                    self.description = f"Checking `{command.lstrip('!')}` for {daemon} on `{device_name}`"
                    results.append(FailedCheck(self.description, str(e)))
                continue

            for command in commands:
                results.append(self.check(device_name, daemon, command, section))
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "protocols"], configuration):
            for daemon_name in configuration["test"]["protocols"]:
                if key_exists(["test", "protocols", daemon_name, "commands"], configuration):
                    self.logger.info(f"Checking {daemon_name} configured commands...")
                    results.extend(self.run(daemon_name, configuration["test"]["protocols"][daemon_name]["commands"]))
        return results
