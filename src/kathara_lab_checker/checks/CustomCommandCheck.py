import re

from Kathara.exceptions import MachineNotFoundError
from Kathara.model.Lab import Lab

from ..foundation.checks.AbstractCheck import AbstractCheck
from ..model.CheckResult import CheckResult
from ..utils import key_exists


class CustomCommandCheck(AbstractCheck):

    def __init__(self, lab: Lab, description: str = None):
        super().__init__(lab, description=description, priority=4000)

    def check(self, device_name: str, command_entry: dict[str, str | int]) -> list[CheckResult]:

        results = []
        try:
            device = self.lab.get_machine(device_name)
            stdout, stderr, exit_code = self.kathara_manager.exec(
                machine_name=device.name, lab_hash=self.lab.hash, command=command_entry["command"], stream=False
            )

            stdout = stdout.decode("utf-8").strip() if stdout else (stderr.decode("utf-8").strip() if stderr else "")

            if "exit_code" in command_entry:
                self.description = (
                    f"Checking the exit code of the command '{command_entry['command']}' on '{device_name}'"
                )
                if exit_code == command_entry["exit_code"]:
                    results.append(CheckResult(self.description, True, "OK"))
                else:
                    reason = (
                        f"The exit code of the command differs from the expected one."
                        f"\n Actual: {exit_code}\n Expected: {command_entry['exit_code']}"
                    )
                    results.append(CheckResult(self.description, False, reason))

            self.description = f"Checking the output of the command '{command_entry['command']}' on '{device_name}'"
            if "output" in command_entry:
                stdout = stdout.replace("\r\n", "\n").replace("\r", "\n")
                command_entry["output"] = command_entry["output"].replace("\r\n", "\n").replace("\r", "\n")

                if stdout == command_entry["output"].replace("\r\n", "\n").replace("\r", "\n"):
                    results.append(CheckResult(self.description, True, "OK"))
                else:
                    reason = (
                        f"The output of the command differs from the expected one."
                        f"\n Actual: {stdout}\n Expected: {command_entry['output']}"
                    )
                    results.append(CheckResult(self.description, False, reason))
            if "regex_match" in command_entry:

                if re.search(command_entry["regex_match"], stdout):
                    results.append(CheckResult(self.description, True, "OK"))
                else:
                    reason = (
                        f"The output of the command do not match the expected regex."
                        f"\n Actual: {stdout}\n Regex: {command_entry['regex_match']}"
                    )
                    results.append(CheckResult(self.description, False, reason))

        except MachineNotFoundError as e:
            results.append(CheckResult(self.description, False, str(e)))

        return results

    def run(self, devices_to_commands: dict[str, list[dict[str, str | int]]]) -> list[CheckResult]:
        results = []
        for device_name, command_entries in devices_to_commands.items():
            for command_entry in command_entries:
                check_result = self.check(device_name, command_entry)
                results.extend(check_result)
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "custom_commands"], configuration):
            self.logger.info("Checking custom commands output...")
            results.extend(self.run(configuration["test"]["custom_commands"]))
        return results
