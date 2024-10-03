import re

from Kathara.exceptions import MachineNotFoundError
from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


class CustomCommandCheck(AbstractCheck):

    def check(self, device_name: str, command_entry: dict[str, str | int], lab: Lab) -> list[CheckResult]:
        kathara_manager: Kathara = Kathara.get_instance()

        self.description = f"Checking the output of the command '{command_entry['command']}' on '{device_name}'"
        results = []
        try:
            device = lab.get_machine(device_name)
            stdout, stderr, exit_code = kathara_manager.exec(machine_name=device.name, lab_hash=lab.hash,
                                                             command=command_entry["command"], stream=False)
            stdout = stdout.decode("utf-8").strip()
            if "exit_code" in command_entry:
                if exit_code == command_entry["exit_code"]:
                    results.append(CheckResult(self.description, True, "OK"))
                else:
                    reason = (f"The exit_code of the command differs from the expected one."
                              f"\nActual: {exit_code}\nExpected: {command_entry['exit_code']}")
                    results.append(CheckResult(self.description, False, reason))

            if "output" in command_entry:
                if stdout == command_entry["output"]:
                    results.append(CheckResult(self.description, True, "OK"))
                else:
                    reason = (f"The output of the command differs from the expected one."
                              f"\nActual: {stdout}\nExpected: {command_entry['output']}")
                    results.append(CheckResult(self.description, False, reason))
            if "regex_match" in command_entry:
                if re.match(command_entry["regex_match"], stdout):
                    results.append(CheckResult(self.description, True, "OK"))
                else:
                    reason = (f"The output of the command do not match the expected regex."
                              f"\nActual: {stdout}\nRegex: {command_entry['regex_match']}")
                    results.append(CheckResult(self.description, False, reason))

        except MachineNotFoundError as e:
            results.append(CheckResult(self.description, False, str(e)))

        return results

    def run(self, devices_to_commands: dict[str, list[dict[str, str | int]]], lab: Lab) -> list[CheckResult]:
        results = []
        for device_name, command_entries in devices_to_commands.items():
            for command_entry in command_entries:
                check_result = self.check(device_name, command_entry, lab)
                results.extend(check_result)
        return results
