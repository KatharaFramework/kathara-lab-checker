from Kathara.exceptions import MachineNotFoundError
from Kathara.model.Machine import Machine

from ..foundation.checks.AbstractCheck import AbstractCheck
from ..model.CheckResult import CheckResult


class CollisionDomainCheck(AbstractCheck):
    def check(self, machine_t: Machine) -> list[CheckResult]:

        results = []
        try:
            machine = self.lab.get_machine(machine_t.name)
            for iface_num, interface_t in machine_t.interfaces.items():
                self.description = (
                    f"Checking the collision domain attached to interface `eth{iface_num}` of `{machine_t.name}`"
                )
                interface = machine.interfaces[iface_num]
                if interface_t.link.name != interface.link.name:
                    reason = (
                        f"Interface `{iface_num}` of device {machine_t.name} is connected to collision domain "
                        f"`{interface.link.name}` instead of `{interface_t.link.name}`"
                    )
                    results.append(CheckResult(self.description, False, reason))
                else:
                    results.append(CheckResult(self.description, True, "OK"))
        except KeyError:
            results.append(CheckResult(self.description, False, f"No interfaces found with name `eth{iface_num}`"))
        except MachineNotFoundError as e:
            self.description = f"Checking the collision domain attached to `{machine_t.name}`"
            results.append(CheckResult(self.description, False, str(e)))
        return results

    def run(self, template_machines: list[Machine]) -> list[CheckResult]:
        results = []
        for machine_t in template_machines:
            check_result = self.check(machine_t)
            results.extend(check_result)
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        self.logger.info("Checking collision domains...")
        return self.run(configuration['template_lab'].machines.values())
