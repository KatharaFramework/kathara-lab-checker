from Kathara.exceptions import MachineNotFoundError
from Kathara.model.Lab import Lab

from ..foundation.checks.AbstractCheck import AbstractCheck
from ..model.FailedCheck import FailedCheck
from ..model.SuccessfulCheck import SuccessfulCheck


class DeviceExistenceCheck(AbstractCheck):

    def __init__(self, lab: Lab, configuration: dict, description: str = None):
        super().__init__(lab, configuration, description=description, priority=0)


    def check(self, device_name: str):
        self.description = f"Check existence of `{device_name}`"
        try:
            self.lab.get_machine(device_name)
        except MachineNotFoundError as e:
            self.results.append(FailedCheck(self.description, str(e)))
            return

        self.results.append(SuccessfulCheck(self.description))

    def run(self, template_machines: list[str]):
        for device_name in template_machines:
            self.check_with_timeout(device_name)

    def run_from_configuration(self):
        self.logger.info("Checking devices existence...")
        self.run(self.configuration['template_lab'].machines.keys())
