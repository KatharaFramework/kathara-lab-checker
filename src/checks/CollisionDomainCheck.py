from Kathara.exceptions import LinkNotFoundError
from Kathara.model import Link
from Kathara.model.Lab import Lab

from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


class CollisionDomainCheck(AbstractCheck):
    def run(self, cd_t: Link, lab: Lab) -> CheckResult:
        try:
            cd = lab.get_link(cd_t.name)
            if cd.machines.keys() != cd_t.machines.keys():
                reason = (
                    f"Devices connected to collision domain {cd.name} {list(cd.machines.keys())} "
                    f"are different from the one in the template {list(cd_t.machines.keys())}."
                )
                return CheckResult(self.description, False, reason)

            return CheckResult(self.description, True, "OK")
        except LinkNotFoundError as e:
            return CheckResult(self.description, False, str(e))
