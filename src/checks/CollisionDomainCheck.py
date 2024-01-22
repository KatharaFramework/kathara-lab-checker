from Kathara.exceptions import LinkNotFoundError
from Kathara.model import Link
from Kathara.model.Lab import Lab

from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


class CollisionDomainCheck(AbstractCheck):
    def check(self, cd_t: Link, lab: Lab) -> CheckResult:
        self.description = f"Checking collision domain `{cd_t.name}`"

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

    def run(self, template_cds: list[Link], lab: Lab) -> list[CheckResult]:
        results = []
        for cd_t in template_cds:
            check_result = self.check(cd_t, lab)
            self.logger.info(check_result)
            results.append(check_result)
        return results