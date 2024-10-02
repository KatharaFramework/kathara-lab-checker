from kathara_lab_checker.checks.AbstractCheck import AbstractCheck
from kathara_lab_checker.checks.CheckResult import CheckResult
from Kathara.model.Lab import Lab
from Kathara.manager.Kathara import Kathara

from kathara_lab_checker.utils import get_output


class DNSRecordCheck(AbstractCheck):

    def run(
        self,
        records: dict[str, dict[str, list[str]]],
        machines_with_dns: list[str],
        lab: Lab,
    ) -> list[CheckResult]:
        results = []
        kathara_manager: Kathara = Kathara.get_instance()

        for recordtype, recordvalue in records.items():
            for record, addresses in recordvalue.items():
                for client in machines_with_dns:
                    exec_output_gen = kathara_manager.exec(
                        machine_name=client,
                        command=f"dig +short {recordtype} {record}",
                        lab_hash=lab.hash,
                    )
                    ip = get_output(exec_output_gen).strip()
                    if ip in addresses:
                        check_result = CheckResult("Checking correctness of DNS records", True, "OK")
                    else:
                        check_result = CheckResult(
                            "Checking correctness of DNS records",
                            False,
                            f"{client} resolve {recordtype} {record} with IP {ip} instead of {addresses}",
                        )
                        check_result
                    self.logger.info(check_result)
                    results.append(check_result)
        return results
