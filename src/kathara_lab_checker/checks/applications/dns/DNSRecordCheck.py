from Kathara.model.Lab import Lab

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....model.CheckResult import CheckResult
from ....utils import get_output, reverse_dictionary, key_exists


class DNSRecordCheck(AbstractCheck):

    def __init__(self, lab: Lab, description: str = None):
        super().__init__(lab, description=description, priority=3030)

    def run(
            self,
            records: dict[str, dict[str, list[str]]],
            machines_with_dns: list[str],
    ) -> list[CheckResult]:
        results = []

        for recordtype, recordvalue in records.items():
            for record, addresses in recordvalue.items():
                for client in machines_with_dns:
                    exec_output_gen = self.kathara_manager.exec(
                        machine_name=client,
                        command=f"dig +short {recordtype} {record}",
                        lab_hash=self.lab.hash,
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
                    results.append(check_result)
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "applications", "dns", "records"], configuration) and \
                key_exists(["test", "applications", "dns", "local_ns"], configuration):
            self.logger.info("Checking DNS records...")
            results.extend(self.run(
                configuration["test"]["applications"]["dns"]["records"],
                reverse_dictionary(configuration["test"]["applications"]["dns"]["local_ns"]).keys(),
            ))
        return results
