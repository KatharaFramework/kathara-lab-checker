from ...AbstractCheck import AbstractCheck
from ...CheckResult import CheckResult
from ....utils import get_output


class DNSRecordCheck(AbstractCheck):

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
                        check_result
                    results.append(check_result)
        return results
