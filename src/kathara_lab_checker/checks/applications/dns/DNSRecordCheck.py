from Kathara.model.Lab import Lab

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....model.FailedCheck import FailedCheck
from ....model.SuccessfulCheck import SuccessfulCheck
from ....utils import get_output, reverse_dictionary, key_exists


class DNSRecordCheck(AbstractCheck):

    def __init__(self, lab: Lab, configuration: dict, description: str = None):
        super().__init__(lab, configuration, description=description, priority=3030)

    def run(
            self,
            records: dict[str, dict[str, list[str]]],
            machines_with_dns: list[str],
    ):
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
                        self.results.append(SuccessfulCheck("Checking correctness of DNS records", "OK"))
                    else:
                        self.results.append(FailedCheck(
                            "Checking correctness of DNS records",
                            f"{client} resolve {recordtype} {record} with IP {ip} instead of {addresses}",
                        ))

    def run_from_configuration(self):
        if key_exists(["test", "applications", "dns", "records"], self.configuration) and \
                key_exists(["test", "applications", "dns", "local_ns"], self.configuration):
            self.logger.info("Checking DNS records...")
            self.run(
                self.configuration["test"]["applications"]["dns"]["records"],
                reverse_dictionary(self.configuration["test"]["applications"]["dns"]["local_ns"]).keys(),
            )
