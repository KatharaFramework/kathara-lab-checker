import re

import jc
from Kathara.exceptions import MachineNotRunningError
from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

from kathara_lab_checker.checks.AbstractCheck import AbstractCheck
from kathara_lab_checker.checks.CheckResult import CheckResult
from kathara_lab_checker.utils import get_output, find_lines_with_string, find_device_name_from_ip


class DNSAuthorityCheck(AbstractCheck):
    def check(
            self, domain: str, authority_ip: str, device_name: str, device_ip: str, lab: Lab
    ) -> CheckResult:
        self.description = (
            f"Checking on `{device_name}` that `{authority_ip}` is the authority for domain `{domain}`"
        )
        kathara_manager: Kathara = Kathara.get_instance()
        try:
            exec_output_gen = kathara_manager.exec(
                machine_name=device_name, command=f"dig NS {domain} @{device_ip}", lab_hash=lab.hash
            )
        except MachineNotRunningError as e:
            return CheckResult(self.description, False, str(e))

        output = get_output(exec_output_gen)
        if output.startswith("ERROR:"):
            return CheckResult(self.description, False, output)

        result = jc.parse("dig", output)
        if result:
            if result[0]["status"] == "NOERROR":
                result = result.pop()
                root_servers = list(map(lambda x: x["data"].split(" ")[0], result["answer"]))
                authority_ips = []
                for root_server in root_servers:
                    exec_output_gen = kathara_manager.exec(
                        machine_name=device_name,
                        command=f"dig +short {root_server} @{device_ip}",
                        lab_hash=lab.hash,
                    )
                    ip = get_output(exec_output_gen).strip()
                    if authority_ip == ip:
                        return CheckResult(self.description, True, "OK")
                    else:
                        authority_ips.append(ip)
                reason = f"The dns authorities for domain `{domain}` have the following IPs {authority_ips}"
                return CheckResult(self.description, False, reason)
            else:
                reason = (
                    f"named on {device_name} is running but answered "
                    f"with {result[0]['status']} when quering for {domain}"
                )
                return CheckResult(self.description, False, reason)
        else:
            with lab.fs.open(f"{device_name}.startup", "r") as startup_file:
                systemctl_lines = find_lines_with_string(startup_file.readline(), "systemctl")

            for line in systemctl_lines:
                if re.search(rf"^\s*systemctl\s*start\s*named\s*$", line):
                    exec_output_gen = kathara_manager.exec(
                        machine_name=device_name,
                        command=f"named -d 5 -g",
                        lab_hash=lab.hash,
                    )

                    output = get_output(exec_output_gen)

                    date_pattern = r"\d{2}-[Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec]{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d{3}"

                    reason_list = find_lines_with_string(output, "could not")
                    reason_list_no_dates = [re.sub(date_pattern, "", line) for line in reason_list]
                    reason = "\n".join(reason_list_no_dates)

                    return CheckResult(self.description, False, reason)

            reason = f"named not started in the startup file of `{device_name}`"
            return CheckResult(self.description, False, reason)

    def run(
            self,
            zone_to_authoritative_ips: dict[str, list[str]],
            local_nameservers: list[str],
            ip_mapping: dict[str, dict[str, str]],
            lab: Lab,
    ) -> list[CheckResult]:
        results = []
        for domain, name_servers in zone_to_authoritative_ips.items():
            self.logger.info(f"Checking authority ip for domain `{domain}`")
            for ns in name_servers:
                check_result = self.check(domain, ns, find_device_name_from_ip(ip_mapping, ns), ns, lab)
                results.append(check_result)

                if domain == ".":
                    self.logger.info(
                        f"Checking if all the named servers can correctly resolve {ns} as the root nameserver..."
                    )
                    for generic_ns_ip in name_servers:
                        check_result = self.check(
                            domain,
                            ns,
                            find_device_name_from_ip(ip_mapping, generic_ns_ip),
                            generic_ns_ip,
                            lab,
                        )
                        results.append(check_result)

                    for local_ns in local_nameservers:
                        check_result = self.check(
                            domain, ns, find_device_name_from_ip(ip_mapping, local_ns), local_ns, lab
                        )
                        results.append(check_result)
        return results
