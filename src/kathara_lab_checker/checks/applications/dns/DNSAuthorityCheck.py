import re
import jc

from Kathara.exceptions import MachineNotRunningError

from ...AbstractCheck import AbstractCheck
from ...CheckResult import CheckResult
from ....utils import get_output, find_lines_with_string, find_device_name_from_ip


class DNSAuthorityCheck(AbstractCheck):
    def check(self, domain: str, authority_ip: str, device_name: str, device_ip: str) -> CheckResult:
        self.description = f"Checking on `{device_name}` that `{authority_ip}` is the authority for domain `{domain}`"

        try:
            exec_output_gen = self.kathara_manager.exec(
                machine_name=device_name, command=f"dig NS {domain} @{device_ip}", lab_hash=self.lab.hash
            )
        except MachineNotRunningError as e:
            return CheckResult(self.description, False, str(e))

        output = get_output(exec_output_gen)
        if output.startswith("ERROR:"):
            return CheckResult(self.description, False, output)

        result = jc.parse("dig", output)
        if result:
            result = result.pop()
            if result["status"] == "NOERROR" and "answer" in result:
                root_servers = list(map(lambda x: x["data"].split(" ")[0], result["answer"]))
                authority_ips = []
                for root_server in root_servers:
                    exec_output_gen = self.kathara_manager.exec(
                        machine_name=device_name,
                        command=f"dig +short {root_server} @{device_ip}",
                        lab_hash=self.lab.hash,
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
                    f"with {result['status']} when quering for {domain}"
                )
                return CheckResult(self.description, False, reason)
        else:
            if self.lab.fs.exists(f"{device_name}.startup"):
                with self.lab.fs.open(f"{device_name}.startup", "r") as startup_file:
                    lines = startup_file.readlines()

                for line in lines:
                    line = line.strip()
                    if re.search(rf"^\s*systemctl\s*start\s*named\s*$", line):
                        exec_output_gen = self.kathara_manager.exec(
                            machine_name=device_name,
                            command=f"named -d 5 -g",
                            lab_hash=self.lab.hash,
                        )

                        output = get_output(exec_output_gen)
                        date_pattern = (
                            r"\d{2}-[Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec]{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d{3}"
                        )

                        reason_list = find_lines_with_string(output, "could not")
                        reason_list.extend(find_lines_with_string(output, "/etc/bind/named.conf"))
                        reason_list_no_dates = [re.sub(date_pattern, "", line) for line in reason_list]
                        reason = "\n".join(reason_list_no_dates)

                        return CheckResult(self.description, False, "Configuration Error:\n" + reason)

                reason = f"named not started in `{device_name}`.startup`"
                return CheckResult(self.description, False, reason)
            else:
                reason = f"There is no `.startup` file for device `{device_name}`"
                return CheckResult(self.description, False, reason)

    def run(
        self,
        zone_to_authoritative_ips: dict[str, list[str]],
        local_nameservers: list[str],
        ip_mapping: dict[str, dict[str, str]],
    ) -> list[CheckResult]:
        results = []
        for domain, name_servers in zone_to_authoritative_ips.items():
            self.logger.info(f"Checking authority ip for domain `{domain}`")
            for ns in name_servers:
                check_result = self.check(domain, ns, find_device_name_from_ip(ip_mapping, ns), ns)
                results.append(check_result)

                if domain == ".":
                    self.logger.info(
                        f"Checking if all the named servers can correctly resolve {ns} as the root nameserver..."
                    )
                    for generic_ns_ip in name_servers:
                        check_result = self.check(
                            domain, ns, find_device_name_from_ip(ip_mapping, generic_ns_ip), generic_ns_ip
                        )
                        results.append(check_result)

                    for local_ns in local_nameservers:
                        check_result = self.check(domain, ns, find_device_name_from_ip(ip_mapping, local_ns), local_ns)
                        results.append(check_result)
        return results
