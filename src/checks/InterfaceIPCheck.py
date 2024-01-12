import ipaddress

from Kathara.exceptions import MachineNotRunningError
from Kathara.model.Lab import Lab

from utils import get_interfaces_addresses
from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


class InterfaceIPCheck(AbstractCheck):

    def check(self, device_name: str, interface_num: int, ip: str, dumped_iface: dict) -> CheckResult:
        self.description = f"Verifying the IP address ({ip}) assigned to eth{interface_num} of {device_name}"

        try:
            iface_info = next(filter(lambda x: x["ifname"] == f"eth{interface_num}", dumped_iface))
        except StopIteration:
            return CheckResult(self.description, False,
                               f"Interface eth`{interface_num}` not found on `{device_name}`")

        ip_address = ipaddress.ip_interface(ip)

        prefix_len = int(ip_address.with_prefixlen.split("/")[1])

        assigned_ips = []
        if iface_info and "addr_info" in iface_info:
            for addr_info in iface_info["addr_info"]:
                assigned_ips.append(f"{addr_info['local']}/{addr_info['prefixlen']}")
                if addr_info["local"] == str(ip_address.ip):
                    if addr_info["prefixlen"] == prefix_len:
                        return CheckResult(self.description, True, "OK")
                    else:
                        reason = f"The IP address has a wrong netmask ({prefix_len})"
                        return CheckResult(self.description, False, reason)

        reason = (f"The interface `{iface_info['ifname']}` of `{device_name}` "
                  f"has the following IP addresses: {assigned_ips}`.")
        return CheckResult(self.description, False, reason)

    def run(self, ip_mapping: dict, lab: Lab) -> list[CheckResult]:
        results = []
        for device_name, iface_to_ips in ip_mapping.items():
            self.logger.info(f"Checking IPs for `{device_name}`...")
            try:
                dumped_iface = get_interfaces_addresses(device_name, lab)
                for interface_num, ip in iface_to_ips.items():
                    check_result = self.check(device_name, int(interface_num), ip, dumped_iface)
                    self.logger.info(check_result)
                    results.append(check_result)
            except MachineNotRunningError:
                self.logger.warning(f"`{device_name}` is not running. Skipping checks...")
        return results
