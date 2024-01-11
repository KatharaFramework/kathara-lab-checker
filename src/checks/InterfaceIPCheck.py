import ipaddress

from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


class InterfaceIPCheck(AbstractCheck):

    def run(self, device_name: str, interface_num: int, ip: str, dumped_iface: dict) -> CheckResult:
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
