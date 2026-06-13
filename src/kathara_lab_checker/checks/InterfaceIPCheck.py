import ipaddress
import json

from Kathara.exceptions import MachineNotRunningError
from Kathara.model.Lab import Lab

from ..foundation.checks.AbstractCheck import AbstractCheck
from ..model.FailedCheck import FailedCheck
from ..model.SuccessfulCheck import SuccessfulCheck
from ..utils import key_exists


class InterfaceIPCheck(AbstractCheck):

    def __init__(self, lab: Lab, configuration: dict, description: str = None):
        super().__init__(lab, configuration, description=description, priority=50)

    def check(self, device_name: str, interface_number: int, ip: str, dumped_iface: dict):
        interface_name = f"eth{interface_number}" if interface_number.isnumeric() else interface_number
        self.description = f"Verifying the IP address ({ip}) assigned to {interface_name} of {device_name}"

        try:
            iface_info = next(filter(lambda x: x["ifname"] == f"{interface_name}", dumped_iface))
        except StopIteration:
            self.results.append(FailedCheck(self.description, f"Interface `{interface_name}` not found on `{device_name}`"))
            return

        ip_address = ipaddress.ip_interface(ip)

        prefix_len = int(ip_address.with_prefixlen.split("/")[1])

        assigned_ips = []
        if iface_info and "addr_info" in iface_info:
            for addr_info in iface_info["addr_info"]:
                assigned_ips.append(f"{addr_info['local']}/{addr_info['prefixlen']}")
                if addr_info["local"] == str(ip_address.ip):
                    if addr_info["prefixlen"] == prefix_len:
                        self.results.append(SuccessfulCheck(self.description))
                        return
                    else:
                        reason = f"The IP address has a wrong netmask ({addr_info['prefixlen']})"
                        self.results.append(FailedCheck(self.description, reason))
                        return

        reason = (
            f"The interface `{iface_info['ifname']}` of `{device_name}` "
            f"has the following IP addresses: {assigned_ips}`."
        )
        self.results.append(FailedCheck(self.description, reason))

    def get_interfaces_addresses(self, device_name: str) -> dict:

        stdout, _, _ = self.kathara_manager.exec(
            machine_name=device_name, command=f"ip -j address", lab_hash=self.lab.hash, stream=False
        )

        return json.loads(stdout)

    def run(self, ip_mapping: dict):
        for device_name, iface_to_ips in ip_mapping.items():
            self.logger.info(f"Checking IPs for `{device_name}`...")
            try:
                dumped_iface = self.get_interfaces_addresses(device_name)
                for interface_number, ip in iface_to_ips.items():
                    self.check_with_timeout(device_name, interface_number, ip, dumped_iface)
            except MachineNotRunningError:
                self.logger.warning(f"`{device_name}` is not running. Skipping checks...")

    def run_from_configuration(self):
        if key_exists(["test", "ip_mapping"], self.configuration):
            self.logger.info("Verifying the IP addresses assigned to devices...")
            self.run(self.configuration["test"]["ip_mapping"])
