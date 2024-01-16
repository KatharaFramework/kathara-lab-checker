import json
from Kathara.exceptions import MachineNotFoundError
from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

from utils import get_output
from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


def filter_by_interface_type(interface_type: str, interfaces: list[dict]):
    return list(filter(lambda x: 'linkinfo' in x and x['linkinfo']['info_kind'] == interface_type, interfaces))


def get_interface_by_name(interface_name: str, interfaces: list[dict]):
    return list(filter(lambda x: x['ifname'] == interface_name, interfaces)).pop()


def get_inteface_by_vni(interface_vni: str, interfaces: list[dict]):
    return list(filter(lambda x: "linkinfo" in x and "id" in x["linkinfo"]["info_data"] and
                                 x["linkinfo"]["info_data"]["id"] == int(interface_vni), interfaces)).pop()


class BridgeCheck(AbstractCheck):

    def check_bridge_interfaces(self, device_name: str, expected_interfaces: list[str], actual_interfaces: list[dict]):
        self.description = (f"Checking that interfaces {expected_interfaces} "
                            f"are attached to the bridge on `{device_name}`")
        interface_masters = {}
        for interface_name in expected_interfaces:
            actual_iface_info = get_interface_by_name(interface_name, actual_interfaces)
            if 'master' in actual_iface_info:
                interface_masters[interface_name] = actual_iface_info['master']
        masters = len(set(interface_masters.values()))
        if masters == 1:
            return CheckResult(self.description, True, "OK")
        elif masters == 0:
            return CheckResult(self.description, False, "No interfaces attached to the bridge")
        elif masters > 1:
            reason = "Interfaces are attached to different bridges.\n"
            for interface_name, interface_master in interface_masters.items():
                reason += f"`{interface_name}` to `{interface_master}`\n"
            return CheckResult(self.description, False, reason)

    def check_vlan_tags(self, device_name: str, interface_name: str, interface_configuration: dict,
                        actual_interface_vlan: dict):
        self.description = (f"Checking that vlans `{interface_configuration['vlan_tags']}` "
                            f"are configured on `{interface_name}` of `{device_name}`")
        expected_vlans = set(interface_configuration['vlan_tags'])
        actual_vlans = set(map(lambda x: x['vlan'], actual_interface_vlan['vlans']))
        actual_vlans.remove(1)

        if expected_vlans == actual_vlans:
            return CheckResult(self.description, True, "OK")
        else:
            not_configured = expected_vlans.difference(actual_vlans)
            reason = f"Vlans `{not_configured}` are not configured on `{interface_name}` of `{device_name}`"
            return CheckResult(self.description, False, reason)

    def check_vxlan_pvid(self, device_name: str, vni: str, pvid: str, actual_interfaces: list[dict],
                         vlans_info: list[dict]):
        self.description = f"Check that `{device_name}` manages vni `{vni}` with pvid `{pvid}`"

        interface_name = get_inteface_by_vni(vni, actual_interfaces)['ifname']
        for vlan in vlans_info:
            if vlan['ifname'] == interface_name:
                actual_pvid = set(
                    map(lambda x: x['vlan'], filter(lambda x: 'PVID' in x['flags'], vlan['vlans'])))
                if pvid:
                    actual_pvid = actual_pvid.pop()
                    if actual_pvid == pvid:
                        return CheckResult(self.description, True, "OK")
                    else:
                        return CheckResult(self.description, False,
                                           f"VNI `{vni}` found with pvid `{actual_pvid}` (instead of {pvid})")
        return CheckResult(self.description, False, f"VNI `{vni}` not found on `{device_name}`")

    def check_vlan_pvid(self, device_name: str, interface_name: str, interface_pvid: str,
                        actual_interface_vlan: dict):
        self.description = (
            f"Checking that `{interface_name}` of `{device_name}` has pvid {interface_pvid}")
        pvid = set(
            map(lambda x: x['vlan'], filter(lambda x: 'PVID' in x['flags'], actual_interface_vlan['vlans'])))
        if pvid:
            actual_pvid = pvid.pop()
            if interface_pvid == actual_pvid:
                return CheckResult(self.description, True, "OK")
            else:
                reason = (f"`{interface_name}` of `{device_name}` has pvid `{actual_pvid}` "
                          f"instead of (`{interface_pvid}`)")
                return CheckResult(self.description, False, reason)
        else:
            reason = f"No pvid configured on `{interface_name}` of `{device_name}`"
            return CheckResult(self.description, False, reason)

    def run(self, devices_to_bridge_configuration: dict[str, list[dict]], lab: Lab) -> list[CheckResult]:
        results = []
        for device_name, bridges_configuration in devices_to_bridge_configuration.items():
            self.logger.info(f"Checking bridges configuration on `{device_name}`...")
            try:
                ip_link_output = get_output(
                    Kathara.get_instance().exec(
                        machine_name=device_name,
                        lab_hash=lab.hash,
                        command="ip -d -j link",
                    )
                )
                bridge_vlan_output = get_output(
                    Kathara.get_instance().exec(
                        machine_name=device_name,
                        lab_hash=lab.hash,
                        command="bridge -j vlan",
                    )
                )
            except MachineNotFoundError as e:
                return [CheckResult(self.description, False, str(e))]

            actual_interfaces = json.loads(ip_link_output)

            actual_vlans = json.loads(bridge_vlan_output)

            for bridge_conf in bridges_configuration:
                expected_bridge_interfaces = list(bridge_conf['interfaces'].keys())
                vxlan_interfaces = []
                vxlan_interfaces_names = []
                if "vxlan" in bridge_conf:
                    for vni in bridge_conf['vxlan']:
                        try:
                            interface = get_inteface_by_vni(vni, actual_interfaces)
                        except IndexError:
                            continue
                        vxlan_interfaces_names.append(interface['ifname'])
                        vxlan_interfaces.append(interface)
                    expected_bridge_interfaces.extend(vxlan_interfaces_names)

                check_result = self.check_bridge_interfaces(device_name, expected_bridge_interfaces, actual_interfaces)
                results.append(check_result)
                self.logger.info(check_result)

                if check_result.passed:
                    for interface_name, interface_conf in bridge_conf['interfaces'].items():
                        actual_interface_vlans = get_interface_by_name(interface_name, actual_vlans)
                        if 'vlan_tags' in interface_conf:
                            check_result = self.check_vlan_tags(device_name, interface_name, interface_conf,
                                                                actual_interface_vlans)
                            results.append(check_result)
                            self.logger.info(check_result)

                        if 'pvid' in interface_conf:
                            check_result = self.check_vlan_pvid(device_name, interface_name, interface_conf['pvid'],
                                                                actual_interface_vlans)
                            results.append(check_result)
                            self.logger.info(check_result)

                    if 'vxlan' in bridge_conf:
                        for vni, vni_info in bridge_conf['vxlan'].items():
                            check_result = self.check_vxlan_pvid(device_name, vni, vni_info['pvid'], actual_interfaces,
                                                                 actual_vlans)
                            results.append(check_result)
                            self.logger.info(check_result)
        return results
