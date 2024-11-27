import json

from Kathara.exceptions import MachineNotRunningError

from kathara_lab_checker.utils import get_output
from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


def filter_by_interface_type(interface_type: str, interfaces: list[dict]):
    return list(filter(lambda x: "linkinfo" in x and x["linkinfo"]["info_kind"] == interface_type, interfaces))


def get_interface_by_name(interface_name: str, interfaces: list[dict]):
    return list(filter(lambda x: x["ifname"] == interface_name, interfaces)).pop()


def get_inteface_by_vni(interface_vni: str, interfaces: list[dict]):
    return list(
        filter(
            lambda x: "linkinfo" in x
            and "id" in x["linkinfo"]["info_data"]
            and x["linkinfo"]["info_data"]["id"] == int(interface_vni),
            interfaces,
        )
    ).pop()


class BridgeCheck(AbstractCheck):
    def check_bridge_interfaces(
        self, device_name: str, expected_interfaces: list[str], actual_interfaces: list[dict]
    ) -> (CheckResult, set[str]):
        self.description = (
            f"Checking that interfaces {expected_interfaces} " f"are attached to the same bridge on `{device_name}`"
        )
        interface_masters = {}
        interfaces_not_found = []
        interfaces_without_bridge = []
        for interface_name in expected_interfaces:
            try:
                actual_iface_info = get_interface_by_name(interface_name, actual_interfaces)
                if "master" in actual_iface_info:
                    interface_masters[interface_name] = actual_iface_info["master"]
                else:
                    interfaces_without_bridge.append(interface_name)
            except IndexError:
                interfaces_not_found.append(interface_name)

        if interfaces_not_found:
            return (
                CheckResult(
                    self.description,
                    False,
                    f"Interfaces `{interfaces_not_found}` are not found on {device_name}",
                ),
                None,
            )
        if interfaces_without_bridge:
            return (
                CheckResult(
                    self.description,
                    False,
                    f"Interfaces `{interfaces_without_bridge}` are not connected to any bridge on {device_name}",
                ),
                None,
            )
        masters = set(interface_masters.values())
        masters_num = len(masters)
        if masters_num == 1:
            master = list(masters)[0]
            if get_interface_by_name(master, actual_interfaces)["linkinfo"]["info_kind"]:
                return CheckResult(self.description, True, "OK"), masters
        elif masters_num == 0:
            return CheckResult(self.description, False, "No interfaces attached to the bridge"), masters
        elif masters_num > 1:
            reason = "Interfaces are not attached to the same bridge.\n"
            for interface_name, interface_master in interface_masters.items():
                master_type = get_interface_by_name(interface_master, actual_interfaces)["linkinfo"]["info_kind"]
                reason += f"`{interface_name}` to `{interface_master}` (type: {master_type})\n"
            return CheckResult(self.description, False, reason), masters

    def check_vlan_filtering(self, device_name: str, bridge_info: dict) -> CheckResult:
        self.description = f"Checking if VLAN filtering is enabled on `{bridge_info['ifname']}` of `{device_name}`"
        if (
            "vlan_filtering" in bridge_info["linkinfo"]["info_data"]
            and bridge_info["linkinfo"]["info_data"]["vlan_filtering"] == 1
        ):
            return CheckResult(self.description, True, "OK")
        else:
            return CheckResult(
                self.description,
                True,
                f"VLAN filtering not enabled on `{bridge_info['ifname']}` of `{device_name}`",
            )

    def check_vlan_tags(
        self,
        device_name: str,
        interface_name: str,
        interface_configuration: dict,
        actual_interface_vlan: dict,
    ):
        self.description = (
            f"Checking that vlans `{interface_configuration['vlan_tags']}` "
            f"are configured on `{interface_name}` of `{device_name}`"
        )
        expected_vlans = set(interface_configuration["vlan_tags"])
        actual_vlans = set(map(lambda x: x["vlan"], actual_interface_vlan["vlans"]))
        actual_vlans.remove(1)

        if expected_vlans == actual_vlans:
            return CheckResult(self.description, True, "OK")
        else:
            not_configured = expected_vlans.difference(actual_vlans)
            reason = f"Vlans `{not_configured}` are not configured on `{interface_name}` of `{device_name}`"
            return CheckResult(self.description, False, reason)

    def check_vxlan_pvid(
        self, device_name: str, vni: str, pvid: str, actual_interfaces: list[dict], vlans_info: list[dict]
    ):
        self.description = f"Checking that `{device_name}` manages VNI `{vni}` with PVID `{pvid}`"

        try:
            interface_name = get_inteface_by_vni(vni, actual_interfaces)["ifname"]
        except IndexError:
            return CheckResult(self.description, False, f"VNI {vni} not configured on `{device_name}`")

        for vlan in vlans_info:
            if vlan["ifname"] == interface_name:
                actual_pvid = set(map(lambda x: x["vlan"], filter(lambda x: "PVID" in x["flags"], vlan["vlans"])))
                if pvid:
                    actual_pvid = actual_pvid.pop()
                    if actual_pvid == pvid:
                        return CheckResult(self.description, True, "OK")
                    else:
                        return CheckResult(
                            self.description,
                            False,
                            f"VNI `{vni}` found with pvid `{actual_pvid}` (instead of {pvid})",
                        )
        return CheckResult(self.description, False, f"VNI `{vni}` not found on `{device_name}`")

    def check_vlan_pvid(self, device_name: str, interface_name: str, interface_pvid: str, actual_interface_vlan: dict):
        self.description = f"Checking that `{interface_name}` of `{device_name}` has pvid {interface_pvid}"
        pvid = set(map(lambda x: x["vlan"], filter(lambda x: "PVID" in x["flags"], actual_interface_vlan["vlans"])))
        if pvid:
            actual_pvid = pvid.pop()
            if interface_pvid == actual_pvid:
                return CheckResult(self.description, True, "OK")
            else:
                reason = (
                    f"`{interface_name}` of `{device_name}` has pvid `{actual_pvid}` "
                    f"(instead of `{interface_pvid}`)"
                )
                return CheckResult(self.description, False, reason)
        else:
            reason = f"No pvid configured on `{interface_name}` of `{device_name}`"
            return CheckResult(self.description, False, reason)

    def run(self, devices_to_bridge_configuration: dict[str, list[dict]]) -> list[CheckResult]:
        results = []
        for device_name, bridges_configuration in devices_to_bridge_configuration.items():
            self.logger.info(f"Checking bridges configuration on `{device_name}`...")
            try:
                ip_link_output = get_output(
                    self.kathara_managerexec(
                        machine_name=device_name,
                        lab_hash=self.lab.hash,
                        command="ip -d -j link",
                    )
                )
                bridge_vlan_output = get_output(
                    self.kathara_manager.exec(
                        machine_name=device_name,
                        lab_hash=self.lab.hash,
                        command="bridge -j vlan",
                    )
                )
            except MachineNotRunningError as e:
                return [CheckResult(self.description, False, str(e))]

            actual_interfaces = json.loads(ip_link_output)

            actual_vlans = json.loads(bridge_vlan_output)

            for bridge_conf in bridges_configuration:
                expected_bridge_interfaces = list(bridge_conf["interfaces"].keys())
                vxlan_interfaces = []
                vxlan_interfaces_names = []
                if "vxlan" in bridge_conf:
                    for vni in bridge_conf["vxlan"]:
                        try:
                            interface = get_inteface_by_vni(vni, actual_interfaces)
                        except IndexError:
                            continue
                        vxlan_interfaces_names.append(interface["ifname"])
                        vxlan_interfaces.append(interface)
                    expected_bridge_interfaces.extend(vxlan_interfaces_names)

                check_result, masters = self.check_bridge_interfaces(
                    device_name, expected_bridge_interfaces, actual_interfaces
                )
                results.append(check_result)

                if check_result.passed:
                    check_result = self.check_vlan_filtering(
                        device_name, get_interface_by_name(masters.pop(), actual_interfaces)
                    )
                    results.append(check_result)

                    for interface_name, interface_conf in bridge_conf["interfaces"].items():
                        description = f"Getting VLAN info for `{interface_name}` on `{device_name}`"
                        actual_interface_vlans = None
                        try:
                            actual_interface_vlans = get_interface_by_name(interface_name, actual_vlans)
                            check_result = CheckResult(description, True, "OK")
                            results.append(check_result)
                        except IndexError:
                            check_result = CheckResult(
                                description,
                                False,
                                f"No VLAN found for for `{interface_name}` on `{device_name}`",
                            )
                            results.append(check_result)

                        if actual_interface_vlans:
                            if "vlan_tags" in interface_conf:
                                check_result = self.check_vlan_tags(
                                    device_name, interface_name, interface_conf, actual_interface_vlans
                                )
                                results.append(check_result)

                            if "pvid" in interface_conf:
                                check_result = self.check_vlan_pvid(
                                    device_name,
                                    interface_name,
                                    interface_conf["pvid"],
                                    actual_interface_vlans,
                                )
                                results.append(check_result)

                    if "vxlan" in bridge_conf:
                        for vni, vni_info in bridge_conf["vxlan"].items():
                            check_result = self.check_vxlan_pvid(
                                device_name, vni, vni_info["pvid"], actual_interfaces, actual_vlans
                            )
                            results.append(check_result)
        return results
