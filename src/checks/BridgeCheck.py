import json
from Kathara.exceptions import MachineNotFoundError
from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

from utils import get_output
from .AbstractCheck import AbstractCheck
from .CheckResult import CheckResult


class BridgeCheck(AbstractCheck):
    def check(self, device_name: str, list_bridges: list, lab: Lab) -> CheckResult:
        kathara_manager: Kathara = Kathara.get_instance()

        self.description = f"Checking that a bridge is present on device `{device_name}`"

        try:
            device = lab.get_machine(device_name)
            output = get_output(
                kathara_manager.exec(
                    machine_name=device.name, lab_hash=lab.hash, command="ip -d -j link show type bridge"
                )
            )
        except MachineNotFoundError as e:
            return CheckResult(self.description, False, str(e))

        output = json.loads(output)

        if len(output) == 0:
            reason = f"Device {device_name} has no bridges running"
            return CheckResult(self.description, False, reason)

        if len(output) != len(list_bridges):
            reason = f"Device {device_name} has {len(output)} bridges running while configuration asserts {len(list_bridges)} bridges running"
            return CheckResult(self.description, False, reason)

        if len(output) != 1:
            # TODO: Remove this check when the cycle will be implemented
            reason = f"Device {device_name} has more than one running bridge"
            return CheckResult(self.description, False, reason)

        try:
            bridge_slaves = get_output(
                kathara_manager.exec(
                    machine_name=device.name,
                    lab_hash=lab.hash,
                    command="bridge -j link",
                )
            )
        except MachineNotFoundError as e:
            return CheckResult(self.description, False, str(e))

        bridge_slaves = json.loads(bridge_slaves)

        try:
            interfaces_vlans = get_output(
                kathara_manager.exec(
                    machine_name=device.name,
                    lab_hash=lab.hash,
                    command="bridge -j vlan",
                )
            )
        except MachineNotFoundError as e:
            return CheckResult(self.description, False, str(e))

        interfaces_vlans = json.loads(interfaces_vlans)

        # From now on I'll use output[0] as current_running_bridge and list_bridges[0] as current_conf_bridge
        current_conf_bridge = list_bridges[0]
        current_running_bridge = output[0]

        current_conf_bridge_with_ifaces = self._build_list_interfaces(
            current_conf_bridge, lab, kathara_manager, device_name
        )

        if current_running_bridge["linkinfo"]["info_data"]["vlan_filtering"] != 1:
            reason = f"Device {device_name} has bridge {current_running_bridge['ifname']} without vlan_filtering enabled"
            return CheckResult(self.description, False, reason)

        current_running_bridge_slaves = list(
            filter(lambda x: x["master"] == current_running_bridge["ifname"], bridge_slaves)
        )

        if len(current_running_bridge_slaves) != len(current_conf_bridge):
            reason = f"Device {device_name} has bridge {current_running_bridge['ifname']} with enslaved {len(bridge_slaves)} ifs but {len(current_conf_bridge)} needed"
            return CheckResult(self.description, False, reason)

        for bridge_slave in current_running_bridge_slaves:
            curr_conf = current_conf_bridge_with_ifaces[bridge_slave["ifname"]]
            if curr_conf:
                current_vlan = list(
                    filter(lambda x: x["ifname"] == bridge_slave["ifname"], interfaces_vlans)
                )[0]["vlans"]
                if "vlan_tags" in curr_conf:
                    vlan_list = list(filter(lambda y: "flags" not in y, current_vlan))
                    vlan_numbers_set = {entry["vlan"] for entry in vlan_list}
                    configued_vlan_set = set(curr_conf["vlan_tags"])
                    if configued_vlan_set == vlan_numbers_set:
                        # return CheckResult(self.description, True, "OK")
                        pass
                    else:
                        symmetric_difference = configued_vlan_set ^ vlan_numbers_set
                        reason = f"Device {device_name} has bridge {current_running_bridge['ifname']} with erros in vlans {symmetric_difference}"
                        return CheckResult(self.description, False, reason)
                else:
                    vlan_pvid = list(filter(lambda y: "flags" in y and "PVID" in y["flags"], current_vlan))[
                        0
                    ]["vlan"]
                    if curr_conf["pvid"] == vlan_pvid:
                        # return CheckResult(self.description, True, "OK")
                        pass
                    else:
                        reason = f"Device {device_name} has bridge {current_running_bridge['ifname']} with erros in untagged ifaces of vlans"
                        return CheckResult(self.description, False, reason)
            else:
                reason = (
                    f"Device {device_name} has bridge {current_running_bridge['ifname']} with erros in vlans"
                )
                return CheckResult(self.description, False, reason)

        return CheckResult(self.description, True, "OK")

    def run(self, devices_to_daemons: dict[str, list[str]], lab: Lab) -> list[CheckResult]:
        results = []
        for device_name, list_bridges in devices_to_daemons.items():
            self.logger.info(f"Checking if bridges are configured on `{device_name}`...")
            check_result = self.check(device_name, list_bridges, lab)
            self.logger.info(check_result)
            results.append(check_result)
        return results

    def _build_list_interfaces(self, config: list, lab: Lab, kathara_manager: Kathara, device_name: str):
        try:
            interfaces_vlans = get_output(
                kathara_manager.exec(
                    machine_name=device_name,
                    lab_hash=lab.hash,
                    command="ip -d -j link show type vxlan",
                )
            )
        except MachineNotFoundError as e:
            return CheckResult(self.description, False, str(e))

        interfaces_vlans = json.loads(interfaces_vlans)

        output = {}
        for config_element in config:
            if "vxlan" in config_element:
                elements = list(
                    filter(
                        lambda x: x["linkinfo"]["info_data"]["id"] == int(config_element["vxlan"]),
                        interfaces_vlans,
                    )
                )
                if len(elements) != 1:
                    raise Exception()
                config_element["interface"] = elements[0]["ifname"]
            output[config_element["interface"]] = config_element
        return output
