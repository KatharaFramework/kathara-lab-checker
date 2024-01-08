import ipaddress
import json
import os
import re
from typing import Any, Union

import jc
from Kathara.exceptions import MachineNotFoundError, LinkNotFoundError, MachineNotRunningError
from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab
from Kathara.model.Link import Link
from Kathara.model.Machine import Machine

import logger

kathara_manager = Kathara.get_instance()


def get_output(exec_output):
    output = ""
    try:
        while True:
            (stdout, stderr) = next(exec_output)
            stdout = stdout.decode("utf-8") if stdout else ""
            stderr = stderr.decode("utf-8") if stderr else ""

            if stdout:
                output += stdout
            if stderr:
                output += f"ERROR: {stderr}"
    except StopIteration:
        pass
    return output


def check_startup(lab: Lab, machines_requiring_startup: list[str]) -> list[tuple[str, bool, str]]:
    results = []

    for device_name in machines_requiring_startup:
        test_text = f"Checking existence of `{device_name}.startup` file: "
        logger.log(test_text, end="")
        if lab.fs.exists(device_name + ".startup"):
            results.append((test_text, True, "OK"))
            logger.log_green("OK")
        else:
            results.append((test_text, False, f"{device_name}.startup file not found"))
            logger.log_red(f"{device_name}.startup file not found")
    return results


def check_device(device_name: str, lab) -> tuple[str, bool, str]:
    test_text = f"Checking existence of `{device_name}`: "
    logger.log(test_text, end="")
    try:
        lab.get_machine(device_name)
    except MachineNotFoundError as e:
        logger.log_red(e)
        return test_text, False, str(e)
    logger.log_green("OK")
    return test_text, True, "OK"


def check_devices(lab: Lab, lab_template: Lab) -> list[tuple[str, bool, str]]:
    results = []
    for device in lab_template.machines.values():
        results.append(check_device(device.name, lab))
    return results


def check_collision_domain(cd_t: Link, lab: Lab) -> tuple[str, bool, str]:
    test_text = f"Checking collision domain `{cd_t.name}`: "
    logger.log(test_text, end="")
    try:
        cd = lab.get_link(cd_t.name)
        if cd.machines.keys() != cd_t.machines.keys():
            reason = (
                f"Devices connected to collision domain {cd.name} {list(cd.machines.keys())} "
                f"are different from the one in the template {list(cd_t.machines.keys())}."
            )
            logger.log_red(reason)
            return test_text, False, reason
        logger.log_green("OK")
        return test_text, True, "OK"
    except LinkNotFoundError as e:
        logger.log_red(e)
        return test_text, False, str(e)


def check_collision_domains(lab: Lab, lab_template: Lab) -> list[tuple[str, bool, str]]:
    results = []
    for cd_t in lab_template.links.values():
        results.append(check_collision_domain(cd_t, lab))
    return results


def check_running_daemon(device_name: str, daemon: str, lab: Lab) -> tuple[str, bool, str]:
    invert: bool = False
    if daemon.startswith("!"):
        daemon = daemon[1:]
        test_text = f"Checking that {daemon} is not running on device `{device_name}`: "
        invert = True
    else:
        test_text = f"Checking that {daemon} is running on device `{device_name}`: "
        invert = False

    try:
        device = lab.get_machine(device_name)
        logger.log(test_text, end="")
        output = get_output(
            kathara_manager.exec(machine_name=device.name, lab_hash=lab.hash, command=f"pgrep {daemon}")
        )
        if (output != "") ^ invert:
            logger.log_green("OK")
            return test_text, True, "OK"
        else:
            reason = f"Daemon {daemon} is {'' if invert else 'not '}running on device `{device_name}"
            logger.log_red(reason)
            return test_text, False, reason
    except MachineNotFoundError as e:
        logger.log_red(str(e))
        return test_text, False, str(e)


def get_kernel_routes(device: Machine, lab: Lab) -> dict[str, Any]:
    output = get_output(
        kathara_manager.exec(machine_name=device.name, lab_hash=lab.hash, command="ip -j route")
    )
    return json.loads(output)


def check_negative_route(
    device_name: str, route_to_check: str, next_hop: str, routes: list[dict]
) -> tuple[str, bool, str]:
    test_text = (
        f"Check that route {route_to_check} "
        + (f"with nexthop {next_hop} " if next_hop else "")
        + f"IS NOT in the routing table of device `{device_name}`:\t"
    )
    logger.log(test_text, end="")
    for route in routes:
        if route["dst"] == route_to_check:
            reason = f"The route `{route_to_check}` IS in the routing table!"
            logger.log_red(reason)
            return test_text, False, reason
    logger.log_green("OK")
    return test_text, True, "OK"


def check_positive_route(
    device_name: str, route_to_check: str, next_hop: str, routes
) -> tuple[str, bool, str]:
    test_text = (
        f"Check that route {route_to_check} "
        + (f"with nexthop {next_hop} " if next_hop else "")
        + f"IS in the routing table of device `{device_name}`:\t"
    )
    logger.log(test_text, end="")
    for route in routes:
        if route["dst"] == route_to_check:
            if next_hop:
                if route["gateway"] == next_hop:
                    logger.log_green("OK")
                    return test_text, True, "OK"
                else:
                    reason = f"The route is present with netxthop {route['gateway']}. Maybe some policies are misconfigured."
                    logger.log_red(reason)
                    return test_text, False, reason
            logger.log_green("OK")
            return test_text, True, "OK"
    reason = f"The route {route_to_check} IS NOT found in the routing table."
    logger.log_red(reason)
    return test_text, False, reason


def check_kernel_route(device_name: str, route_to_check: str, next_hop: str, routes) -> tuple[str, bool, str]:
    negative = False
    if route_to_check.startswith("!"):
        route_to_check = route_to_check[1:]
        negative = True
    if not negative:
        return check_positive_route(device_name, route_to_check, next_hop, routes)
    else:
        return check_negative_route(device_name, route_to_check, next_hop, routes)


def check_kernel_routes(device_name: str, routes_to_check: list[Union[str, tuple[str, str]]], lab: Lab):
    logger.log(f"Checking Routing Table of {device_name}")
    device = lab.get_machine(device_name)
    device_routes = get_kernel_routes(device, lab)
    results = []
    for route in routes_to_check:
        next_hop = None
        if type(route) == list:
            next_hop = route[1]
            route = route[0]
        results.append(check_kernel_route(device_name, route, next_hop, device_routes))
    return results


def check_bgp_peering(device: Machine, lab: Lab, neighbor: str) -> tuple[str, bool, str]:
    test_text = f"{device.name} has bgp peer {neighbor}:\t"
    logger.log(test_text, end="")
    exec_output_gen = kathara_manager.exec(
        machine_name=device.name, command="vtysh -e 'show ip bgp summary json'", lab_hash=lab.hash
    )
    output = get_output(exec_output_gen)
    if output.startswith("ERROR:") or "exec failed" in output:
        logger.log_red(output)
        return test_text, False, output
    output = json.loads(output)
    for peer in output["ipv4Unicast"]["peers"]:
        if neighbor == peer:
            logger.log_green("OK")
            return test_text, True, "OK"
    reason = f"The peering between {device.name} and {neighbor} is not up."
    logger.log_red(reason)
    return test_text, False, reason


def check_bgp_network_command(device: Machine, network: str, lab: Lab) -> tuple[str, bool, str]:
    test_text = f"Checking bgp network ({network}) for {device.name}:\t"
    logger.log(test_text, end="")
    exec_output_gen = kathara_manager.exec(
        machine_name=device.name, command="vtysh -e 'show running-config bgp'", lab_hash=lab.hash
    )
    output = list(filter(lambda x: "network" in x, get_output(exec_output_gen).split("\n")))
    for line in output:
        if re.search(rf"\s*network\s*{network}", line):
            logger.log_green("OK")
            return test_text, True, "OK"
    reason = f"Network {network} is not announced in BGP."
    logger.log_red(reason)
    return test_text, False, reason


def check_protocol_injection(
    device: Machine, protocol_to_check: str, injected_protocol: str, lab: Lab
) -> tuple[str, bool, str]:
    invert: bool = False
    if injected_protocol.startswith("!"):
        injected_protocol = injected_protocol[1:]
        test_text = f"Checking that {injected_protocol} routes are not redistributed to {protocol_to_check} on device `{device.name}`: "
        invert = True
    else:
        test_text = f"Checking that {injected_protocol} routes are redistributed to {protocol_to_check} on device `{device.name}`: "
        invert = False

    logger.log(test_text, end="")
    exec_output_gen = kathara_manager.exec(
        machine_name=device.name,
        command=f"vtysh -e 'show running-config {protocol_to_check}'",
        lab_hash=lab.hash,
    )
    output = get_output(exec_output_gen).split("\n")
    found = False
    for line in output:
        if re.search(rf"^\s*redistribute\s*{injected_protocol}$", line):
            found = True
            break
    if found ^ invert:
        logger.log_green("OK")
        return test_text, True, "OK"
    else:
        reason = (
            f"{injected_protocol} routes are {'' if invert else 'not '}injected into `{protocol_to_check}`"
        )
        logger.log_red(reason)
    return test_text, False, reason


def check_dns_authority_for_domain(
    domain: str, authority_ip: str, device_name: str, lab: Lab
) -> tuple[str, bool, str]:
    test_text = f"Checking that `{authority_ip}` is the authority for domain `{domain}`:\t"
    logger.log(test_text, end="")
    exec_output_gen = kathara_manager.exec(
        machine_name=device_name, command=f"dig NS {domain}", lab_hash=lab.hash
    )

    output = get_output(exec_output_gen)
    if output.startswith("ERROR:"):
        logger.log_red("\n" + output)
        return test_text, False, output
    result = jc.parse("dig", output)
    if result and result[0]["status"] == "NOERROR":
        result = result.pop()
        root_servers = list(map(lambda x: x["data"].split(" ")[0], result["answer"]))
        authority_ips = []
        for root_server in root_servers:
            exec_output_gen = kathara_manager.exec(
                machine_name=device_name, command=f"dig +short {root_server}", lab_hash=lab.hash
            )
            ip = get_output(exec_output_gen).strip()
            if authority_ip == ip:
                logger.log_green("OK")
                return test_text, True, "OK"
            else:
                authority_ips.append(ip)
        reason = f"The dns authorities for domain `{domain}` have the following IPs {authority_ips}"
        logger.log_red(reason)
        return test_text, False, reason
    else:
        logger.log_red("\n" + output)
        return test_text, False, output


def check_local_name_server_for_device(local_ns_ip: str, device_name: str, lab: Lab) -> tuple[str, bool, str]:
    test_text = f"Checking that `{local_ns_ip}` is the local name server for device `{device_name}`:\t"
    logger.log(test_text, end="")
    exec_output_gen = kathara_manager.exec(
        machine_name=device_name, command=f"cat /etc/resolv.conf", lab_hash=lab.hash
    )
    output = get_output(exec_output_gen)
    if output.startswith("ERROR:"):
        logger.log_red("\n" + output)
        return test_text, False, output

    lines = output.splitlines()
    if not lines:
        reason = f"`resolv.conf` file not found for device `{device_name}`"
        logger.log_red(reason)
        return test_text, False, reason
    for line in lines:
        if re.search(rf"^nameserver {local_ns_ip}$", line):
            logger.log_green("OK")
            return test_text, True, "OK"
        else:
            reason = f"The local name server for device `{device_name}` has ip `{local_ns_ip}`"
            logger.log_red(reason)
            return test_text, False, reason


def verifying_reachability_from_device(device_name: str, destination: str, lab: Lab) -> tuple[str, bool, str]:
    test_text = f"Verifying `{destination}` reachability from device `{device_name}`:\t"
    logger.log(test_text, end="")
    try:
        exec_output_gen = kathara_manager.exec(
            machine_name=device_name,
            command=f"bash -c 'ping -q -n -c 1 {destination}; echo $?'",
            lab_hash=lab.hash,
        )
    except Exception as e:
        logger.log_red(str(e))
        return test_text, False, str(e)
    output = get_output(exec_output_gen)
    if output.splitlines()[-1] == "0":
        logger.log_green("OK")
        return test_text, True, "OK"
    else:
        reason = f"`{destination}` not reachable from device `{device_name}`"
        logger.log_red(reason)
        return test_text, False, reason


def check_ip_on_interface(
    device_name: str, iface_num: int, ip: str, iface_info: dict
) -> tuple[str, bool, str]:
    test_text = f"Verifying the IP address ({ip}) assigned to eth{iface_num} of {device_name}:\t"
    logger.log(test_text, end="")
    ip_address = ipaddress.ip_interface(ip)

    prefix_len = int(ip_address.with_prefixlen.split("/")[1])

    assigned_ips = []
    if iface_info and "addr_info" in iface_info:
        for addr_info in iface_info["addr_info"]:
            assigned_ips.append(f"{addr_info['local']}/{addr_info['prefixlen']}")
            if addr_info["local"] == str(ip_address.ip):
                if addr_info["prefixlen"] == prefix_len:
                    logger.log_green("OK")
                    return test_text, True, "OK"
                else:
                    reason = f"The IP address has a wrong netmask ({prefix_len})"
                    logger.log_red(reason)
                    return test_text, False, reason
        reason = f"The interface `{iface_info['ifname']}` of `{device_name}` has the following IP addresses: {assigned_ips}`."
        logger.log_red(reason)
        return test_text, False, reason


def check_ips_on_interfaces(
    device_name: str, iface_to_ips: dict[str, str], lab: Lab
) -> list[tuple[str, bool, str]]:
    logger.log(f"Checking IPs mapping on device `{device_name}`...")
    results = []
    try:
        exec_output_gen = kathara_manager.exec(
            machine_name=device_name,
            command=f"ip -j address",
            lab_hash=lab.hash,
        )
    except MachineNotRunningError as e:
        results.append((f"Trying to get information on {device_name} interfaces:", False, str(e)))
        return results

    dumped_iface = json.loads(get_output(exec_output_gen))

    for interface_num, ip in iface_to_ips.items():
        try:
            iface_info = next(filter(lambda x: x["ifname"] == f"eth{interface_num}", dumped_iface))
            results.append(check_ip_on_interface(device_name, int(interface_num), ip, iface_info))
        except StopIteration:
            results.append(
                (
                    f"Trying to get information on interface eth{interface_num} of {device_name}:",
                    False,
                    f"Interface eth`{interface_num}` not found on `{device_name}`",
                )
            )

    return results
