import re
from typing import Optional


def red(s):
    return f"\033[91m {s}\033[00m"


def green(s):
    return f"\033[92m {s}\033[00m"


def yellow(s):
    return f"\033[93m {s}\033[00m"


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


def get_router_config_section(running_config: str, daemon: str) -> list[str]:
    """
    Return the lines of the `router <protocol>` block(s) for the given FRR daemon (e.g. ripd -> `router rip`).

    The full `show running-config` must be used: since FRR 9.x, some daemons (e.g. ripd, ripngd, staticd) are
    managed by mgmtd, so `show running-config <daemon>` no longer contains their configuration.
    """
    protocol = daemon[:-1] if daemon.endswith("d") else daemon
    header = re.compile(rf"^router\s+{re.escape(protocol)}(\s|$)")

    section = []
    in_block = False
    for line in running_config.splitlines():
        if header.match(line):
            in_block = True
            continue
        if in_block:
            if line and not line[0].isspace():
                in_block = False
                continue
            section.append(line)
    return section


def find_device_name_from_ip(ip_mapping: dict[str, dict[str, str]], ip_search: str) -> Optional[str]:
    for device, ip_addresses in ip_mapping.items():
        for _, ip in ip_addresses.items():
            # Check if the base IP matches (ignoring the CIDR notation)
            if ip.split("/")[0] == ip_search:
                return device
    raise Exception("Something is missing/wrong in the ip_mapping configuration!")


def find_lines_with_string(file_content, search_string):
    """
    Returns lines from the provided multi-line string that contain the search string.

    :param file_content: A string representing the content of a file (multi-line string).
    :param search_string: A string to search for in each line of the file content.
    :return: A list of lines that contain the search string.
    """
    # Splitting the string into lines
    lines = file_content.split("\n")

    # Filtering lines that contain the search string
    matching_lines = [line for line in lines if search_string in line]

    return matching_lines


def reverse_dictionary(dictionary: dict):
    reversed_dict = {}
    for k, values in dictionary.items():
        for v in values:
            reversed_dict[v] = reversed_dict.get(v, []) + [k]
    return reversed_dict


def key_exists(key_list, dictionary):
    current_configuration = dictionary
    for k in key_list:
        if k in current_configuration:
            current_configuration = current_configuration[k]
        else:
            return False
    return True