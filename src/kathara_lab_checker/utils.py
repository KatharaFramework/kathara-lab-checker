import json
from typing import Optional

from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab


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
