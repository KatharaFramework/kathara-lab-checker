import json
import os
from typing import Any, Optional

from Kathara.exceptions import MachineNotRunningError
from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab
from openpyxl.styles import Alignment
from openpyxl.workbook import Workbook

import TestCollector as TestCollectorPackage


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


def get_interfaces_addresses(device_name: str, lab: Lab) -> dict:
    kathara_manager = Kathara.get_instance()

    exec_output_gen = kathara_manager.exec(
        machine_name=device_name,
        command=f"ip -j address",
        lab_hash=lab.hash,
    )

    return json.loads(get_output(exec_output_gen))


def get_kernel_routes(device_name: str, lab: Lab) -> list[dict[str, Any]]:
    kathara_manager = Kathara.get_instance()

    try:
        output = get_output(
            kathara_manager.exec(machine_name=device_name, lab_hash=lab.hash, command="ip -j route")
        )
    except MachineNotRunningError:
        return []

    return json.loads(output)


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

def write_result_to_excel(test_collector: 'TestCollectorPackage.TestCollector', path: str):
    # Create a new Excel workbook
    workbook = Workbook()

    # Select the active sheet
    sheet = workbook.active

    sheet["A1"] = "Student Name"
    sheet["B1"] = "Tests Passed"
    sheet["C1"] = "Tests Failed"
    sheet["D1"] = "Tests Total Number"
    sheet["E1"] = "Problems"

    for index, (test_name, test_results) in enumerate(test_collector.tests.items()):
        failed_tests = test_collector.get_failed(test_name)
        passed_tests = test_collector.get_passed(test_name)
        sheet["A" + str(index + 2)] = test_name
        sheet["B" + str(index + 2)] = len(passed_tests)
        sheet["C" + str(index + 2)] = len(failed_tests)
        sheet["D" + str(index + 2)] = len(test_results)

        if failed_tests:
            failed_string = ""
            for idx, failed in enumerate(failed_tests):
                failed_string += f"{(idx + 1)}: {failed.reason}\n"
            if len(failed_string) >= 32767:
                raise Exception("ERROR: Excel cell too big")
            sheet["E" + str(index + 2)] = failed_string
            sheet["E" + str(index + 2)].alignment = Alignment(wrapText=True)
        else:
            sheet["E" + str(index + 2)] = "None"

    excel_file = os.path.join(path, "results.xlsx")
    workbook.save(excel_file)

def reverse_dictionary(dictionary: dict):
    reversed_dict = {}
    for k, values in dictionary.items():
        for v in values:
            reversed_dict[v] = reversed_dict.get(v, []) + [k]
    return reversed_dict