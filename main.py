import argparse
import json
import os
import shutil
import signal
import sys
import time
from openpyxl import Workbook
from openpyxl.styles import Alignment
from tqdm import tqdm

from typing import Optional

from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab
from Kathara.parser.netkit.LabParser import LabParser
from Kathara.setting.Setting import Setting

import lib
import logger

CURRENT_LAB: Optional[Lab] = None


def handler(signum, frame):
    if CURRENT_LAB:
        logger.log_yellow(f"\nCtrl-C was pressed. Undeploying current lab in: {CURRENT_LAB.fs_path()}")
        Kathara.get_instance().undeploy_lab(lab=CURRENT_LAB)
    exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A tool for automatically check Kathará network scenarios", add_help=True
    )

    parser.add_argument(
        "--config",
        "-c",
        required=True,
        help="The path to the configuration file for the tests",
    )

    parser.add_argument(
        "--no-cache",
        required=False,
        action="store_true",
        default=False,
        help="Re-process all the tests",
    )

    args = parser.parse_args(sys.argv[1:])

    signal.signal(signal.SIGINT, handler)
    manager: Kathara = Kathara.get_instance()

    logger.log("Reading Test configuration...")
    with open(args.config, "r") as json_conf:
        configuration = json.load(json_conf)

    Setting.get_instance().load_from_dict({"image": configuration["default_image"]})

    logger.log(f"Parsing network scenarios template in: {configuration["structure"]}")
    lab_template = LabParser().parse(
        os.path.dirname(configuration["structure"]),
        conf_name=os.path.basename(configuration["structure"]),
    )

    labs_path = os.path.abspath(configuration["labs_path"])
    logger.log(f"Parsing network scenarios in: {labs_path}")

    # Create a new Excel workbook
    workbook = Workbook()

    # Select the active sheet
    sheet = workbook.active

    sheet["A1"] = "Student Name"
    sheet["B1"] = "Tests Passed"
    sheet["C1"] = "Tests Failed"
    sheet["D1"] = "Tests Total Number"
    sheet["E1"] = "Problems"

    for index, lab_dir in enumerate(tqdm(os.listdir(labs_path))):
        lab_path = os.path.join(labs_path, lab_dir)
        if not os.path.isdir(lab_path):
            continue

        logger.log(f"##################### {lab_dir} #####################")
        sheet["A" + str(index + 2)] = lab_dir

        test_results_path = os.path.join(lab_path, "test_results")
        if os.path.exists(test_results_path) and not args.no_cache:
            logger.log_yellow("Network scenario already processed, skipping...")
            continue

        logger.log(f"Parsing network scenario in: {lab_path}")

        try:
            lab = LabParser().parse(lab_path)
            CURRENT_LAB = lab
        except IOError as e:
            logger.log_yellow(f"{str(e)} Skipping directory")
            continue

        logger.log(f"Undeploying network scenario in case it was running...")
        manager.undeploy_lab(lab=lab)
        logger.log(f"Deploying network scenario...")
        manager.deploy_lab(lab=lab)

        logger.log(f"Waiting convergence...")
        time.sleep(configuration["convergence_time"])

        logger.log(f"Starting tests")
        collected_tests = []

        logger.log(f"Verifying lab structure using lab.conf template in: {configuration['structure']}")

        logger.log("Checking that all devices exist...")
        collected_tests.extend(lib.check_devices(lab, lab_template))
        logger.log("Checking collision domains...")
        collected_tests.extend(lib.check_collision_domains(lab, lab_template))

        logger.log("Checking that all required startup files exist...")
        collected_tests.extend(lib.check_startup(lab, configuration["test"]["requiring_startup"]))

        if "ip_mapping" in configuration["test"]:
            for device_name, iface_to_ips in configuration["test"]["ip_mapping"].items():
                collected_tests.extend(lib.check_ips_on_interfaces(device_name, iface_to_ips, lab))

        logger.log(f"Starting reachability test...")
        for device_name, ips_to_reach in configuration["test"]["reachability"].items():
            for ip in ips_to_reach:
                collected_tests.append(lib.verifying_reachability_from_device(device_name, ip, lab))

        logger.log(f"Checking if daemons are running...")
        for device, daemons in configuration["test"]["daemons"].items():
            logger.log(f"Checking if daemons are running on {device}")
            for daemon_name in daemons:
                collected_tests.append(lib.check_running_daemon(device, daemon_name, lab))

        logger.log("Checking routing daemons configurations...")
        for daemon_name, daemon_test in configuration["test"]["protocols"].items():
            if daemon_name == "bgpd":
                logger.log(f"Checking BGP peerings configurations...")
                for device_name, neighbors in daemon_test["peerings"].items():
                    logger.log(f"Checking configuration of {device_name}")
                    device = lab.get_machine(device_name)
                    for neighbor in neighbors:
                        collected_tests.append(lib.check_bgp_peering(device, lab, neighbor))

                logger.log(f"Checking BGP announces...")
                for device_name, networks in daemon_test["networks"].items():
                    logger.log(f"Checking announces of {device_name}")
                    device = lab.get_machine(device_name)
                    for network in networks:
                        collected_tests.append(lib.check_bgp_network_command(device, network, lab))

            logger.log(f"Checking protocols injection...")
            if "injections" in daemon_test:
                for device_name, injected_protocols in daemon_test["injections"].items():
                    logger.log(f"Checking protocols injection of {device_name}")
                    device = lab.get_machine(device_name)
                    for injected_protocol in injected_protocols:
                        collected_tests.append(
                            lib.check_protocol_injection(device, daemon_name, injected_protocol, lab)
                        )

        logger.log(f"Checking Routing Tables...")
        for device_name, routes_to_check in configuration["test"]["kernel_routes"].items():
            collected_tests.extend(lib.check_kernel_routes(device_name, routes_to_check, lab))

        for application_name, application in configuration["test"]["applications"].items():
            if application_name == "dns":
                logger.log("Checking DNS configurations...")
                for domain, name_servers in application["authoritative"].items():
                        for ns in name_servers:
                            device_name = lib.find_device_name_from_ip(configuration["test"]["ip_mapping"], ns)
                            if device_name:
                                collected_tests.append(lib.check_dns_authority_for_domain(domain, ns, device_name, lab))
                            else:
                                raise Exception()
                            
                            if domain == ".":
                                logger.log(f"Checking if all the named servers can correctly resolve {ns} as the root nameserver...")
                                for generic_ns_ip in application["authoritative"]["."]:
                                    device_name = lib.find_device_name_from_ip(configuration["test"]["ip_mapping"], generic_ns_ip)
                                    if device_name:
                                        collected_tests.append(lib.check_dns_authority_for_domain(domain, ns, device_name, lab))
                                    else:
                                        raise Exception()
                                for local_ns, managed_devices in application["local_ns"].items():
                                    device_name = lib.find_device_name_from_ip(configuration["test"]["ip_mapping"], local_ns)
                                    if device_name:
                                        collected_tests.append(lib.check_dns_authority_for_domain(domain, ns, device_name, lab))
                                    else:
                                        raise Exception()

                logger.log("Checking local name servers configurations...")
                for local_ns, managed_devices in application["local_ns"].items():
                    for device in managed_devices:
                        collected_tests.append(lib.check_local_name_server_for_device(local_ns, device, lab))

                for dns_name, devices in application["reachability"].items():
                    logger.log(f"Checking reachability of dns name `{dns_name}` from `{devices}`...")
                    for device_name in devices:
                        collected_tests.append(
                            lib.verifying_reachability_from_device(device_name, dns_name, lab)
                        )

        logger.log("Undeploying Network Scenario")
        manager.undeploy_lab(lab=lab)

        total_tests = len(collected_tests)
        test_results = list(map(lambda x: x[1], collected_tests))
        failed_tests = list(filter(lambda x: not x[1], collected_tests))
        logger.log(f"Total Tests: {total_tests}")
        logger.log(f"Passed Tests: {test_results.count(True)}/{total_tests}")

        sheet["B" + str(index + 2)] = test_results.count(True)
        sheet["C" + str(index + 2)] = test_results.count(False)
        sheet["D" + str(index + 2)] = total_tests

        test_results_path = os.path.join(lab.fs_path(), "test_results")
        if os.path.exists(test_results_path):
            shutil.rmtree(test_results_path)

        os.mkdir(test_results_path)

        summary_path = os.path.join(test_results_path, "summary.txt")
        with open(summary_path, "w") as result_file:
            result_file.write("############ Tests Summary  ############\n")
            result_file.write(f"Total Tests: {total_tests}\n")
            result_file.write(f"Passed Tests: {test_results.count(True)}/{total_tests}\n")
            result_file.write(f"Failed Tests: {test_results.count(False)}/{total_tests}\n")

        all_path = os.path.join(test_results_path, "all_tests.txt")
        with open(all_path, "w") as result_file:
            result_file.write("############ All Tests  ############\n")
            for idx, test in enumerate(collected_tests):
                result_file.write(f"################# {idx} #################\n")
                result_file.write(f"Test: {test[0]}\nResult: {test[1]}\nReason: {test[2]}\n")

        failed_path = os.path.join(test_results_path, "failed.txt")
        if failed_tests:
            logger.log(f"Writing FAILED test report to: {failed_path}")
            with open(failed_path, "w") as result_file:
                result_file.write("############ Failed Tests ############\n")
                for idx, failed in enumerate(failed_tests):
                    result_file.write(f"################# {idx} #################\n")
                    result_file.write(f"Test: {failed[0]}\nResult: {failed[1]}\nReason: {failed[2]}\n")

        if failed_tests:
            failed_string = ""
            for idx, failed in enumerate(failed_tests):
                failed_string += f"{(idx+1)}: {failed[2]}\n"
            if len(failed_string) >= 32767:
                logger.log_red("ERROR: Excel cell too big")
            sheet["E" + str(index + 2)] = failed_string
            sheet["E" + str(index + 2)].alignment = Alignment(wrapText=True)
        else:
            sheet["E" + str(index + 2)] = "None"

    excel_file = os.path.join(labs_path, "results.xlsx")
    workbook.save(excel_file)
