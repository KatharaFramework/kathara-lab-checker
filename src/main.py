import argparse
import json
import logging
import os
import shutil
import signal
import sys
import time
from typing import Optional

import coloredlogs
from Kathara.exceptions import MachineCollisionDomainError
from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab
from Kathara.parser.netkit.LabParser import LabParser
from Kathara.setting.Setting import Setting
from tqdm import tqdm

import logger
from checks.KernelRouteCheck import KernelRouteCheck
from TestCollector import TestCollector
from checks.applications.dns.DNSAuthorityCheck import DNSAuthorityCheck
from checks.applications.dns.LocalNSCheck import LocalNSCheck
from checks.protocols.ProtocolRedistributionCheck import ProtocolRedistributionCheck
from checks.protocols.bgp.BGPNetworkCheck import BGPNetworkCheck
from checks.protocols.bgp.BGPPeeringCheck import BGPPeeringCheck
from checks.CollisionDomainCheck import CollisionDomainCheck
from checks.DaemonCheck import DaemonCheck
from checks.DeviceExistenceCheck import DeviceExistenceCheck
from checks.InterfaceIPCheck import InterfaceIPCheck
from checks.ReachabilityCheck import ReachabilityCheck
from checks.StartupExistenceCheck import StartupExistenceCheck
from utils import get_interfaces_addresses, get_kernel_routes, find_device_name_from_ip, write_result_to_excel

CURRENT_LAB: Optional[Lab] = None


def handler(signum, frame):
    if CURRENT_LAB:
        logger.warning(f"\nCtrl-C was pressed. Undeploying current lab in: {CURRENT_LAB.fs_path()}")
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

    logger = logging.getLogger("kathara-lab-checker")

    coloredlogs.install(fmt='%(message)s',
                        level='INFO', logger=logger)

    logger.propagate = False

    manager: Kathara = Kathara.get_instance()

    logger.info("Reading Test configuration...")
    with open(args.config, "r") as json_conf:
        configuration = json.load(json_conf)

    Setting.get_instance().load_from_dict({"image": configuration["default_image"]})

    logger.info(f"Parsing network scenarios template in: {configuration['structure']}")
    lab_template = LabParser().parse(
        os.path.dirname(configuration["structure"]),
        conf_name=os.path.basename(configuration["structure"]),
    )

    labs_path = os.path.abspath(configuration["labs_path"])
    logger.info(f"Parsing network scenarios in: {labs_path}")

    test_collector = TestCollector()

    for index, lab_dir in enumerate(tqdm(os.listdir(labs_path))):
        lab_path = os.path.join(labs_path, lab_dir)
        if not os.path.isdir(lab_path):
            continue

        logger.info(f"##################### {lab_dir} #####################")
        # sheet["A" + str(index + 2)] = lab_dir

        test_results_path = os.path.join(lab_path, "test_results")
        if os.path.exists(test_results_path) and not args.no_cache:
            logger.warning("Network scenario already processed, skipping...")
            continue

        logger.info(f"Parsing network scenario in: {lab_path}")

        try:
            lab = LabParser().parse(lab_path)
            CURRENT_LAB = lab
        except IOError as e:
            logger.warning(f"{str(e)} Skipping directory")
            continue
        except MachineCollisionDomainError as mcde:
            logger.warning(f"{str(mcde)} Skipping directory")
            continue

        logger.info(f"Undeploying network scenario in case it was running...")
        manager.undeploy_lab(lab=lab)
        logger.info(f"Deploying network scenario...")
        manager.deploy_lab(lab=lab)

        logger.info(f"Waiting convergence...")
        time.sleep(configuration["convergence_time"])

        logger.info(f"Starting tests")

        logger.info(f"Verifying lab structure using lab.conf template in: {configuration['structure']}")

        logger.info("Checking that all devices exist...")
        for device_name in lab_template.machines.keys():
            check = DeviceExistenceCheck(f'Check existence of `{device_name}`')
            check_result = check.run(device_name, lab)
            logger.info(check_result)
            test_collector.add_check_result(lab_dir, check_result)

        logger.info("Checking collision domains...")
        for cd_t in lab_template.links.values():
            check = CollisionDomainCheck(f"Checking collision domain `{cd_t.name}`")
            check_result = check.run(cd_t, lab)
            logger.info(check_result)
            test_collector.add_check_result(lab_dir, check_result)

        logger.info("Checking that all required startup files exist...")
        for device_name in configuration["test"]["requiring_startup"]:
            check = StartupExistenceCheck(f"Check existence of `{device_name}.startup` file")
            check_result = check.run(device_name, lab)
            logger.info(check_result)
            test_collector.add_check_result(lab_dir, check_result)

        if "ip_mapping" in configuration["test"]:
            for device_name, iface_to_ips in configuration["test"]["ip_mapping"].items():
                dumped_iface = get_interfaces_addresses(device_name, lab)
                for interface_num, ip in iface_to_ips.items():
                    check = InterfaceIPCheck(
                        f"Verifying the IP address ({ip}) assigned to eth{interface_num} of {device_name}")
                    check_result = check.run(device_name, int(interface_num), ip, dumped_iface)
                    logger.info(check_result)
                    test_collector.add_check_result(lab_dir, check_result)

        logger.info(f"Starting reachability test...")
        for device_name, ips_to_reach in configuration["test"]["reachability"].items():
            for destination in ips_to_reach:
                check = ReachabilityCheck("")
                check_result = check.run(device_name, destination, lab)
                logger.info(check_result)
                test_collector.add_check_result(lab_dir, check_result)

        logger.info(f"Checking if daemons are running...")
        for device_name, daemons in configuration["test"]["daemons"].items():
            logger.info(f"Checking if daemons are running on {device_name}")
            for daemon_name in daemons:
                check = DaemonCheck("")
                check_result = check.run(device_name, daemon_name, lab)
                logger.info(check_result)
                test_collector.add_check_result(lab_dir, check_result)

        logger.info("Checking routing daemons configurations...")
        for daemon_name, daemon_test in configuration["test"]["protocols"].items():
            if daemon_name == "bgpd":
                logger.info(f"Check BGP peerings configurations...")
                for device_name, neighbors in daemon_test["peerings"].items():
                    logger.info(f"Check configuration of {device_name}")
                    device = lab.get_machine(device_name)
                    for neighbor in neighbors:
                        check = BGPPeeringCheck(f"{device_name} has bgp peer {neighbor}")
                        check_result = check.run(device_name, neighbor, lab)
                        logger.info(check_result)
                        test_collector.add_check_result(lab_dir, check_result)

                logger.info(f"Checking BGP announces...")
                for device_name, networks in daemon_test["networks"].items():
                    logger.info(f"Checking announces of {device_name}")
                    for network in networks:
                        check = BGPNetworkCheck(f"Check bgp network ({network}) for {device_name}")
                        check_result = check.run(device_name, network, lab)
                        logger.info(check_result)
                        test_collector.add_check_result(lab_dir, check_result)

            logger.info(f"Checking protocols injection...")
            if "injections" in daemon_test:
                for device_name, injected_protocols in daemon_test["injections"].items():
                    logger.info(f"Checking protocols injection of {device_name}")
                    for injected_protocol in injected_protocols:
                        check = ProtocolRedistributionCheck("")
                        check_result = check.run(device_name, daemon_name, injected_protocol, lab)
                        logger.info(check_result)
                        test_collector.add_check_result(lab_dir, check_result)

        logger.info(f"Checking Routing Tables...")
        for device_name, routes_to_check in configuration["test"]["kernel_routes"].items():
            device_routes = get_kernel_routes(device_name, lab)
            for route_to_check in routes_to_check:
                next_hop = None
                if type(route_to_check) == list:
                    next_hop = route_to_check[1]
                    route_to_check = route_to_check[0]
                check = KernelRouteCheck("")
                check_result = check.run(device_name, route_to_check, next_hop, device_routes)
                logger.info(check_result)
                test_collector.add_check_result(lab_dir, check_result)

        for application_name, application in configuration["test"]["applications"].items():
            if application_name == "dns":
                logger.info("Checking DNS configurations...")
                for domain, name_servers in application["authoritative"].items():
                    for ns in name_servers:
                        device_name = find_device_name_from_ip(configuration["test"]["ip_mapping"], ns)
                        if device_name:
                            check = DNSAuthorityCheck("")
                            check_result = check.run(domain, ns, device_name, lab)
                            logger.info(check_result)
                            test_collector.add_check_result(lab_dir, check_result)
                        else:
                            raise Exception("Something missing/wrong in the ip mapping configuration.")

                        if domain == ".":
                            logger.info(
                                f"Checking if all the named servers can correctly "
                                f"resolve {ns} as the root nameserver..."
                            )
                            for generic_ns_ip in application["authoritative"]["."]:
                                device_name = find_device_name_from_ip(
                                    configuration["test"]["ip_mapping"], generic_ns_ip
                                )
                                if device_name:
                                    check = DNSAuthorityCheck("")
                                    check_result = check.run(domain, ns, device_name, lab)
                                    logger.info(check_result)
                                    test_collector.add_check_result(lab_dir, check_result)
                                else:
                                    raise Exception()
                            for local_ns, managed_devices in application["local_ns"].items():
                                device_name = find_device_name_from_ip(
                                    configuration["test"]["ip_mapping"], local_ns
                                )
                                if device_name:
                                    check = DNSAuthorityCheck("")
                                    check_result = check.run(domain, ns, device_name, lab)
                                    logger.info(check_result)
                                    test_collector.add_check_result(lab_dir, check_result)
                                else:
                                    raise Exception()

                logger.info("Checking local name servers configurations...")
                for local_ns, managed_devices in application["local_ns"].items():
                    for device_name in managed_devices:
                        check = LocalNSCheck("")
                        check_result = check.run(local_ns, device_name, lab)
                        logger.info(check_result)
                        test_collector.add_check_result(lab_dir, check_result)

                for dns_name, devices in application["reachability"].items():
                    logger.info(f"Checking reachability of dns name `{dns_name}` from `{devices}`...")
                    for device_name in devices:
                        check = ReachabilityCheck("")
                        check_result = check.run(device_name, dns_name, lab)
                        logger.info(check_result)
                        test_collector.add_check_result(lab_dir, check_result)

        logger.info("Undeploying Network Scenario")
        manager.undeploy_lab(lab=lab)

        total_tests = len(test_collector.tests[lab_dir])
        test_results = list(map(lambda x: x.passed, test_collector.tests[lab_dir]))
        failed_tests = test_collector.get_failed(lab_dir)
        logger.info(f"Total Tests: {total_tests}")
        logger.info(f"Passed Tests: {test_results.count(True)}/{total_tests}")

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
            for idx, test in enumerate(test_collector.tests[lab_dir]):
                result_file.write(f"################# {idx} #################\n")
                result_file.write(f"Test: {test.description}\nResult: {test.passed}\nReason: {test.reason}\n")

        failed_path = os.path.join(test_results_path, "failed.txt")
        if failed_tests:
            logger.info(f"Writing FAILED test report to: {failed_path}")
            with open(failed_path, "w") as result_file:
                result_file.write("############ Failed Tests ############\n")
                for idx, test in enumerate(failed_tests):
                    result_file.write(f"################# {idx} #################\n")
                    result_file.write(f"Test: {test.description}\nResult: {test.passed}\nReason: {test.reason}\n")

    if test_collector.tests:
        logger.info(f"Writing All Test Results into: {labs_path}")
        write_result_to_excel(test_collector, labs_path)