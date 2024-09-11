#!/usr/bin/env python3
import argparse
import importlib.metadata
import json
import logging
import os
import signal
import time
from functools import partial
from typing import Optional

import coloredlogs
from Kathara.exceptions import MachineCollisionDomainError
from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab
from Kathara.parser.netkit.LabParser import LabParser
from Kathara.setting.Setting import Setting
from tqdm import tqdm

from kathara_lab_checker.TestCollector import TestCollector
from kathara_lab_checker.checks.BridgeCheck import BridgeCheck
from kathara_lab_checker.checks.CollisionDomainCheck import CollisionDomainCheck
from kathara_lab_checker.checks.DaemonCheck import DaemonCheck
from kathara_lab_checker.checks.DeviceExistenceCheck import DeviceExistenceCheck
from kathara_lab_checker.checks.IPv6EnabledCheck import IPv6EnabledCheck
from kathara_lab_checker.checks.InterfaceIPCheck import InterfaceIPCheck
from kathara_lab_checker.checks.KernelRouteCheck import KernelRouteCheck
from kathara_lab_checker.checks.ReachabilityCheck import ReachabilityCheck
from kathara_lab_checker.checks.StartupExistenceCheck import StartupExistenceCheck
from kathara_lab_checker.checks.SysctlCheck import SysctlCheck
from kathara_lab_checker.checks.applications.dns.DNSAuthorityCheck import DNSAuthorityCheck
from kathara_lab_checker.checks.applications.dns.LocalNSCheck import LocalNSCheck
from kathara_lab_checker.checks.protocols.AnnouncedNetworkCheck import AnnouncedNetworkCheck
from kathara_lab_checker.checks.protocols.ProtocolRedistributionCheck import ProtocolRedistributionCheck
from kathara_lab_checker.checks.protocols.bgp.BGPPeeringCheck import BGPPeeringCheck
from kathara_lab_checker.checks.protocols.evpn.AnnouncedVNICheck import AnnouncedVNICheck
from kathara_lab_checker.checks.protocols.evpn.EVPNSessionCheck import EVPNSessionCheck
from kathara_lab_checker.checks.protocols.evpn.VTEPCheck import VTEPCheck
from kathara_lab_checker.utils import reverse_dictionary, write_final_results_to_excel, write_result_to_excel


VERSION = "0.1.2"
CURRENT_LAB: Optional[Lab] = None


def handler(signum, frame, live=False):
    logger = logging.getLogger("kathara-lab-checker")
    if CURRENT_LAB and not live:
        logger.warning(f"\nCtrl-C was pressed. Undeploying current lab in: {CURRENT_LAB.fs_path()}")
        Kathara.get_instance().undeploy_lab(lab=CURRENT_LAB)
    exit(1)


def run_on_single_network_scenario(lab_path: str, configuration: dict, lab_template: Lab,
                                   no_cache: bool = False, live: bool = False, keep_open: bool = False,
                                   skip_report: bool = False):
    global CURRENT_LAB
    logger = logging.getLogger("kathara-lab-checker")

    manager = Kathara.get_instance()
    test_collector = TestCollector()

    lab_path = os.path.abspath(lab_path)
    lab_name = os.path.basename(lab_path)

    if not os.path.isdir(lab_path):
        logger.warning(f"{lab_path} is not a lab directory.")
        return

    test_results_path = os.path.join(lab_path, f"{lab_name}_result.xlsx")
    if os.path.exists(test_results_path) and not no_cache:
        logger.warning("Network scenario already processed, skipping...")
        return

    logger.info(f"##################### {lab_name} #####################")
    logger.info(f"Parsing network scenario in: {lab_path}")
    logger.info(f"Network scenario name: {lab_name}")
    try:
        lab = LabParser().parse(lab_path)
        CURRENT_LAB = lab
    except IOError as e:
        logger.warning(f"{str(e)} Skipping directory")
        return
    except MachineCollisionDomainError as e:
        logger.warning(f"{str(e)} Skipping directory")
        return

    if not live:
        logger.info(f"Undeploying network scenario in case it was running...")
        manager.undeploy_lab(lab=lab)
        logger.info(f"Deploying network scenario...")
        manager.deploy_lab(lab=lab)

        logger.info(f"Waiting convergence...")
        time.sleep(configuration["convergence_time"])
    else:
        machines = manager.get_machines_api_objects(lab=lab)
        if not machines:
            logger.warning("No devices running in the network scenario. Test aborted.")
            return

    logger.info(f"Starting tests")

    logger.info(f"Verifying lab structure using lab.conf template in: {configuration['structure']}")

    logger.info("Checking that all devices exist...")
    check_results = DeviceExistenceCheck().run(list(lab_template.machines.keys()), lab)
    test_collector.add_check_results(lab_name, check_results)

    logger.info("Checking collision domains...")
    check_results = CollisionDomainCheck().run(list(lab_template.links.values()), lab)
    test_collector.add_check_results(lab_name, check_results)

    logger.info("Checking that all required startup files exist...")
    check_results = StartupExistenceCheck().run(configuration["test"]["requiring_startup"], lab)
    test_collector.add_check_results(lab_name, check_results)

    if "ipv6_enabled" in configuration["test"]:
        logger.info(f"Checking that IPv6 is enabled on devices: {configuration['test']['ipv6_enabled']}")
        check_results = IPv6EnabledCheck().run(configuration["test"]["ipv6_enabled"], lab)
        test_collector.add_check_results(lab_name, check_results)

    if "sysctls" in configuration["test"]:
        logger.info(f"Checking sysctl configurations on devices...")
        check_results = SysctlCheck().run(configuration["test"]["sysctls"], lab)
        test_collector.add_check_results(lab_name, check_results)

    if "ip_mapping" in configuration["test"]:
        logger.info("Verifying the IP addresses assigned to devices...")
        check_results = InterfaceIPCheck().run(configuration["test"]["ip_mapping"], lab)
        test_collector.add_check_results(lab_name, check_results)

    if "bridges" in configuration["test"]:
        logger.info("Verifying the bridges inside devices...")
        check_results = BridgeCheck().run(configuration["test"]["bridges"], lab)
        test_collector.add_check_results(lab_name, check_results)

    if "reachability" in configuration["test"]:
        logger.info(f"Starting reachability test...")
        check_results = ReachabilityCheck().run(configuration["test"]["reachability"], lab)
        test_collector.add_check_results(lab_name, check_results)

    if "daemons" in configuration["test"]:
        logger.info(f"Checking if daemons are running...")
        check_results = DaemonCheck().run(configuration["test"]["daemons"], lab)
        test_collector.add_check_results(lab_name, check_results)

    if "protocols" in configuration["test"]:
        logger.info("Checking routing daemons configurations...")
        for daemon_name, daemon_test in configuration["test"]["protocols"].items():
            if daemon_name == "bgpd":
                logger.info(f"Check BGP peerings configurations...")
                check_results = BGPPeeringCheck().run(daemon_test["peerings"], lab)
                test_collector.add_check_results(lab_name, check_results)

                if "networks" in daemon_test:
                    logger.info(f"Checking BGP announces...")
                    check_results = AnnouncedNetworkCheck().run(daemon_name, daemon_test["networks"], lab)
                    test_collector.add_check_results(lab_name, check_results)

                if "evpn" in daemon_test:
                    logger.info(f"Checking EVPN configurations...")
                    evpn_test = daemon_test["evpn"]
                    for test in evpn_test:
                        if "evpn_sessions" in test:
                            logger.info(f"Checking EVPN session configuration...")
                            check_results = EVPNSessionCheck().run(evpn_test["evpn_sessions"], lab)
                            test_collector.add_check_results(lab_name, check_results)

                        if "vtep_devices" in test:
                            logger.info(f"Checking VTEP devices configuration...")
                            check_results = VTEPCheck().run(evpn_test["vtep_devices"], lab)
                            test_collector.add_check_results(lab_name, check_results)

                            logger.info(f"Checking BGP VNIs configurations...")
                            check_results = AnnouncedVNICheck().run(
                                evpn_test["vtep_devices"], evpn_test["evpn_sessions"], lab
                            )
                            test_collector.add_check_results(lab_name, check_results)

            if "injections" in daemon_test:
                logger.info(f"Checking {daemon_name} protocols redistributions...")
                check_results = ProtocolRedistributionCheck().run(daemon_name, daemon_test["injections"], lab)
                test_collector.add_check_results(lab_name, check_results)

    if "kernel_routes" in configuration["test"]:
        logger.info(f"Checking Routing Tables...")
        check_results = KernelRouteCheck().run(configuration["test"]["kernel_routes"], lab)
        test_collector.add_check_results(lab_name, check_results)

    if "applications" in configuration["test"]:
        for application_name, application in configuration["test"]["applications"].items():
            if application_name == "dns":
                logger.info("Checking DNS configurations...")
                check_results = DNSAuthorityCheck().run(
                    application["authoritative"],
                    list(application["local_ns"].keys()),
                    configuration["test"]["ip_mapping"],
                    lab,
                )
                test_collector.add_check_results(lab_name, check_results)

                logger.info("Checking local name servers configurations...")
                check_results = LocalNSCheck().run(application["local_ns"], lab)
                test_collector.add_check_results(lab_name, check_results)

                logger.info(f"Starting reachability test for DNS...")
                check_results = ReachabilityCheck().run(reverse_dictionary(application["reachability"]), lab)
                test_collector.add_check_results(lab_name, check_results)

    if not live and not keep_open:
        logger.info("Undeploying Network Scenario")
        manager.undeploy_lab(lab=lab)

    total_tests = len(test_collector.tests[lab_name])
    test_results = list(map(lambda x: x.passed, test_collector.tests[lab_name]))
    logger.info(f"Total Tests: {total_tests}")
    logger.info(f"Passed Tests: {test_results.count(True)}/{total_tests}")

    if not skip_report:
        logger.info(f"Writing test report for {lab_name} in: {lab_path}...")
        write_result_to_excel(test_collector.tests[lab_name], lab_path)

    return test_collector


def run_on_multiple_network_scenarios(labs_path: str, configuration: dict, lab_template: Lab, no_cache: bool = False,
                                      live: bool = False, keep_open: bool = False, skip_report: bool = False):
    logger = logging.getLogger("kathara-lab-checker")
    labs_path = os.path.abspath(labs_path)

    logger.info(f"Parsing network scenarios in: {labs_path}")

    test_collector = TestCollector()
    for lab_name in tqdm(
            list(
                filter(
                    lambda x: os.path.isdir(os.path.join(labs_path, x)) and x != ".DS_Store",
                    os.listdir(labs_path),
                )
            )
    ):
        test_results = run_on_single_network_scenario(
            os.path.join(labs_path, lab_name), configuration, lab_template, no_cache, live, keep_open, skip_report
        )

        if test_results:
            test_collector.add_check_results(lab_name, test_results.tests[lab_name])

    if test_collector.tests and not skip_report:
        logger.info(f"Writing All Test Results into: {labs_path}")
        write_final_results_to_excel(test_collector, labs_path)


def parse_arguments():
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
        '-v', '--version',
        action='version',
        version=f'kathara-lab-checker {VERSION}'
    )

    parser.add_argument(
        "--no-cache",
        required=False,
        action="store_true",
        default=False,
        help="Re-process all the tests",
    )

    parser.add_argument(
        "--live",
        required=False,
        action="store_true",
        default=False,
        help="Do not deploy/undeploy the network scenarios",
    )

    parser.add_argument(
        "--keep-open",
        required=False,
        action="store_true",
        default=False,
        help="Do not undeploy the network scenarios",
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "--lab",
        required=False,
        help="The path to the network scenario to check",
    )

    group.add_argument(
        "--labs",
        required=False,
        help="The path to a directory containing multiple network scenarios to check with the same configuration",
    )

    parser.add_argument(
        "--skip-report",
        required=False,
        action="store_true",
        default=False,
        help="Skip the generation of the report",
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    signal.signal(signal.SIGINT, partial(handler, live=args.live))

    logger = logging.getLogger("kathara-lab-checker")
    # logger.addHandler(TqdmLoggingHandler())

    coloredlogs.install(fmt="%(message)s", level="INFO", logger=logger)

    logger.propagate = False

    logger.info("Parsing test configuration...")
    with open(args.config, "r") as json_conf:
        conf = json.load(json_conf)

    Setting.get_instance().load_from_dict({"image": conf["default_image"]})

    logger.info(f"Parsing network scenarios template in: {conf['structure']}")
    template_lab = LabParser().parse(
        os.path.dirname(conf["structure"]),
        conf_name=os.path.basename(conf["structure"]),
    )

    if args.lab:
        run_on_single_network_scenario(args.lab, conf, template_lab, args.no_cache, args.live, args.keep_open,
                                       args.skip_report)
    elif args.labs:
        run_on_multiple_network_scenarios(args.labs, conf, template_lab, args.no_cache, args.live, args.keep_open,
                                          args.skip_report)


if __name__ == "__main__":
    main()
