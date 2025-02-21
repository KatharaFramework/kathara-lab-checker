#!/usr/bin/env python3
import argparse
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

from .TestCollector import TestCollector
from .checks.BridgeCheck import BridgeCheck
from .checks.CollisionDomainCheck import CollisionDomainCheck
from .checks.CustomCommandCheck import CustomCommandCheck
from .checks.DaemonCheck import DaemonCheck
from .checks.DeviceExistenceCheck import DeviceExistenceCheck
from .checks.IPv6EnabledCheck import IPv6EnabledCheck
from .checks.InterfaceIPCheck import InterfaceIPCheck
from .checks.KernelRouteCheck import KernelRouteCheck
from .checks.ReachabilityCheck import ReachabilityCheck
from .checks.StartupExistenceCheck import StartupExistenceCheck
from .checks.SysctlCheck import SysctlCheck
from .checks.applications.dns.DNSAuthorityCheck import DNSAuthorityCheck
from .checks.applications.dns.DNSRecordCheck import DNSRecordCheck
from .checks.applications.dns.LocalNSCheck import LocalNSCheck
from .checks.protocols.AnnouncedNetworkCheck import AnnouncedNetworkCheck
from .checks.protocols.ProtocolRedistributionCheck import ProtocolRedistributionCheck
from .checks.protocols.bgp.BGPNeighborCheck import BGPNeighborCheck
from .checks.protocols.bgp.BGPRoutesCheck import BGPRoutesCheck
from .checks.protocols.evpn.AnnouncedVNICheck import AnnouncedVNICheck
from .checks.protocols.evpn.EVPNSessionCheck import EVPNSessionCheck
from .checks.protocols.evpn.VTEPCheck import VTEPCheck
from .excel_utils import write_final_results_to_excel, write_result_to_excel
from .model.CheckResult import CheckResult
from .utils import reverse_dictionary

VERSION = "0.1.8"
CURRENT_LAB: Optional[Lab] = None


def handler(signum, frame, live=False):
    logger = logging.getLogger("kathara-lab-checker")
    if CURRENT_LAB and not live:
        logger.warning(f"\nCtrl-C was pressed. Undeploying current lab in: {CURRENT_LAB.fs_path()}")
        Kathara.get_instance().undeploy_lab(lab=CURRENT_LAB)
    exit(1)


def run_on_single_network_scenario(
        lab_path: str,
        configuration: dict,
        lab_template: Lab,
        no_cache: bool = False,
        live: bool = False,
        keep_open: bool = False,
        report_type: str = "csv",
):
    global CURRENT_LAB
    logger = logging.getLogger("kathara-lab-checker")

    manager = Kathara.get_instance()
    test_collector = TestCollector()

    lab_path = os.path.abspath(lab_path)
    lab_name = os.path.basename(lab_path)

    if not os.path.isdir(lab_path):
        logger.warning(f"{lab_path} is not a lab directory.")
        return

    test_results_path_xlsx = os.path.join(lab_path, f"{lab_name}_result.xlsx")
    test_results_path_csv = os.path.join(lab_path, f"{lab_name}_result_all.csv")
    if (os.path.exists(test_results_path_xlsx) or os.path.exists(test_results_path_csv)) and not no_cache:
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
        check_results = [CheckResult("The lab.conf cannot be parsed", False, str(e))]
        test_collector.add_check_results(lab_name, check_results)
        return test_collector
    except MachineCollisionDomainError as e:
        logger.warning(f"{str(e)} Skipping directory")
        check_results = [CheckResult("The lab.conf cannot be parsed", False, str(e))]
        test_collector.add_check_results(lab_name, check_results)
        return test_collector

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
    check_results = DeviceExistenceCheck(lab).run(list(lab_template.machines.keys()))
    test_collector.add_check_results(lab_name, check_results)

    logger.info("Checking collision domains...")
    check_results = CollisionDomainCheck(lab).run(list(lab_template.machines.values()))
    test_collector.add_check_results(lab_name, check_results)

    if "requiring_startup" in configuration["test"]:
        logger.info("Checking that all required startup files exist...")
        check_results = StartupExistenceCheck(lab).run(configuration["test"]["requiring_startup"])
        test_collector.add_check_results(lab_name, check_results)

    if "ipv6_enabled" in configuration["test"]:
        logger.info(f"Checking that IPv6 is enabled on devices: {configuration['test']['ipv6_enabled']}")
        check_results = IPv6EnabledCheck(lab).run(configuration["test"]["ipv6_enabled"])
        test_collector.add_check_results(lab_name, check_results)

    if "sysctls" in configuration["test"]:
        logger.info(f"Checking sysctl configurations on devices...")
        check_results = SysctlCheck(lab).run(configuration["test"]["sysctls"])
        test_collector.add_check_results(lab_name, check_results)

    if "ip_mapping" in configuration["test"]:
        logger.info("Verifying the IP addresses assigned to devices...")
        check_results = InterfaceIPCheck(lab).run(configuration["test"]["ip_mapping"])
        test_collector.add_check_results(lab_name, check_results)

    if "bridges" in configuration["test"]:
        logger.info("Verifying the bridges inside devices...")
        check_results = BridgeCheck(lab).run(configuration["test"]["bridges"])
        test_collector.add_check_results(lab_name, check_results)

    if "reachability" in configuration["test"]:
        logger.info(f"Starting reachability test...")
        check_results = ReachabilityCheck(lab).run(configuration["test"]["reachability"])
        test_collector.add_check_results(lab_name, check_results)

    if "daemons" in configuration["test"]:
        logger.info(f"Checking if daemons are running...")
        check_results = DaemonCheck(lab).run(configuration["test"]["daemons"])
        test_collector.add_check_results(lab_name, check_results)

    if "protocols" in configuration["test"]:
        logger.info("Checking routing daemons configurations...")
        for daemon_name, daemon_test in configuration["test"]["protocols"].items():
            if daemon_name == "bgpd":
                logger.info(f"Check BGP peerings configurations...")

                if "neighbors" in daemon_test:
                    check_results = BGPNeighborCheck(lab).run(daemon_test["neighbors"])
                    test_collector.add_check_results(lab_name, check_results)

                if "networks" in daemon_test:
                    logger.info(f"Checking BGP announces...")
                    check_results = AnnouncedNetworkCheck(lab).run(daemon_name, daemon_test["networks"])
                    test_collector.add_check_results(lab_name, check_results)

                if "routes" in daemon_test:
                    logger.info(f"Checking BGP Routes...")
                    check_results = BGPRoutesCheck(lab).run(daemon_test["routes"])
                    test_collector.add_check_results(lab_name, check_results)

                if "evpn" in daemon_test:
                    logger.info(f"Checking EVPN configurations...")
                    evpn_test = daemon_test["evpn"]
                    for test in evpn_test:
                        if "evpn_sessions" in test:
                            logger.info(f"Checking EVPN session configuration...")
                            check_results = EVPNSessionCheck(lab).run(evpn_test["evpn_sessions"])
                            test_collector.add_check_results(lab_name, check_results)

                        if "vtep_devices" in test:
                            logger.info(f"Checking VTEP devices configuration...")
                            check_results = VTEPCheck(lab).run(evpn_test["vtep_devices"])
                            test_collector.add_check_results(lab_name, check_results)

                            logger.info(f"Checking BGP VNIs configurations...")
                            check_results = AnnouncedVNICheck(lab).run(
                                evpn_test["vtep_devices"], evpn_test["evpn_sessions"]
                            )
                            test_collector.add_check_results(lab_name, check_results)

            if "injections" in daemon_test:
                logger.info(f"Checking {daemon_name} protocols redistributions...")
                check_results = ProtocolRedistributionCheck(lab).run(daemon_name, daemon_test["injections"])
                test_collector.add_check_results(lab_name, check_results)

    if "kernel_routes" in configuration["test"]:
        logger.info(f"Checking Routing Tables...")
        check_results = KernelRouteCheck(lab).run(configuration["test"]["kernel_routes"])
        test_collector.add_check_results(lab_name, check_results)

    if "applications" in configuration["test"]:
        for application_name, application in configuration["test"]["applications"].items():
            if application_name == "dns":
                if "authoritative" in application:
                    logger.info("Checking DNS configurations...")
                    check_results = DNSAuthorityCheck(lab).run(
                        application["authoritative"],
                        list(application["local_ns"].keys()),
                        configuration["test"]["ip_mapping"],
                    )
                    test_collector.add_check_results(lab_name, check_results)

                if "local_ns" in application:
                    logger.info("Checking local name servers configurations...")
                    check_results = LocalNSCheck(lab).run(application["local_ns"])
                    test_collector.add_check_results(lab_name, check_results)

                if "records" in application:
                    logger.info(f"Starting test for DNS records...")
                    check_results = DNSRecordCheck(lab).run(
                        application["records"], reverse_dictionary(application["local_ns"]).keys()
                    )
                    test_collector.add_check_results(lab_name, check_results)

    if "custom_commands" in configuration["test"]:
        logger.info("Checking custom commands output...")
        check_results = CustomCommandCheck(lab).run(configuration["test"]["custom_commands"])
        test_collector.add_check_results(lab_name, check_results)

    if not live and not keep_open:
        logger.info("Undeploying Network Scenario")
        manager.undeploy_lab(lab=lab)

    total_tests = len(test_collector.tests[lab_name])
    test_results = list(map(lambda x: x.passed, test_collector.tests[lab_name]))
    logger.info(f"Total Tests: {total_tests}")
    logger.info(f"Passed Tests: {test_results.count(True)}/{total_tests}")

    if report_type != "none":
        logger.info(f"Writing test report for {lab_name} in: {lab_path} as {report_type.upper()} report...")
        if report_type == "xlsx":
            write_result_to_excel(test_collector.tests[lab_name], lab_path)
        elif report_type == "csv":
            from .csv_utils import write_result_to_csv
            write_result_to_csv(test_collector.tests[lab_name], lab_path)

    return test_collector


def run_on_multiple_network_scenarios(
        labs_path: str,
        configuration: dict,
        lab_template: Lab,
        no_cache: bool = False,
        live: bool = False,
        keep_open: bool = False,
        report_type: str = "csv",
):
    logger = logging.getLogger("kathara-lab-checker")
    labs_path = os.path.abspath(labs_path)

    logger.info(f"Parsing network scenarios in: {labs_path}")

    test_collector = TestCollector()
    for lab_name in tqdm(
            sorted(
                list(
                    filter(
                        lambda x: os.path.isdir(os.path.join(labs_path, x)) and x != ".DS_Store",
                        os.listdir(labs_path),
                    )
                ),
                key=str.casefold,
            )
    ):
        test_results = run_on_single_network_scenario(
            os.path.join(labs_path, lab_name), configuration, lab_template, no_cache, live, keep_open, report_type
        )

        if test_results:
            test_collector.add_check_results(lab_name, test_results.tests[lab_name])

    if test_collector.tests and report_type != "none":
        logger.info(f"Writing All Test Results into: {labs_path} as {report_type.upper()} report...")
        if report_type == "xlsx":
            write_final_results_to_excel(test_collector, labs_path)
        elif report_type == "csv":
            from .csv_utils import write_final_results_to_csv
            write_final_results_to_csv(test_collector, labs_path)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="A tool for automatically check Kathará network scenarios",
        prog="kathara_lab_checker",
        add_help=True,
    )

    parser.add_argument(
        "--config",
        "-c",
        required=True,
        help="The path to the configuration file for the tests",
    )

    parser.add_argument("-v", "--version", action="version", version=f"kathara-lab-checker {VERSION}")

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
        "--report-type",
        required=False,
        choices=["xlsx", "csv", "none"],
        default="csv",
        help="Report format: 'csv' for a text-based report, 'xlsx' for an Excel spreadsheet, 'none' to skip report"
    )

    return parser.parse_args()


def main():
    args = parse_arguments()
    
    signal.signal(signal.SIGINT, partial(handler, live=args.live))

    logger = logging.getLogger("kathara-lab-checker")

    coloredlogs.install(fmt="%(message)s", level="INFO", logger=logger)

    logger.propagate = False

    logger.info("Parsing test configuration...")
    with open(args.config, "r") as json_conf:
        conf = json.load(json_conf)

    Setting.get_instance().load_from_dict({"image": conf["default_image"]})

    logger.info(f"Parsing network scenarios template in: {conf['structure']}")
    if not os.path.exists(conf["structure"]):
        logger.error(f"The structure file {conf['structure']} does not exist")
        exit(1)

    template_lab = LabParser().parse(
        os.path.dirname(conf["structure"]),
        conf_name=os.path.basename(conf["structure"]),
    )

    if args.lab:
        run_on_single_network_scenario(
            args.lab, conf, template_lab, args.no_cache, args.live, args.keep_open, args.report_type
        )
    elif args.labs:
        run_on_multiple_network_scenarios(
            args.labs, conf, template_lab, args.no_cache, args.live, args.keep_open, args.report_type
        )


if __name__ == "__main__":
    main()
