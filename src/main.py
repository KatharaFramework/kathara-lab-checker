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

from TestCollector import TestCollector
from checks.CollisionDomainCheck import CollisionDomainCheck
from checks.DaemonCheck import DaemonCheck
from checks.DeviceExistenceCheck import DeviceExistenceCheck
from checks.InterfaceIPCheck import InterfaceIPCheck
from checks.KernelRouteCheck import KernelRouteCheck
from checks.ReachabilityCheck import ReachabilityCheck
from checks.StartupExistenceCheck import StartupExistenceCheck
from checks.applications.dns.DNSAuthorityCheck import DNSAuthorityCheck
from checks.applications.dns.LocalNSCheck import LocalNSCheck
from checks.protocols.ProtocolRedistributionCheck import ProtocolRedistributionCheck
from checks.protocols.bgp.BGPNetworkCheck import BGPNetworkCheck
from checks.protocols.bgp.BGPPeeringCheck import BGPPeeringCheck
from utils import reverse_dictionary, write_final_results_to_excel, write_result_to_excel

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
        check_results = DeviceExistenceCheck().run(list(lab_template.machines.keys()), lab)
        test_collector.add_check_results(lab_dir, check_results)

        logger.info("Checking collision domains...")
        check_results = CollisionDomainCheck().run(list(lab_template.links.values()), lab)
        test_collector.add_check_results(lab_dir, check_results)

        logger.info("Checking that all required startup files exist...")
        check_results = StartupExistenceCheck().run(configuration["test"]["requiring_startup"], lab)
        test_collector.add_check_results(lab_dir, check_results)

        logger.info("Verifying the IP addresses assigned to devices...")
        check_results = InterfaceIPCheck().run(configuration["test"]["ip_mapping"], lab)
        test_collector.add_check_results(lab_dir, check_results)

        logger.info(f"Starting reachability test...")
        check_results = ReachabilityCheck().run(configuration["test"]["reachability"], lab)
        test_collector.add_check_results(lab_dir, check_results)

        logger.info(f"Checking if daemons are running...")
        check_results = DaemonCheck().run(configuration["test"]["daemons"], lab)
        test_collector.add_check_results(lab_dir, check_results)

        logger.info("Checking routing daemons configurations...")
        for daemon_name, daemon_test in configuration["test"]["protocols"].items():
            if daemon_name == "bgpd":
                logger.info(f"Check BGP peerings configurations...")
                check_results = BGPPeeringCheck().run(daemon_test["peerings"], lab)
                test_collector.add_check_results(lab_dir, check_results)

                logger.info(f"Checking BGP announces...")
                check_results = BGPNetworkCheck().run(daemon_test["networks"], lab)
                test_collector.add_check_results(lab_dir, check_results)

            if "injections" in daemon_test:
                logger.info(f"Checking {daemon_name} protocols redistributions...")
                check_results = ProtocolRedistributionCheck().run(daemon_name, daemon_test["injections"], lab)
                test_collector.add_check_results(lab_dir, check_results)

        logger.info(f"Checking Routing Tables...")
        check_results = KernelRouteCheck().run(configuration["test"]["kernel_routes"], lab)
        test_collector.add_check_results(lab_dir, check_results)

        for application_name, application in configuration["test"]["applications"].items():
            if application_name == "dns":
                logger.info("Checking DNS configurations...")
                check_results = DNSAuthorityCheck().run(application["authoritative"],
                                                        list(application["local_ns"].keys()),
                                                        configuration["test"]["ip_mapping"], lab)
                test_collector.add_check_results(lab_dir, check_results)

                logger.info("Checking local name servers configurations...")
                check_results = LocalNSCheck().run(application["local_ns"], lab)
                test_collector.add_check_results(lab_dir, check_results)

                logger.info(f"Starting reachability test for DNS...")
                check_results = ReachabilityCheck().run(reverse_dictionary(application["reachability"]), lab)
                test_collector.add_check_results(lab_dir, check_results)

        logger.info("Undeploying Network Scenario")
        manager.undeploy_lab(lab=lab)

        total_tests = len(test_collector.tests[lab_dir])
        test_results = list(map(lambda x: x.passed, test_collector.tests[lab_dir]))
        failed_tests = test_collector.get_failed(lab_dir)
        logger.info(f"Total Tests: {total_tests}")
        logger.info(f"Passed Tests: {test_results.count(True)}/{total_tests}")

        logger.info(f"Writing test report for {lab_dir} in: {lab_path}...")
        write_result_to_excel(test_collector.tests[lab_dir], lab_path)

    if test_collector.tests:
        logger.info(f"Writing All Test Results into: {labs_path}")
        write_final_results_to_excel(test_collector, labs_path)
