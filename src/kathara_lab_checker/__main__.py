#!/usr/bin/env python3
import argparse
import json
import logging
import os
import signal
import tempfile
import time
from functools import partial
from typing import Optional, Any

import coloredlogs
import yaml
from Kathara.exceptions import MachineCollisionDomainError
from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab
from Kathara.parser.netkit.LabParser import LabParser
from Kathara.setting.Setting import Setting
from tqdm import tqdm

from .TestCollector import TestCollector
from .excel_utils import write_final_results_to_excel, write_result_to_excel
from .foundation.checks.CheckFactory import CheckFactory
from .model.CheckResult import CheckResult

VERSION = "0.1.10"
CURRENT_LAB: Optional[Lab] = None


def handler(signum, frame, live=False):
    logger = logging.getLogger("kathara-lab-checker")
    if CURRENT_LAB and not live:
        logger.warning(f"\nCtrl-C was pressed. Undeploying current lab in: {CURRENT_LAB.fs_path()}")
        Kathara.get_instance().undeploy_lab(lab=CURRENT_LAB)
    exit(1)


def run_on_single_network_scenario(
        lab_path: str,
        configuration: dict[str, Any],
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

    if "lab_inline" in configuration:
        logger.info(f"Verifying lab structure using inline lab.conf template")
    else:
        logger.info(f"Verifying lab structure using lab.conf template in: {configuration['structure']}")

    check_instances = CheckFactory().instantiate_classes_from_package_name("kathara_lab_checker.checks", lab)
    for check in check_instances:
        check_results = check.run_from_configuration(configuration)
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
            os.path.join(labs_path, lab_name), configuration, no_cache, live, keep_open, report_type
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


def load_config_and_lab(config_path: str):
    """
    Loads a correction file as JSON or YAML. 
    If 'lab_inline' is set, writes it to a temp file and uses that as 'structure'.
    Returns (conf, structure_file).
    """
    with open(config_path, "r", encoding="utf-8") as f:
        content = f.read()
    try:
        conf = json.loads(content)
    except ValueError:
        try:
            conf = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise ValueError(f"Config file '{config_path}' is neither valid JSON nor YAML:\n{e}")

    inline = conf.get("lab_inline", "")
    if inline:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as tmp:
            tmp.write(inline)
            conf["structure"] = tmp.name

    sfile = conf.get("structure")
    if not sfile or not os.path.exists(sfile):
        raise ValueError("No valid structure file found.")
    return conf, sfile


def main():
    args = parse_arguments()

    signal.signal(signal.SIGINT, partial(handler, live=args.live))

    logger = logging.getLogger("kathara-lab-checker")

    coloredlogs.install(fmt="%(message)s", level="INFO", logger=logger)

    logger.propagate = False

    logger.info("Parsing test configuration...")
    conf, structure = load_config_and_lab(args.config)

    Setting.get_instance().load_from_dict({"image": conf["default_image"]})

    if "lab_inline" in conf:
        logger.info(f"Parsing inline network scenarios template")
    else:
        logger.info(f"Parsing network scenarios template in: {structure}")

    template_lab = LabParser().parse(
        os.path.dirname(structure),
        conf_name=os.path.basename(structure),
    )

    conf["template_lab"] = template_lab
    if args.lab:
        run_on_single_network_scenario(
            args.lab, conf, args.no_cache, args.live, args.keep_open, args.report_type
        )
    elif args.labs:
        run_on_multiple_network_scenarios(
            args.labs, conf, args.no_cache, args.live, args.keep_open, args.report_type
        )


if __name__ == "__main__":
    main()
