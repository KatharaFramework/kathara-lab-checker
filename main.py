import json
import os
import time

from Kathara.manager.Kathara import Kathara
from Kathara.parser.netkit.LabParser import LabParser
from Kathara.setting.Setting import Setting

import lib
import logger

if __name__ == '__main__':
    Setting.get_instance().load_from_dict({"image": "kathara/frr"})
    manager = Kathara.get_instance()

    logger.log("Reading Test configuration...")
    with open("configuration.json", "r") as json_conf:
        configuration = json.load(json_conf)

    labs_path = os.path.abspath(configuration['labs_path'])
    logger.log(f"Parsing network scenarios in: {labs_path}")
    for lab_path in os.listdir(labs_path):
        lab_path = os.path.join(labs_path, lab_path)

        logger.log(f"Parsing network scenario in: {lab_path}")
        lab = LabParser().parse(lab_path)

        logger.log(f"Undeploying network scenario...")
        manager.undeploy_lab(lab=lab)
        logger.log(f"Deploying network scenario...")
        manager.deploy_lab(lab=lab)

        logger.log(f"Waiting convergence...")
        time.sleep(configuration['convergence_time'])

        logger.log(f"Starting tests")
        collected_tests = []
        logger.PASSED_TEST = []
        logger.FAILED_TEST = []

        logger.log(f"Verifying lab structure using lab.conf template in: {configuration['structure']}")
        lab_template = LabParser().parse(configuration['structure'])

        logger.log("Checking that all devices exist...")
        collected_tests.extend(lib.check_devices(lab, lab_template))
        logger.log("Checking collision domains...")
        collected_tests.extend(lib.check_collision_domains(lab, lab_template))

        logger.log(f"Starting reachability test...")
        for device_name, ips_to_reach in configuration['test']['reachability'].items():
            for ip in ips_to_reach:
                collected_tests.append(
                    lib.verifying_reachability_from_device(device_name, ip, lab))

        logger.log(f"Checking if daemons are running...")
        for daemon, devices in configuration['test']['daemons'].items():
            logger.log(f"Checking if {daemon} is running on {devices}")
            for device_name in devices:
                collected_tests.append(lib.check_running_daemon(device_name, daemon, lab))

        logger.log("Checking routing daemons configurations...")
        for daemon_name, daemon_test in configuration['test']['protocols'].items():
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
                            lib.check_protocol_injection(device, daemon_name, injected_protocol, lab))

        logger.log(f"Checking Routing Tables...")
        for device_name, routes in configuration['test']['kernel_routes'].items():
            logger.log(f"Checking Routing Table of {device_name}")
            device = lab.get_machine(device_name)
            device_routes = lib.get_kernel_routes(device, lab)
            for route in routes:
                next_hop = None
                if type(route) == list:
                    next_hop = route[1]
                    route = route[0]
                collected_tests.append(lib.check_kernel_route(route, next_hop, device_routes))

        for application_name, application in configuration['test']['applications'].items():
            if application_name == "dns":
                logger.log("Checking DNS configurations...")
                for domain, name_servers in application['authoritative'].items():
                    for ns in name_servers:
                        collected_tests.append(lib.check_dns_authority_for_domain(domain, ns, "as1r1", lab))

                logger.log("Checking local name servers configurations...")
                for local_ns, managed_devices in application['local_ns'].items():
                    for device in managed_devices:
                        collected_tests.append(lib.check_local_name_server_for_device(local_ns, device, lab))

                for dns_name, devices in application['reachability'].items():
                    logger.log(f"Checking reachability of dns name `{dns_name}` from `{devices}`...")
                    for device_name in devices:
                        collected_tests.append(
                            lib.verifying_dns_name_reachability_from_device(device_name, dns_name, lab))

        logger.log("Undeploying Network Scenario")
        manager.undeploy_lab(lab=lab)

        total_tests = len(collected_tests)
        test_results = list(map(lambda x: x[1], collected_tests))
        failed_tests = list(filter(lambda x: not x[1], collected_tests))
        logger.log(f"Total Tests: {total_tests}")
        logger.log(f"Passed Tests: {test_results.count(True)}/{total_tests}")

        report_path = os.path.join(lab.fs_path(), "failed.txt")
        if failed_tests:
            logger.log(f"Writing FAILED test report to: {report_path}")
            with open(report_path, "w") as result_file:
                result_file.write("############ Failed Tests ############")
                for idx, failed in enumerate(failed_tests):
                    result_file.write(f"################# {idx} #################\n")
                    result_file.write(f"Test: {failed[0]}\nResult: {failed[1]}\nReason: {failed[2]}\n")

        elif os.path.exists(report_path):
            os.remove(report_path)
