import re

from Kathara.exceptions import MachineNotRunningError
from Kathara.model.Lab import Lab

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....model.FailedCheck import FailedCheck
from ....model.SuccessfulCheck import SuccessfulCheck
from ....utils import get_output, key_exists


class HTTPCheck(AbstractCheck):
    """
    Execute HTTP checks using curl on the remote device.
    """

    def __init__(self, lab: Lab, configuration: dict, description: str = None):
        super().__init__(lab, configuration, description=description, priority=3040)

    def check(self, device_name: str, test_params: dict):
        """
        Runs curl on the device with the given parameters:
          {
            "url": "<required>",
            "method": "<optional, default=GET>",
            "status_code": 200,
            "regex_body": "<regex to match>",
            "body_contains": "<literal substring>"
          }
        Returns one or more CheckResult objects.
        """
        url = test_params.get("url")
        if not url:
            desc = f"HTTP Check on {device_name} missing 'url'"
            self.results.append(FailedCheck(desc, "No 'url' provided"))
            return

        desc = f"HTTP check '{url}' on {device_name}"

        method = test_params.get("method", "GET").upper()

        # Use curl to output both body and HTTP code separated by a unique delimiter.
        delimiter = "===CURL_STATUS==="
        curl_cmd = f"curl -s -X {method} -w '{delimiter}%{{http_code}}' '{url}'"

        try:
            exec_output = self.kathara_manager.exec(
                machine_name=device_name,
                command=curl_cmd,
                lab_hash=self.lab.hash
            )
        except MachineNotRunningError as e:
            self.results.append(FailedCheck(desc, str(e)))
            return

        combined_output = get_output(exec_output).strip()
        if delimiter in combined_output:
            body, code_str = combined_output.rsplit(delimiter, 1)
        else:
            body = combined_output
            code_str = ""

        expected_code = test_params.get("status_code", 200)
        if not code_str.isdigit():
            self.results.append(FailedCheck(desc, f"curl output did not contain a valid status code: '{code_str}'"))
        else:
            actual_code = int(code_str)
            if actual_code == expected_code:
                self.results.append(SuccessfulCheck(f"{desc} status", f"HTTP {actual_code} == {expected_code}"))
            else:
                self.results.append(FailedCheck(f"{desc} status",
                                           f"Expected HTTP {expected_code}, got {actual_code}"))

        if "regex_body" in test_params or "body_contains" in test_params:
            if "regex_body" in test_params:
                regex = test_params["regex_body"]
                regex_desc = f"{desc} body regex /{regex}/"
                if re.search(regex, body):
                    self.results.append(SuccessfulCheck(regex_desc, "OK"))
                else:
                    self.results.append(FailedCheck(regex_desc, "Body does not match regex"))

            if "body_contains" in test_params:
                substr = test_params["body_contains"]
                substr_desc = f"{desc} body substring '{substr}'"
                if substr in body:
                    self.results.append(SuccessfulCheck(substr_desc, "OK"))
                else:
                    self.results.append(FailedCheck(substr_desc, "Substring not found in body"))

    def run(self, device_http_tests: dict[str, list[dict]]):
        """
        device_http_tests = {
          "device_name": [
            { "url": "<required>", "method": "GET", "status_code": 200, "regex_body": "foo|bar" },
            { "url": "<another_url>", "body_contains": "hello world" }
          ],
          ...
        }
        """
        for device_name, checks in device_http_tests.items():
            self.logger.info(f"Performing HTTP checks on {device_name}...")
            for check_params in checks:
                self.check_with_timeout(device_name, check_params)

    def run_from_configuration(self):
        if key_exists(["test", "applications", "http"], self.configuration):
            self.logger.info("Checking HTTP endpoints via cURL...")
            self.run(self.configuration["test"]["applications"]["http"])
