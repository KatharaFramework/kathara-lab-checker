import os
import csv

def write_final_results_to_csv(test_collector, path: str):
    """
    Writes the overall summary report for all labs.
    The CSV contains the same columns as the Excel summary:
    "Student Name", "Tests Passed", "Tests Failed", "Tests Total Number", "Problems".
    """
    csv_file = os.path.join(path, "results.csv")
    with open(csv_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Student Name", "Tests Passed", "Tests Failed", "Tests Total Number", "Problems"])
        for lab_name, test_results in test_collector.tests.items():
            failed_tests = [tr for tr in test_results if not tr.passed]
            passed_tests = [tr for tr in test_results if tr.passed]
            if failed_tests:
                failed_string = ""
                for idx, failed in enumerate(failed_tests, 1):
                    failed_string += f"{idx}: {failed.description}: {failed.reason}\n"
                # (Excel truncates long cells; CSV remains untruncated)
            else:
                failed_string = "None"
            writer.writerow([lab_name, len(passed_tests), len(failed_tests), len(test_results), failed_string.strip()])


def write_result_to_csv(check_results: list, path: str):
    """
    Writes detailed test results in three CSV files (mimicking Excel's multiple sheets):
      - A summary CSV file (with total tests, passed tests, and failed tests).
      - An "all" results CSV file (listing every test result).
      - A "failed" results CSV file (listing only failed tests).
    The files are named based on the base name of the given path.
    """
    base_name = os.path.basename(path)

    # Summary CSV
    summary_file = os.path.join(path, f"{base_name}_result_summary.csv")
    with open(summary_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Total Tests", "Passed Tests", "Failed"])
        total = len(check_results)
        passed = len([r for r in check_results if r.passed])
        failed = len([r for r in check_results if not r.passed])
        writer.writerow([total, passed, failed])

    # "All" Results CSV
    all_file = os.path.join(path, f"{base_name}_result_all.csv")
    with open(all_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Test Description", "Passed", "Reason"])
        for r in check_results:
            writer.writerow([r.description, r.passed, r.reason])

    # "Failed" Results CSV
    failed_file = os.path.join(path, f"{base_name}_result_failed.csv")
    with open(failed_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Test Description", "Passed", "Reason"])
        for r in check_results:
            if not r.passed:
                writer.writerow([r.description, r.passed, r.reason])
