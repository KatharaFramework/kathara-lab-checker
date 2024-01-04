def log_red(s):
    print(f"\033[91m {s}\033[00m")


def log_green(s):
    print(f'\033[92m {s}\033[00m')


def log_yellow(s):
    print(f"\033[93m {s}\033[00m")


def log(message: str, end: str = "\n"):
    print(message, end=end)
