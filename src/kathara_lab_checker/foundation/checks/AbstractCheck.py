import logging
import threading
from abc import ABC, abstractmethod
from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab
from ..model.CheckResult import CheckResult
from ...model.TimedoutCheck import TimedoutCheck


class _GuardedResultsList(list):
    """A list whose append/extend silently drop items once *cancelled* is set.

    A lock around every mutation ensures that a timed-out worker thread that
    is still running cannot append results after cancellation has been
    signalled by the main thread.
    """

    __slots__ = ("_lock", "_cancelled")

    def __init__(self, cancelled: threading.Event) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._cancelled = cancelled

    def append(self, item) -> None:  # type: ignore[override]
        with self._lock:
            if not self._cancelled.is_set():
                list.append(self, item)

    def extend(self, items) -> None:  # type: ignore[override]
        with self._lock:
            if not self._cancelled.is_set():
                list.extend(self, items)

    def _force_append(self, item) -> None:
        """Append unconditionally, bypassing the cancellation guard.

        Used only by check_with_timeout to record TimedoutCheck after
        cancellation has already been signalled.
        """
        with self._lock:
            list.append(self, item)


class AbstractCheck(ABC):

    __slots__ = ["lab", "description", "priority", "kathara_manager", "logger", "results", "cancelled", "configuration", "timeout"]

    def __init__(self, lab: Lab, configuration: dict, description: str = None, priority: int = 0):
        self.lab: Lab = lab
        self.description: str = description
        self.priority: int = priority
        self.kathara_manager: Kathara = Kathara.get_instance()
        self.cancelled: threading.Event = threading.Event()
        self.results: list[CheckResult] = _GuardedResultsList(self.cancelled)
        self.logger = logging.getLogger("kathara-lab-checker")
        self.configuration: dict = configuration
        self.timeout: float = self.get_timeout(configuration)

    def get_timeout(self, configuration: dict) -> float:
        """Return the timeout for this check from the configuration.

        Looks up configuration["timeouts"][<ClassName>] first, then falls back
        to configuration["default_timeout"], then to 60 seconds.
        """
        return configuration.get("timeouts", {}).get(
            type(self).__name__,
            configuration.get("default_timeout", 60)
        )

    def reset_cancelled(self) -> None:
        """Clear the cancellation signal before (re-)running a check."""
        self.cancelled.clear()

    def check_with_timeout(self, *args, **kwargs) -> bool:
        """Run self.check(*args, **kwargs) in a daemon thread with a timeout.

        On timeout the ``cancelled`` event is set to request cooperative
        cancellation. The thread keeps running until it returns naturally, but
        its partial results are still recorded and a TimedoutCheck is appended.

        Returns True if the check completed in time, False otherwise.
        """
        self.cancelled.clear()
        t = threading.Thread(target=self.check, args=args, kwargs=kwargs, daemon=True)
        self.logger.info(f"Starting check '{type(self).__name__}' with timeout {self.timeout} seconds.")
        t.start()
        t.join(timeout=self.timeout)

        timed_out = t.is_alive()
        if timed_out:
            # Signal cancellation first so future worker appends are silently dropped.
            self.cancelled.set()
            self.logger.warning(
                f"Check '{type(self).__name__}' timed out after {self.timeout} seconds. "
            )
            description = self.description if self.description is not None else f"{type(self).__name__} with args={args} kwargs={kwargs if kwargs else ''}"
            # _force_append bypasses the guard so TimedoutCheck is always recorded.
            self.results._force_append(TimedoutCheck(description, self.timeout))
            return False
        return True

    @abstractmethod
    def run_from_configuration(self):
        raise NotImplementedError("You must implement `run_from_configuration` method.")
