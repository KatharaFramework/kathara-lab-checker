import logging
from abc import ABC, abstractmethod
from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab


class AbstractCheck(ABC):

    __slots__ = [ "lab", "description", "priority", "kathara_manager", "logger"]

    def __init__(self, lab: Lab, description: str = None, priority: int = 0):
        self.lab: Lab = lab
        self.description: str = description
        self.priority: int = priority
        self.kathara_manager: Kathara = Kathara.get_instance()
        self.logger = logging.getLogger("kathara-lab-checker")


    @abstractmethod
    def run_from_configuration(self, configuration: dict):
        raise NotImplementedError("You must implement `run_from_configuration` method.")
