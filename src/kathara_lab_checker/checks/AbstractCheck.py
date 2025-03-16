import logging
from abc import ABC
from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab


class AbstractCheck(ABC):

    __slots__ = ["description", "logger", "kathara_manager", "lab"]

    def __init__(self, lab: Lab, description: str = None):
        self.description: str = description
        self.logger = logging.getLogger("kathara-lab-checker")
        self.kathara_manager: Kathara = Kathara.get_instance()
        self.lab: Lab = lab
