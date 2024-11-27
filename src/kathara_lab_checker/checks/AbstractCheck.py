import logging
from abc import ABC
from Kathara.manager.Kathara import Kathara


class AbstractCheck(ABC):

    __slots__ = ["description", "logger", "kathara_manager"]

    def __init__(self, description: str = None):
        self.description: str = description
        self.logger = logging.getLogger("kathara-lab-checker")
        self.kathara_manager: Kathara = Kathara.get_instance()
