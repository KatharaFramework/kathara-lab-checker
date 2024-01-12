import logging
from abc import ABC


class AbstractCheck(ABC):

    def __init__(self, description: str = None):
        self.description: str = description
        self.logger = logging.getLogger("kathara-lab-checker")
