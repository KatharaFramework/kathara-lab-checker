from abc import ABC


class AbstractCheck(ABC):

    def __init__(self, description: str):
        self.description: str = description
