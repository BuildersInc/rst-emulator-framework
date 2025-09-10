from abc import ABC, abstractmethod
import logging

from emulator.unicorn_engine import UnicornEngine
from config.TM4C123GH6PM import APB_GPIO_PORT_F, RCGC_GPIO_R


class PreCondition(ABC):
    def __init__(self, name: str):
        super().__init__()
        self.passed = False
        self.name = name

    @abstractmethod
    def check_pre_condition(self, emulation: UnicornEngine) -> bool:
        pass

    def _check_precon(self, emulation: UnicornEngine) -> bool:
        self.passed = self.check_pre_condition(emulation)
        logging.debug("precon %s, was %s", self.name,
                      "Successful" if self.passed else "Not Successful")

        return self.passed


# pylint: disable=C0103, R0903
class RCGC_PORT_F_IS_SET(PreCondition):
    """
    Checks if RCGC Register on Port F is set

    """
    def check_pre_condition(self, emulation: UnicornEngine) -> bool:
        return emulation.mask_is_set(RCGC_GPIO_R, 0x20)


class GPIO_PORT_F_DEN(PreCondition):
    """
    Checks if DEN on Port F is set for SW1
    """
    def check_pre_condition(self, emulation: UnicornEngine) -> bool:
        return emulation.mask_is_set(APB_GPIO_PORT_F.DEN, 0x10)


class GPIO_PORT_F_DIR(PreCondition):
    """
    Checks if DIR on Port F is cleared for SW1
    """

    def check_pre_condition(self, emulation: UnicornEngine) -> bool:
        return emulation.mask_is_clear(APB_GPIO_PORT_F.DIR, 0x10)


class GPIO_PORT_F_PUR(PreCondition):
    """
    Checks if PUR on Port F is set for SW1
    """
    def check_pre_condition(self, emulation: UnicornEngine) -> bool:
        return emulation.mask_is_set(APB_GPIO_PORT_F.PUR, 0x10)
# pylint: enable=all
