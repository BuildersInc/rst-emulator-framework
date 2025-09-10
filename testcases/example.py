from datetime import timedelta
from typing import List

from config.emulation_config import RSTEmulationConfig, default_config
from config.TM4C123GH6PM import APB_GPIO_PORT_F
from emulator.unicorn_engine import UnicornEngine
from rst_testcase.pre_condition import (GPIO_PORT_F_DIR, GPIO_PORT_F_PUR,
                                        RCGC_PORT_F_IS_SET, PreCondition)
from rst_testcase.testcase import Testcase
from rst_testcase.io_event import Direction, IOEvent


class GpioPortFDen(PreCondition):
    """
    Example Precondition
    """
    def check_pre_condition(self, emulation: UnicornEngine) -> bool:
        return emulation.mask_is_set(APB_GPIO_PORT_F.DEN, 0x10)


class BtnPress(IOEvent):
    """
    Example IO Input event
    """
    def pass_condition(self, emulation: UnicornEngine):
        return emulation.mask_is_set(self.gpio_bank.DATA, self.port)


TEST_DEPENDENCIES: List[str] = [

]
"""
Insert for the test needed external dependencies here.
This part is optional

Reserved for the future
"""

TEST_UC_CONFIG: RSTEmulationConfig = default_config()
"""
UC Configuration.
For example the architecture and Mode
"""

TESTCASE = Testcase()
"""
Inits a test case
needs to be populated with events after the initialization
"""


btn_press = BtnPress(
    Direction.INPUT,
    APB_GPIO_PORT_F,
    0x10,
    "TestEvent",
    timedelta(seconds=0)
)
btn_press.add_precondition(RCGC_PORT_F_IS_SET("RCGC Check"))
btn_press.add_precondition(GpioPortFDen("DEN Check"))
btn_press.add_precondition(GPIO_PORT_F_DIR("DIR Check"))
btn_press.add_precondition(GPIO_PORT_F_PUR("PUR Check"))

TESTCASE.attach_event(btn_press)
