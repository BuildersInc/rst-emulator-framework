from datetime import timedelta
from typing import List

from config.emulation_config import RSTEmulationConfig, default_config
from config.TM4C123GH6PM import APB_GPIO_PORT_F
from emulator.unicorn_engine import UnicornEngine
from rst_testcase.pre_condition import (GPIO_PORT_F_DIR, GPIO_PORT_F_PUR,
                                        RCGC_PORT_F_IS_SET, PreCondition)
from rst_testcase.testcase import Direction, IOEvent, Testcase


class GpioPortFDen(PreCondition):
    """
    Example Precondition
    """
    def check_pre_condition(self, emulation: UnicornEngine) -> bool:
        return emulation.mask_is_set(APB_GPIO_PORT_F.DEN, 0x10)


TEST_DEPENDENCIES: List[str] = [

]

TEST_UC_CONFIG: RSTEmulationConfig = default_config()

TESTCASE = Testcase()


btn_press = IOEvent(
    Direction.INPUT,
    APB_GPIO_PORT_F,
    0x10,
    "TestEvent",
    timedelta(seconds=1)
)
btn_press.add_precondition(RCGC_PORT_F_IS_SET("RCGC Check"))
btn_press.add_precondition(GpioPortFDen("DEN Check"))
btn_press.add_precondition(GPIO_PORT_F_DIR("DIR Check"))
btn_press.add_precondition(GPIO_PORT_F_PUR("PUR Check"))

TESTCASE.attach_event(btn_press)
