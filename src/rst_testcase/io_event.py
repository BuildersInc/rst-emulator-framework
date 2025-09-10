from enum import Enum, auto
from datetime import datetime, timedelta
import logging

from typing import List

from emulator.unicorn_engine import UnicornEngine
from rst_testcase.pre_condition import PreCondition
from config.TM4C123GH6PM import GPIO

class Direction(Enum):
    INPUT = auto()
    OUTPUT = auto()


class IOEvent:
    def __init__(self, direction: Direction,
                 gpio: GPIO,
                 port: int, event_name: str,
                 time_delay: timedelta) -> None:

        self.direction: Direction = direction
        self.gpio_bank: GPIO = gpio
        self._port: int = 0
        self.port: int = port
        self.time_delay: timedelta = time_delay
        self.passed = False
        self.failed = False
        self._is_pressed = False
        self._tries = 0
        self._precon: List[PreCondition] = []
        self.event_name = f"EVENT:{event_name}"

    def check_precons(self, emulation: UnicornEngine,
                      emulation_start_time: datetime) -> bool | None:

        if datetime.now() - emulation_start_time < self.time_delay:
            return None

        all_passed = all([precon._check_precon(emulation) for precon in self._precon])

        if not all_passed:
            return False

        logging.info("%s: All Precons passed", self.event_name)
        return True

    def trigger_input(self, emulation: UnicornEngine):

        if not self._is_pressed:
            self._set_input(emulation)
        else:
            self._release_input(emulation)

    def pass_condition(self, emulation: UnicornEngine) -> bool:
        """
        Implement a check that checks the emulation / register state

        Args:
            emulation (UnicornEngine): emulation Engine with context

        Returns:
            bool: _description_
        """
        raise NotImplementedError()

    def check_condition(self, emulation: UnicornEngine,
                        emulation_start_time: datetime):
        precon_pass = self.check_precons(emulation, emulation_start_time)
        if precon_pass is None:
            return
        elif precon_pass is False:
            self._tries += 1
            return

        check = self.pass_condition(emulation)
        if not check:
            self._tries += 1
            return

        if self._tries == 30:
            logging.debug("Event %s was Failed", self.event_name)
            self.failed = True
            return

        logging.debug("Event %s was successfull", self.event_name)
        self.passed = True

    def print_result(self):
        if self.failed:
            print("Test Failed")
        else:
            print("Test was successfull")

    def add_precondition(self, precon: PreCondition):
        self._precon.append(precon)

    def is_input(self) -> bool:
        return self.direction == Direction.INPUT

    def _set_input(self, emulation: UnicornEngine):
        if self.direction == Direction.OUTPUT:
            raise IOError("IO Event must be of type input for an Input Trigger")
        emulation.safe_set_value_in_memory(self.gpio_bank.DATA, self.port)

    def _release_input(self, emulation: UnicornEngine):
        if self.direction == Direction.OUTPUT:
            raise IOError("IO Event must be of type input for an Input Trigger")
        emulation.safe_clear_value_in_memory(self.gpio_bank.DATA, self.port)

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, value):
        if value > 0xFF:
            raise ValueError(f"Port value must be below 255! is {value}")
        self._port = value
