
import logging
from datetime import timedelta
from enum import Enum, auto
from typing import List

from config.TM4C123GH6PM import GPIO
from emulator.unicorn_engine import UnicornEngine
from rst_testcase.pre_condition import PreCondition


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

    def trigger_input(self, emulation: UnicornEngine):

        all_passed = all([precon._check_precon(emulation) for precon in self._precon])

        # for precon in self._precon:
        #     all_passed = precon._check_precon(emulation)
        if not all_passed:
            return
        logging.info("All Precons passed")
        if self.direction == Direction.OUTPUT:
            raise IOError("IO Event must be of type input for an Input Trigger")
        if not self._is_pressed:
            self._set_input(emulation)
        else:
            self._release_input(emulation)

    def check_condition(self, emulation: UnicornEngine):
        check = emulation.mask_is_set(self.gpio_bank.DATA, self.port)
        if not check:
            self._tries += 1

        if self._tries == 30:
            self.failed = True

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
        emulation.safe_set_value_in_memory(self.gpio_bank.DATA, self.port)

    def _release_input(self, emulation: UnicornEngine):
        emulation.safe_clear_value_in_memory(self.gpio_bank.DATA, self.port)

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, value):
        if value > 0xFF:
            raise ValueError(f"Port value must be below 255! is {value}")
        self._port = value


class Testcase:
    def __init__(self):
        self.event_list: List[IOEvent] = []

    def attach_event(self, event: IOEvent):
        self.event_list.append(event)

    def attach_multiple_events(self, event_list: List[IOEvent]):
        for event in event_list:
            self.attach_event(event)

    def all_failed(self) -> bool:
        return all([x.failed for x in self])

    def all_passed(self) -> bool:
        return all([x.passed for x in self])

    def __iter__(self):
        return iter(self.event_list)
