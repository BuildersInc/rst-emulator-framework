from enum import Enum, auto
import logging
from datetime import datetime, timedelta

import unicorn as uc

from fileloader.asm import ASMFile
from config.emulation_config import RSTEmulationConfig
from emulator.unicorn_engine import UnicornEngine

from rst_testcase.testsuite import Testsuite


class EMULATIONSTATUS(Enum):
    NOT_STARTED = auto()
    RUNNING = auto()
    SUCCESS = auto()
    WATCHDOG_TIMEOUT_REACHED = auto()
    TESTCASE_FAILURE = auto()


class ASMEmulator(UnicornEngine):
    def __init__(self, asm_file: ASMFile, config: RSTEmulationConfig):
        super().__init__(config)
        self.asm_file = asm_file
        self.config = config
        self.executed_instruction_count: int = 0
        self.start_time: datetime = None
        self.status = EMULATIONSTATUS.NOT_STARTED

    def prepare_emulation(self) -> None:
        self.emulation_add_hooks()
        self.load_code(self.asm_file)

    def non_stop_emulation(self) -> None:
        self.emu_engine.emu_start(self.config.CODE_START | 1,
                                  self.config.CODE_START + self.asm_file.instruction_count)

    def step(self, step_count: int = 1):
        """
        Executes <step_count> Steps of the Simulation

        Args:
            step_count (int, optional): How many steps shall be executed.
                Defaults to 1.
        """
        program_counter = self.emu_engine.reg_read(uc.arm_const.UC_ARM_REG_PC)
        self.emu_engine.emu_start((self.config.CODE_START + program_counter) | 1,
                                  self.config.CODE_START + self.asm_file.instruction_count,
                                  count=step_count)
        self.executed_instruction_count += step_count

    def start_emulation_with_test(self, testcase: Testsuite):
        self.status = EMULATIONSTATUS.RUNNING
        self.start_time = datetime.now()
        max_time = timedelta(seconds=60)

        while self.status == EMULATIONSTATUS.RUNNING:
            if (datetime.now() - self.start_time) > max_time:
                logging.critical("Max time reached")
                self.status = EMULATIONSTATUS.WATCHDOG_TIMEOUT_REACHED
                break

            self.step(self.config.EMULATION_SPEED)
            for event in testcase:
                if event.passed:
                    continue

                if event.is_input():
                    logging.debug("Triggering Input for %s", event.event_name)
                    event.toggle_input(self)
                result = event.check_condition(self, self.start_time)

                if result:
                    event.passed = True
            if testcase.all_failed():
                self.status = EMULATIONSTATUS.TESTCASE_FAILURE
            elif testcase.all_passed():
                self.status = EMULATIONSTATUS.SUCCESS

        for event in testcase:
            elapsed = datetime.now() - self.start_time
            logging.info("Done after %.6f seconds",
                         elapsed.total_seconds())
            logging.info("Emulation exit state %s", str(self.status))
            event.print_result()
