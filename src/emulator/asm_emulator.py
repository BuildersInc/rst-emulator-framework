import logging
from datetime import datetime, timedelta

import unicorn as uc

from fileloader.asm import ASMFile
from config.emulation_config import RSTEmulationConfig
from emulator.unicorn_engine import UnicornEngine

from rst_testcase.testcase import Testcase


class ASMEmulator(UnicornEngine):
    def __init__(self, asm_file: ASMFile, config: RSTEmulationConfig):
        super().__init__(config)
        self.asm_file = asm_file
        self.config = config
        self.executed_instruction_count: int = 0
        self.start_time: datetime = None

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

    def start_emulation_with_test(self, testcase: Testcase):
        self.start_time = datetime.now()
        running = True
        time_delay = timedelta(seconds=5)
        while running:
            # if (datetime.now() - self.start_time) > time_delay:
            #     running = False
            #     break

            self.step(1)
            for event in testcase:
                if event.passed:
                    continue

                if event.is_input():
                    logging.debug("Triggering Input for %s", event.event_name)
                    event.trigger_input(self)
                result = event.check_condition(self, self.start_time)

                if result:
                    event.passed = True
            if testcase.all_failed() or testcase.all_passed():
                running = False
        for event in testcase:
            print(f"Done after {(datetime.now() - self.start_time).seconds}")
            event.print_result()
