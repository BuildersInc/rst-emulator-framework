import unicorn as uc

from fileloader.asm import ASMFile
from config.emulation_config import RSTEmulationConfig
from config.constants import RCGC_GPIO_R
from emulator.unicorn_engine import UnicornEngine


class ASMEmulator(UnicornEngine):
    def __init__(self, asm_file: ASMFile, config: RSTEmulationConfig):
        super().__init__(config)
        self.asm_file = asm_file
        self.config = config

    def prepare_emulation(self) -> None:
        self.emulation_add_hooks()
        self.load_code(self.asm_file)

    def start_emulation(self) -> None:
        self.prepare_emulation()
        self.emu_engine.emu_start(self.config.CODE_START | 1,
                                  self.config.CODE_START + self.asm_file.instruction_count)
        print(self.emu_engine.reg_read(uc.arm_const.UC_ARM_REG_R0))
        print(self.emu_engine.mem_read(RCGC_GPIO_R, 4).hex())
