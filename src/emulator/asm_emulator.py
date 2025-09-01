from unicorn import UC_PROT_ALL
import unicorn as uc

from fileloader.asm import ASMFile
from config.emulation_config import RSTEmulationConfig
from emulator.unicorn_engine import UnicornEngine


class ASMEmulator(UnicornEngine):
    def __init__(self, asm_file: ASMFile, config: RSTEmulationConfig):
        super().__init__(config)
        self.asm_file = asm_file
        self.config = config
        self.initial_address = 0x1000000

    def prepare_emulation(self):
        self._ensure_thumb_mode()
        self.emulation_add_hooks()
        self.map_memory(self.initial_address, 1024,
                        UC_PROT_ALL, self.asm_file.byte_code)

    def start_emulation(self):
        self.prepare_emulation()
        self.emu_engine.emu_start(self.initial_address | 1,
                                  self.initial_address + len(self.asm_file))
        print(self.emu_engine.reg_read(uc.arm_const.UC_ARM_REG_R0))
        print(self.emu_engine.mem_read(0x4000000, 4).hex())

    def _ensure_thumb_mode(self) -> bool:
        """
        Sets the the thumb mode register

        Returns:
            bool: Thumb mode is enabled
        """

        cpsr = self.emu_engine.reg_read(uc.arm_const.UC_ARM_REG_CPSR)
        self.emu_engine.reg_write(
            uc.arm_const.UC_ARM_REG_CPSR, cpsr | (1 << 5))
        return (self.emu_engine.reg_read(uc.arm_const.UC_ARM_REG_CPSR) & (1 << 5)) != 0
