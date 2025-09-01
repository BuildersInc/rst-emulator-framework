from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, \
                    UC_MODE_ARM,  UC_HOOK_CODE
import unicorn as uc

from fileloader.asm import ASMFile


def hook_code(unicorn, addr, size, user_data):
    mem = unicorn.mem_read(addr, size)
    for insn in MD.disasm(mem, addr):
        print(f"{hex(insn.address)}\t{insn.mnemonic}\t{insn.op_str}")
    return True

class ASMEmulator:
    def __init__(self, asm_file: ASMFile):
        self.asm_file = asm_file
        self.initial_address = 0x1000000
        self.uc_em = None

    def emulate(self, verbose: bool = True):
        self.uc_em = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self._map_memory(self.initial_address, 1024, uc.UC_PROT_ALL, self.asm_file.byte_code)
        # base = 0x2000000 & ~0xFFF
        # self._map_memory(0x2000000, 1024, uc.UC_PROT_ALL, bytes([0x00] * 1024))
        # self._map_memory(0x2000000, 1024, uc.UC_PROT_ALL, bytes([0x00] * 1024))
        self._ensure_thumb_mode()

        if verbose:
            self.uc_em.hook_add(UC_HOOK_CODE, hook_code)

        self.uc_em.emu_start(self.initial_address,
                             self.initial_address + len(self.asm_file.byte_code))

        print("Emulation Process Completed")
        print(f"RO {self.uc_em.reg_read(uc.arm_const.UC_ARM_REG_R0)}")
        print(f"R1 {self.uc_em.reg_read(uc.arm_const.UC_ARM_REG_R1)}")
        # print(f"RCGC {self.uc_em.mem_read(0x2000000, 4).hex()}")

    def _ensure_thumb_mode(self) -> bool:
        """
        Sets the the thumb mode register

        Returns:
            bool: Thumb mode is enabled
        """
        cpsr = self.uc_em.reg_read(uc.arm_const.UC_ARM_REG_CPSR)
        self.uc_em.reg_write(uc.arm_const.UC_ARM_REG_CPSR, cpsr | (1 << 5))
        return self.uc_em.reg_read(uc.arm_const.UC_ARM_REG_CPSR) != 0

    def _map_memory(self,
                    address: int,
                    size: int,
                    prot_mode: int,
                    value: bytes
                    ):

        self.uc_em.mem_map(address, size, prot_mode)
        self.uc_em.mem_write(address, value)
