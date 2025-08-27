from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_ARM,  UcError
import unicorn as uc

from fileloader.asm import ASMFile


class ASMEmulator:
    def __init__(self, asm_file: ASMFile):
        self.asm_file = asm_file
        self.initial_address = 0x1000000

    def emulate(self):
        uc_em = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc_em.mem_map(self.initial_address, 1024, uc.UC_PROT_ALL)
        uc_em.mem_map(0x2000000, 1024, uc.UC_PROT_ALL)
        uc_em.mem_write(self.initial_address, self.asm_file.byte_code)
        uc_em.mem_write(0x2000000, bytes([0x00] * 64))
        uc_em.emu_start(self.initial_address,
                        self.initial_address + len(self.asm_file.byte_code))

        print("Emulation Process Completed")
        print(f"RO {uc_em.reg_read(uc.arm_const.UC_ARM_REG_R0)}")
        print(f"RCGC {uc_em.mem_read(0x2000000, 4)}")
