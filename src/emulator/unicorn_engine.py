import logging

from unicorn import Uc
import unicorn as uc
import capstone as cs

from config.emulation_config import RSTEmulationConfig


class UnicornEngine():
    def __init__(self, config: RSTEmulationConfig):
        self.config = config
        self.emu_engine: Uc = None
        self.decomp_engine: cs.Cs = None

    def prepare_emulation(self):
        raise NotImplementedError()

    def start_emulation(self):
        raise NotImplementedError()

    def init(self):
        self.init_decomp_engine()
        self.init_emu_engine()

    def init_emu_engine(self):
        self.emu_engine = Uc(self.config.UNICORN_ARCH,
                             self.config.UNICORN_MODE)
        logging.debug("Init Stack")
        self.map_memory(self.config.STACK_BASE, self.config.STACK_SIZE,
                        uc.UC_PROT_ALL, b"\x00" * self.config.STACK_SIZE)

        self.emu_engine.reg_write(uc.arm_const.UC_ARM_REG_SP,
                                  self.config.STACK_BASE + (self.config.STACK_SIZE // 2))
        self.map_memory(0x4000000, 1024,
                        uc.UC_PROT_ALL, b"\x00" * 1024)

    def init_decomp_engine(self):
        self.decomp_engine = cs.Cs(self.config.CAPSTONE_ARCH,
                                   self.config.CAPSTONE_MODE)
        self.decomp_engine.detail = True

    def hook_mem_invalid(self, unicorn, access, address, size, value, user_data):
        pc = unicorn.reg_read(uc.arm_const.UC_ARM_REG_PC)
        if access == uc.UC_MEM_WRITE:
            print(
                f"invalid WRITE of 0x{address:x} at 0x{pc:X}, data size = {size}, data value = 0x{value:x}")
        if access == uc.UC_MEM_READ:
            print(
                f"invalid READ of 0x{address:x} at 0x{pc:X}, data size = {size}")
        if access == uc.UC_MEM_FETCH:
            print(
                f"UC_MEM_FETCH of 0x{address:x} at 0x{pc:X}, data size = {size}")
        if access == uc.UC_MEM_READ_UNMAPPED:
            print(
                f"UC_MEM_READ_UNMAPPED of 0x{address:x} at 0x{pc:X}, data size = {size}")
        if access == uc.UC_MEM_WRITE_UNMAPPED:
            print(
                f"UC_MEM_WRITE_UNMAPPED of 0x{address:x} at 0x{pc:X}, data size = {size}")
        if access == uc.UC_MEM_FETCH_UNMAPPED:
            print(
                f"UC_MEM_FETCH_UNMAPPED of 0x{address:x} at 0x{pc:X}, data size = {size}")
        if access == uc.UC_MEM_WRITE_PROT:
            print(
                f"UC_MEM_WRITE_PROT of 0x{address:x} at 0x{pc:X}, data size = {size}")
        if access == uc.UC_MEM_FETCH_PROT:
            print(
                f"UC_MEM_FETCH_PROT of 0x{address:x} at 0x{pc:X}, data size = {size}")
        if access == uc.UC_MEM_FETCH_PROT:  # duplicate case in your original
            print(
                f"UC_MEM_FETCH_PROT of 0x{address:x} at 0x{pc:X}, data size = {size}")
        if access == uc.UC_MEM_READ_AFTER:
            print(
                f"UC_MEM_READ_AFTER of 0x{address:x} at 0x{pc:X}, data size = {size}")
        return False

    def hook_code(self, unicorn, addr, size, user_data):
        mem = unicorn.mem_read(addr, size)
        for insn in self.decomp_engine.disasm(mem, addr):
            print(f"{hex(insn.address)}\t{insn.mnemonic}\t{insn.op_str}")
        return True

    def map_memory(self, address: int,
                   size: int, prot_mode: int,
                   value: bytes
                   ):
        self.emu_engine.mem_map(address, size, prot_mode)
        self.emu_engine.mem_write(address, value)

    def emulation_add_hooks(self):
        self.emu_engine.hook_add(uc.UC_HOOK_CODE, self.hook_code)
        self.emu_engine.hook_add(uc.UC_HOOK_MEM_INVALID, self.hook_mem_invalid)
