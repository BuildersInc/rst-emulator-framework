import logging

from unicorn import Uc
import unicorn as uc
import capstone as cs

from config.emulation_config import RSTEmulationConfig
from rstutils.rst_utils import invert_bits
from fileloader.asm import ASMFile


class UnicornEngine():
    def __init__(self, config: RSTEmulationConfig):
        self.config = config
        self.emu_engine: Uc = None
        self.decomp_engine: cs.Cs = None

    def prepare_emulation(self):
        raise NotImplementedError()

    def init(self):
        """
        Wrapper function to load
        decompilation and emulation engine
        """
        self.init_decomp_engine()
        self.init_emu_engine()

    def init_emu_engine(self):
        """
        Initialize emulation engine
        - Init stack
        - Reserve memory for register map
        """
        self.emu_engine = Uc(self.config.UNICORN_ARCH,
                             self.config.UNICORN_MODE)
        logging.debug("Init Stack")
        self.map_memory(self.config.STACK_BASE, self.config.STACK_SIZE,
                        uc.UC_PROT_ALL, b"\x00" * self.config.STACK_SIZE)

        self.emu_engine.reg_write(uc.arm_const.UC_ARM_REG_SP,
                                  self.config.STACK_BASE + (self.config.STACK_SIZE // 2))
        logging.debug("Load Register Memory space from %s till %s",
                      hex(self.config.REGISTER_MEMORY_SPACE_START),
                      hex(self.config.REGISTER_MEMORY_SPACE_START +
                          self.config.REGISTER_MEMORY_SPACE_SIZE))

        self.map_memory(self.config.REGISTER_MEMORY_SPACE_START,
                        self.config.REGISTER_MEMORY_SPACE_SIZE,
                        uc.UC_PROT_ALL,
                        b"\x00" * self.config.REGISTER_MEMORY_SPACE_SIZE)

    def init_decomp_engine(self):
        """
        Initialise decompilation capstone engine
        needed for tracing errors
        """
        self.decomp_engine = cs.Cs(self.config.CAPSTONE_ARCH,
                                   self.config.CAPSTONE_MODE)
        self.decomp_engine.detail = True

    def map_memory(self, address: int,
                   size: int, prot_mode: int,
                   value: bytes
                   ):
        """
        Reserves a memory space and
        loads it with the provided value


        Args:
            address (int): Starting address
            size (int): How many bytes
            prot_mode (int): Protection mode the memory space
            value (bytes): Memory content
        """
        page_size = 0x1000
        aligned_size = ((size + page_size - 1) // page_size) * page_size
        self.emu_engine.mem_map(address, aligned_size, prot_mode)
        self.emu_engine.mem_write(address, value)

    def emulation_add_hooks(self):
        """
        Attaches hooks that logs certain states
        - Print each line
        - Print invalid memory access
        """
        self.emu_engine.hook_add(uc.UC_HOOK_CODE,
                                 self._hook_code)
        self.emu_engine.hook_add(uc.UC_HOOK_MEM_INVALID,
                                 self._hook_mem_invalid)

    def load_code(self, code: ASMFile):

        self.map_memory(self.config.CODE_START, len(code),
                        uc.UC_PROT_ALL, code.byte_code)
        logging.debug("Loaded %i Instructions at address %s",
                      code.instruction_count, hex(self.config.CODE_START))

    def safe_set_value_in_memory(self, address, value, size=4):
        register_state = self.emu_engine.mem_read(
            address, size
        )
        register_state = int.from_bytes(register_state, 'little')
        register_state |= value

        register_state = bytes(bytearray(register_state.to_bytes(size, 'little')))
        self.emu_engine.mem_write(
            address, register_state
        )

    def safe_clear_value_in_memory(self, address, value, size=4):
        register_state = self.emu_engine.mem_read(
                address, size
            )
        register_state = int.from_bytes(register_state, 'little')
        register_state &= invert_bits(value)
        register_state = bytes(bytearray(register_state.to_bytes(size, 'little')))
        self.emu_engine.mem_write(
            address, register_state
        )

    def mask_is_set(self, address, mask, size=4) -> bool:
        register_state = self.emu_engine.mem_read(
            address, size
        )

        return (int.from_bytes(register_state, 'little') & mask) == mask

    def _hook_mem_invalid(self, unicorn, access, address, size, value, user_data):
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
        if access == uc.UC_MEM_READ_AFTER:
            print(
                f"UC_MEM_READ_AFTER of 0x{address:x} at 0x{pc:X}, data size = {size}")
        return False

    def _hook_code(self, unicorn, addr, size, user_data):
        mem = unicorn.mem_read(addr, size)
        for insn in self.decomp_engine.disasm(mem, addr):
            print(f"{hex(insn.address)}\t{insn.mnemonic}\t{insn.op_str}")
        return True
