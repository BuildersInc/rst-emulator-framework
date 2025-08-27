import logging
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UcError
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2
from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB, KS_MODE_ARM,  KsError


class ASMFile:
    def __init__(self, path_to_file: Path):
        logging.debug("Load file with path %s", path_to_file)
        self.path = path_to_file
        self.file_content = self.path.read_text(encoding="utf-8").strip()
        self._byte_code = None
        self._compiled = False

    def compile_file(self):
        ks_obj = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        arm_arr_int_bytes, number_of_instructions = ks_obj.asm(self.file_content)
        self.byte_code = bytes(arm_arr_int_bytes)

        out = self.path.parent / "compiled.obj"
        out.write_bytes(self.byte_code)

    @property
    def byte_code(self):
        if not self._compiled:
            raise RuntimeError("ASM File is not compiled yet")
        return self._byte_code

    @byte_code.setter
    def byte_code(self, value):
        self._compiled = True
        self._byte_code = value


def load_file(path_to_file: str) -> ASMFile:
    """
    Loads a ASM file

    Args:
        path_to_file (str): path to the File

    Returns:
        ASMFile: compiled asm File
    """

    path = Path(path_to_file)
    if not path.is_absolute():
        path = path.absolute()

    if not path.exists():
        logging.critical("File %s not Found", path)
        return FileNotFoundError(path.as_posix())

    asm_file = ASMFile(path)
    return asm_file
