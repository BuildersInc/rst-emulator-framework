import logging
from pathlib import Path

from keystone import Ks

from config.emulation_config import RSTEmulationConfig, default_config
from rstutils import rst_utils


class ASMFile:
    def __init__(self, path_to_file: Path, config: RSTEmulationConfig):
        logging.debug("Load file with path %s", path_to_file)
        self.path = path_to_file
        self.config = config
        self.file_content = self.path.read_text(encoding="utf-8").strip()
        self._inst_count = 0
        self._byte_code = None
        self._compiled = False

    def compile_file(self, create_obj_file: bool = False):
        self._prepare_file()
        ks_obj = Ks(self.config.KEYSTONE_ARCH, self.config.KEYSTONE_MODE)
        arm_arr_int_bytes, self.instruction_count = ks_obj.asm(self.file_content)
        self.byte_code = bytes(arm_arr_int_bytes)

        if create_obj_file:
            out = self.path.parent / "compiled.obj"
            out.write_bytes(self.byte_code)

    def _prepare_file(self) -> None:
        """
        Removes all unnecessary parts of the asm file
        """

    @property
    def byte_code(self):
        """
        The compiled bytecode

        Raises:
            RuntimeError: Raises when accessed before compilation

        """
        if not self._compiled:
            raise RuntimeError("ASM File is not compiled yet")
        return self._byte_code

    @byte_code.setter
    def byte_code(self, value):
        self._compiled = True
        self._byte_code = value

    @property
    def instruction_count(self):
        """
        Number of instructions in the file

        Raises:
            RuntimeError: Raises when accessed before compilation

        """
        if not self._compiled:
            raise RuntimeError("ASM File is not compiled yet")
        return self._inst_count

    @instruction_count.setter
    def instruction_count(self, value):
        self._inst_count = value

    def __len__(self):
        return len(self.byte_code)


def load_file(path_to_file: str, config: RSTEmulationConfig = None) -> ASMFile:
    """
    Loads a ASM file

    Args:
        path_to_file (str): path to the File

    Returns:
        ASMFile: compiled asm File
    """

    path = rst_utils.absolute_path(path_to_file)

    if config is None:
        logging.info("keystone uses default config")
        config = default_config()

    asm_file = ASMFile(path, config)
    return asm_file
