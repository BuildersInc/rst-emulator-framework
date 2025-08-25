import logging
from pathlib import Path


class ASMFile:
    def __init__(self, path_to_file: Path):
        logging.debug("Load file with path %s", path_to_file)
        self.path = path_to_file
        self.file_content = self.path.read_text(encoding="utf-8")

    def compile_file(self):
        ...


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

    asm_file = ASMFile(path_to_file)
    return asm_file
