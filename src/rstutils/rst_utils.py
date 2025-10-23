from pathlib import Path
import logging


def invert_bits(value: int, bits: int = 4 * 8) -> int:
    mask = (1 << bits) - 1
    return value ^ mask


def absolute_path(path_to_file: str) -> Path:
    """
    Appends the CWD to the provided file path
    to make it absolute. If not already an
    absolute path

    Raises:
        FileNotFoundError: if File does not exists

    Args:
        path_to_file (str): path to the File

    Returns:
        Path: Absolute Path to the file
    """
    path = Path(path_to_file)
    if not path.is_absolute():
        path = path.absolute()

    if not path.exists():
        logging.critical("File %s not Found", path)
        raise FileNotFoundError(path.as_posix())
    return path
