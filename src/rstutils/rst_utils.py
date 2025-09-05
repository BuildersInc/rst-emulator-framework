from pathlib import Path
import logging

def invert_bits(value: int, bits: int = (4 * 8)) -> int:
    mask = (1 << bits) - 1
    return value ^ mask


def absolute_path(path_to_file: str) -> Path:
    path = Path(path_to_file)
    if not path.is_absolute():
        path = path.absolute()

    if not path.exists():
        logging.critical("File %s not Found", path)
        return FileNotFoundError(path.as_posix())
    return path