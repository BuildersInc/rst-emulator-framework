
def invert_bits(value: int, bits: int = (4 * 8)) -> int:
    mask = (1 << bits) - 1
    return value ^ mask
