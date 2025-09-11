from dataclasses import dataclass

from unicorn import UC_ARCH_ARM, UC_MODE_THUMB
from keystone import KS_ARCH_ARM, KS_MODE_THUMB
from capstone import CS_ARCH_ARM, CS_MODE_THUMB

# pylint: disable=C0103
@dataclass
class RSTEmulationConfig:
    UNICORN_ARCH: int
    UNICORN_MODE: int

    KEYSTONE_ARCH: int
    KEYSTONE_MODE: int

    CAPSTONE_ARCH: int
    CAPSTONE_MODE: int

    STACK_BASE: int
    STACK_SIZE: int

    REGISTER_MEMORY_SPACE_START: int
    REGISTER_MEMORY_SPACE_SIZE: int

    USER_MEMORY_SPACE_START: int
    USER_MEMORY_SPACE_SIZE: int

    CODE_START: int
    EMULATION_SPEED: int
# pylint: enable=all


def default_config() -> RSTEmulationConfig:
    """
    Creates a default configuration

    Returns:
        RSTEmulationConfig: Default config
    """
    return RSTEmulationConfig(
        UC_ARCH_ARM,
        UC_MODE_THUMB,
        KS_ARCH_ARM,
        KS_MODE_THUMB,
        CS_ARCH_ARM,
        CS_MODE_THUMB,
        STACK_BASE=0x2000000,
        STACK_SIZE=1024,
        REGISTER_MEMORY_SPACE_START=0x40000000,
        REGISTER_MEMORY_SPACE_SIZE=0x10000000,
        USER_MEMORY_SPACE_START=0,
        USER_MEMORY_SPACE_SIZE=0,
        CODE_START=0x00,
        EMULATION_SPEED=100_000
    )
