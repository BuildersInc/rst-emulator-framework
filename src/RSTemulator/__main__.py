import logging
import argparse
from datetime import timedelta
from unicorn import UcError
from keystone import KsError

from fileloader import asm
from emulator import asm_emulator, unicorn_engine
from config.emulation_config import default_config
from config.TM4C123GH6PM import APB_GPIO_PORT_F, RCGC_GPIO_R
from rstutils.rst_utils import invert_bits
import rst_testcase.testcase as rst_test


def get_parser():
    """
    Generate an argument parser
    :return: New argument parser
    """
    new_parser = \
        argparse.ArgumentParser(description='RST Test and Emulation Environment',
                                formatter_class=argparse.RawTextHelpFormatter)

    debugging_utils = new_parser.add_argument_group('Debugging Utils',
                                                    'Debugging flags')

    debugging_utils.add_argument('-v', '--verbosity', required=False,
                                 action='count', default=False,
                                 help='increase output verbosity (e.g.: -vv is more than -v).')

    debugging_utils.add_argument("--no-logfile", dest="no_logfile",
                                 required=False, action="store_true",
                                 help="Do not log into a \"LastRun.log\" file")

    new_parser.add_argument("--asm-file", "-asm", required=True, dest="input_file",

                            help="Provide input file")
    return new_parser


def setup_logger(args) -> None:
    """
    Setup and configure a logger
    provide --no-logfile to not create a last_run.log
    Args:
        args : startup arguments
    """
    log_format = "[%(asctime)s.%(msecs)03d|%(levelname)s|%(name)s] %(message)s"
    # level is set to 10 (DEBUG) if -v is given, 9 if -vv, and so on. Otherwise to 20 (INFO)
    level = logging.DEBUG - args.verbosity + \
        1 if args.verbosity else logging.INFO
    # logging.basicConfig(format=LOG_FORMAT, datefmt="%H:%M:%S", level=level)
    formatter = logging.Formatter(log_format, datefmt="%H:%M:%S")
    if not args.no_logfile:
        file_handler = logging.FileHandler('last_run.log', mode="w")
        file_handler.setFormatter(formatter)
        logging.getLogger().addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logging.getLogger().addHandler(console_handler)
    logging.getLogger().setLevel(level)

class RCGC_IS_SET(rst_test.PreCondition):
    def check_pre_condition(self, emulation: unicorn_engine.UnicornEngine) -> bool:
        return emulation.mask_is_set(RCGC_GPIO_R, 0x08)


class GPIO_PORT_F_DEN(rst_test.PreCondition):
    def check_pre_condition(self, emulation: unicorn_engine.UnicornEngine) -> bool:
        return emulation.mask_is_set(APB_GPIO_PORT_F.DEN, 0x10)


class GPIO_PORT_F_DIR(rst_test.PreCondition):
    def check_pre_condition(self, emulation: unicorn_engine.UnicornEngine) -> bool:
        return emulation.mask_is_set(APB_GPIO_PORT_F.DIR, invert_bits(0x10))


class GPIO_PORT_F_PUR(rst_test.PreCondition):
    def check_pre_condition(self, emulation: unicorn_engine.UnicornEngine) -> bool:
        return emulation.mask_is_set(APB_GPIO_PORT_F.PUR, 0x10)


def main(args):
    config = default_config()
    test_case = rst_test.Testcase()
    btn_press = rst_test.IOEvent(
        rst_test.Direction.INPUT,
        APB_GPIO_PORT_F,
        0x10,
        timedelta(seconds=1)
    )
    btn_press.add_precondition(RCGC_IS_SET())
    btn_press.add_precondition(GPIO_PORT_F_DEN())
    btn_press.add_precondition(GPIO_PORT_F_DIR())
    btn_press.add_precondition(GPIO_PORT_F_PUR())

    test_case.attach_event(btn_press)
    try:
        asm_file = asm.load_file(args.input_file, config)
        asm_file.compile_file()
        emulator = asm_emulator.ASMEmulator(asm_file, config)
        emulator.init()
        # emulator.start_emulation()
        emulator.prepare_emulation()
        emulator.start_emulation_with_test(test_case)
    except KsError as error_msg:
        logging.critical("Assembling failed %s", error_msg)
    except UcError as error_msg:
        logging.critical("Emulation failed %s", error_msg)


if __name__ == "__main__":
    parser = get_parser()
    parsed_args = parser.parse_args()
    setup_logger(parsed_args)
    main(args=parsed_args)
