import logging
import argparse
import importlib.util
import sys

from unicorn import UcError
from keystone import KsError

from fileloader import asm
from emulator import asm_emulator
from rstutils import rst_utils


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
                            help="Provide input assembly file")
    new_parser.add_argument("--test-file", required=True, dest="testcase_file",
                            help="The configured testcase")
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


def main(args):
    test_file = rst_utils.absolute_path(args.testcase_file)
    spec = importlib.util.spec_from_file_location("testcase_file", test_file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    if hasattr(mod, "TEST_DEPENDENCIES") and any(mod.TEST_DEPENDENCIES):
        logging.info("Loading dependencies of the testfile")
        # Todo

    if not hasattr(mod, "TEST_UC_CONFIG"):
        logging.critical("Missing UC Config")
        sys.exit(1)
    if not hasattr(mod, "TESTCASE"):
        logging.critical("Missing Testcase")
        sys.exit(1)

    test_case = mod.TESTCASE

    try:
        asm_file = asm.load_file(args.input_file, mod.TEST_UC_CONFIG)
        asm_file.compile_file()
        emulator = asm_emulator.ASMEmulator(asm_file, mod.TEST_UC_CONFIG)
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
