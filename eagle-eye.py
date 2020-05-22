#!/usr/bin/python3

from printer import Printer, Level, Force
from argparser import Parser
from api import API, OutputFormat
from enum import Enum
import config as __config

from argparse import RawTextHelpFormatter
import argparse
import sys

l_version = '0.0.3 beta'


def print_example_usage():
    print("""
    --------------------------------
    Test Connectivity
    --------------------------------
    python3 eagle-eye.py -t

    --------------------------------
    Get a JSON Web Token (JWT)
    --------------------------------
    python3 eagle-eye.py -a
    
    --------------------------------
    List exposure types
    --------------------------------
    python3 eagle-eye.py -let -o RAW
    python3 eagle-eye.py -let -o SUM
    python3 eagle-eye.py -let -o CSV
    """)


def run_main_program():
    LINES_BEFORE = 1
    LINES_AFTER = 1

    Printer.verbose = Parser.verbose
    Printer.debug = Parser.debug
    Printer.log_filename = Parser.log_filename
    Printer.log_level = Parser.log_level
    Printer.log_max_bytes_per_file = Parser.log_max_bytes_per_file
    Printer.log_max_number_log_files = Parser.log_max_number_log_files
    Printer.log_format = Parser.log_format
    Printer.enable_logging()

    if Parser.show_examples:
        print_example_usage()
        exit(0)

    if Parser.test_connectivity or Parser.authenticate or Parser.list_exposure_types or Parser.list_exposures:
        l_api = API(p_parser=Parser)
    else:
        lArgParser.print_usage()
        Printer.print("Required arguments not provided", Level.ERROR, Force.FORCE, LINES_BEFORE, LINES_AFTER)

    if Parser.test_connectivity:
        l_api.test_connectivity()
        exit(0)

    if Parser.authenticate:
        l_api.test_authentication()
        exit(0)

    if Parser.list_exposure_types:
        l_api.list_exposure_types()
        exit(0)

    if Parser.list_exposures:
        l_api.get_exposed_ip_ports()
        exit(0)

if __name__ == '__main__':
    lArgParser = argparse.ArgumentParser(description="""
  ______            _        ______           
 |  ____|          | |      |  ____|          
 | |__   __ _  __ _| | ___  | |__  _   _  ___ 
 |  __| / _` |/ _` | |/ _ \ |  __|| | | |/ _ \\
 | |___| (_| | (_| | |  __/ | |___| |_| |  __/
 |______\__,_|\__, |_|\___| |______\__, |\___|
               __/ |                __/ |     
              |___/                |___/      

 Automated Expanse Expander analysis - Fortuna Fortis Paratus
 Version: {}
""".format(l_version), formatter_class=RawTextHelpFormatter)
    lArgParser.add_argument('-v', '--verbose',
                            help='Enable verbose output such as current progress and duration',
                            action='store_true')
    lArgParser.add_argument('-d', '--debug',
                            help='Show debug output',
                            action='store_true')

    l_utilities_group = lArgParser.add_argument_group(title="Utilities", description=None)
    l_utilities_group.add_argument('-e', '--examples',
                                  help='Show examples and exit',
                                  action='store_true')
    l_utilities_group.add_argument('-t', '--test',
                                  help='Test connectivity to API and exit',
                                  action='store_true')
    l_utilities_group.add_argument('-a', '--authenticate',
                                  help='Exchange a refresh token for an access token and exit',
                                  action='store_true')

    l_exposures_group = lArgParser.add_argument_group(
        title="Exposures API Interface",
        description="Methods to interact with the Exposures API")
    l_exposures_group.add_argument('-let', '--list-exposure-types',
                                  help='List exposure types and exit',
                                  action='store_true')
    l_exposures_group.add_argument('-le', '--list-exposures',
                                  help='List exposures and exit',
                                  action='store_true')
    l_exposures_group.add_argument('-o', '--output-format',
                            help='Output format. Required if -o, --output-format provided',
                            required=('-let' in sys.argv or '--list-exposure-types' in sys.argv or '-le' in sys.argv or '--list-exposures' in sys.argv),
                            type=OutputFormat,
                            choices=list(OutputFormat),
                            action='store'
                            )

    Parser.parse_configuration(p_args=lArgParser.parse_args(), p_config=__config)
    run_main_program()
