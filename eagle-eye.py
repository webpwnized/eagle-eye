#!/usr/bin/python3

from printer import Printer, Level
from argparser import Parser
from api import API, OutputFormat
from enum import Enum
import config as __config


from argparse import RawTextHelpFormatter
import argparse
import sys




l_version = '0.0.1 beta'


def print_example_usage():
    Printer.print("I do stuff")


def run_main_program():
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

    l_api = API(p_parser=Parser)

    if Parser.test_connectivity:
        l_api.test_connectivity()

    if Parser.list_exposure_types:
        l_api.list_exposure_types()

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
                            help='Enable debug mode',
                            action='store_true')

    requiredAguments = lArgParser.add_mutually_exclusive_group(required=True)
    requiredAguments.add_argument('-e', '--examples',
                                  help='Show examples and exit',
                                  action='store_true')
    requiredAguments.add_argument('-t', '--test',
                                  help='Test connectivity to API and exit',
                                  action='store_true')
    requiredAguments.add_argument('-let', '--list-exposure-types',
                                  help='List exposure types and exit',
                                  action='store_true')

    lArgParser.add_argument('-o', '--output-format',
                            help='Output format. One of RAW, SUM[MARY], CSV Required if -o, --output-format provided',
                            required=('-let' in sys.argv or '--list-exposure-types' in sys.argv),
                            type=OutputFormat,
                            choices=list(OutputFormat),
                            action='store'
                            )

    Parser.parse_configuration(p_args=lArgParser.parse_args(), p_config=__config)
    run_main_program()
