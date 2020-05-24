#!/usr/bin/python3

from printer import Printer, Level, Force
from argparser import Parser
from api import API, OutputFormat, ExposureEventType, ExposureSeverity, ExposureActivityStatus, ExposureLastEventWindow
from enum import Enum
import config as __config

from argparse import RawTextHelpFormatter
import argparse
import sys


l_version = '0.0.5 beta'


def print_example_usage():
    print("""
    --------------------------------
    Get Help
    --------------------------------
    python3 eagle-eye.py -h
    python3 eagle-eye.py -u
    python3 eagle-eye.py -e

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
    python3 eagle-eye.py -let -o JSON
    python3 eagle-eye.py -let -o CSV

    --------------------------------
    List exposures
    --------------------------------
    python3 eagle-eye.py -le -o JSON -et RDP_SERVER,NET_BIOS_NAME_SERVER
    python3 eagle-eye.py -le -o CSV -et RDP_SERVER,NET_BIOS_NAME_SERVER -esort businessUnit.name,severity,port,ip
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

    if Parser.show_usage:
        lArgParser.print_usage()
        exit(0)

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
    l_utilities_group.add_argument('-u', '--usage',
                                  help='Show usage and exit',
                                  action='store_true')
    l_utilities_group.add_argument('-t', '--test',
                                  help='Test connectivity to API and exit',
                                  action='store_true')
    l_utilities_group.add_argument('-a', '--authenticate',
                                  help='Exchange a refresh token for an access token and exit',
                                  action='store_true')

    l_exposures_group = lArgParser.add_argument_group(
        title="Exposures API Interface Endpoints",
        description="Methods to interact with the Exposures API")
    l_exposures_group.add_argument('-let', '--list-exposure-types',
                                  help='List exposure types and exit',
                                  action='store_true')
    l_exposures_group.add_argument('-le', '--list-exposures',
                                  help='List exposures and exit',
                                  action='store_true')

    l_exposure_options_group = lArgParser.add_argument_group(
        title="Exposures API Interface Endpoint Options",
        description="Arguments to methods that interact with the Exposures API. Use these options with '-le', '--list-exposures'")
    l_exposure_options_group.add_argument('-el', '--exposure-limit',
                            help='How many items to return at one time (default 100, max 10,000). Note that this parameter will be ignored when requesting CSV data.',
                            type=int,
                            action='store'
    )
    l_exposure_options_group.add_argument('-eo', '--exposure-offset',
                            help='How many items to skip before beginning to return results. Note that this parameter will be ignored when requesting CSV data.',
                            type=int,
                            action='store'
    )
    l_exposure_options_group.add_argument('-et', '--exposure-type',
                            help='Returns only results that have an exposure type that is in the given list. The values which can be used in this parameter should be retrieved from -let, --list-exposure-types.',
                            type=str,
                            action='store'
    )
    l_exposure_options_group.add_argument('-ei', '--exposure-inet',
                            help='Search for given IP/CIDR block using a single IP (d.d.d.d), a dashed IP range (d.d.d.d-d.d.d.d), a CIDR block (d.d.d.d/m), a partial CIDR (d.d.), or a wildcard (d.d.*). Returns only results whose IP address overlaps with the passed IP Address or CIDR.',
                            type=str,
                            action='store'
    )
    l_exposure_options_group.add_argument('-ec', '--exposure-content',
                            help='Returns only results whose contents match the given query',
                            type=str,
                            action='store'
    )
    l_exposure_options_group.add_argument('-eas', '--exposure-activity-status',
                            help='Filter results by exposure activity status',
                            type=ExposureActivityStatus,
                            choices=list(ExposureActivityStatus),
                            action='store'
    )
    l_exposure_options_group.add_argument('-elet', '--exposure-last-event-time',
                            help='Returns only results whose last scanned or last disappearance were after the given timestamp',
                            type=str,
                            action='store'
    )
    l_exposure_options_group.add_argument('-elew', '--exposure-last-event-window',
                            help='Filter results by exposure last event window',
                            type=ExposureLastEventWindow,
                            choices=list(ExposureLastEventWindow),
                            action='store'
    )
    l_exposure_options_group.add_argument('-es', '--exposure-severity',
                            help='Filter results by exposure event type',
                            type=ExposureSeverity,
                            choices=list(ExposureSeverity),
                            action='store'
    )
    l_exposure_options_group.add_argument('-eet', '--exposure-event-type',
                            help='Filter results by exposure event type',
                            type=ExposureEventType,
                            choices=list(ExposureEventType),
                            action='store'
    )
    l_exposure_options_group.add_argument('-etag', '--exposure-tag',
                            help='Comma-separated string with no spaces after the comma; Returns only results that have ips corresponding to the given set of tags.',
                            type=str,
                            action='store'
    )
    l_exposure_options_group.add_argument('-ebu', '--exposure-business-unit',
                            help='Comma-separated string; Returns only results associated with the given businessUnit ids, provided that the requesting user has permissions to view results associated with the given business unit.',
                            type=str,
                            action='store'
    )
    l_exposure_options_group.add_argument('-epn', '--exposure-port-number',
                            help='Comma-separated string; Returns only results that have port numbers corresponding to the given port numbers.',
                            type=str,
                            action='store'
    )
    l_exposure_options_group.add_argument('-esort', '--exposure-sort',
                            help='Comma-separated string; orders results by the given fields. If the field name is prefixed by a -, then the ordering will be descending for that field. Use a dotted notation to order by fields that are nested. This values which can be used in this parameter should be retrieved from /configurations/exposures.',
                            type=str,
                            action='store'
    )
    l_exposure_options_group.add_argument('-o', '--output-format',
                            help='Output format. Required if -o, --output-format provided',
                            required=('-let' in sys.argv or '--list-exposure-types' in sys.argv or '-le' in sys.argv or '--list-exposures' in sys.argv),
                            type=OutputFormat,
                            choices=list(OutputFormat),
                            action='store'
    )

    Parser.parse_configuration(p_args=lArgParser.parse_args(), p_config=__config)
    run_main_program()
