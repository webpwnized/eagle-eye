#!/usr/bin/python3

from printer import Printer, Level, Force
from argparser import Parser
from api import API, OutputFormat, ExposureEventType, ExposureSeverity, ExposureActivityStatus, ExposureLastEventWindow, IssueSeverity
import config as __config

from argparse import RawTextHelpFormatter
import argparse
import sys


l_version = '0.0.11 beta'


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
    List business units
    --------------------------------
    python3 eagle-eye.py -lbu -o JSON
    python3 eagle-eye.py -lbu -o CSV

    --------------------------------
    List exposure types
    --------------------------------
    python3 eagle-eye.py -let -o JSON
    python3 eagle-eye.py -let -o CSV

    --------------------------------
    List exposure summaries
    --------------------------------
    python3 eagle-eye.py -les -o JSON
    python3 eagle-eye.py -les -o CSV
    python3 eagle-eye.py -les -et TELNET_SERVER -o CSV
    python3 eagle-eye.py -les -es CRITICAL -o CSV

    ----------------------------------------------------------------
    List exposures - Insecure protocols
    ----------------------------------------------------------------
    python3 eagle-eye.py -le -o JSON -et SIP_SERVER,XMPP_SERVER,BACNET_SERVER,ETHERNET_IP_SERVER,MODBUS_SERVER,VX_WORKS_SERVER,CASSANDRA_SERVER,COUCH_DB_SERVER,ELASTICSEARCH_SERVER,HADOOP_SERVER,MEMCACHED_SERVER,MONGO_SERVER,MS_SQL_SERVER,MY_SQL_SERVER,POSTGRES_SERVER,REDIS_SERVER,SHAREPOINT_SERVER,BUILDING_CONTROL_SYSTEM,DATA_STORAGE_AND_ANALYSIS,EMBEDDED_SYSTEM,NETWORKING_AND_SECURITY_INFRASTRUCTURE,RSYNC_SERVER,SMB_SERVER,UNENCRYPTED_FTP_SERVER,AJP_SERVER,NET_BIOS_NAME_SERVER,PC_ANYWHERE_SERVER,RDP_SERVER,RPC_BIND_SERVER,SNMP_SERVER,TELNET_SERVER,UPNP_SERVER,VNC_OVER_HTTP_SERVER,VNC_SERVER,FTP_SERVER,JENKINS_SERVER,SALT_STACK_SERVER,UNENCRYPTED_LOGIN
    
    python3 eagle-eye.py -le -o CSV -et SIP_SERVER,XMPP_SERVER,BACNET_SERVER,ETHERNET_IP_SERVER,MODBUS_SERVER,VX_WORKS_SERVER,CASSANDRA_SERVER,COUCH_DB_SERVER,ELASTICSEARCH_SERVER,HADOOP_SERVER,MEMCACHED_SERVER,MONGO_SERVER,MS_SQL_SERVER,MY_SQL_SERVER,POSTGRES_SERVER,REDIS_SERVER,SHAREPOINT_SERVER,BUILDING_CONTROL_SYSTEM,DATA_STORAGE_AND_ANALYSIS,EMBEDDED_SYSTEM,NETWORKING_AND_SECURITY_INFRASTRUCTURE,RSYNC_SERVER,SMB_SERVER,UNENCRYPTED_FTP_SERVER,AJP_SERVER,NET_BIOS_NAME_SERVER,PC_ANYWHERE_SERVER,RDP_SERVER,RPC_BIND_SERVER,SNMP_SERVER,TELNET_SERVER,UPNP_SERVER,VNC_OVER_HTTP_SERVER,VNC_SERVER,FTP_SERVER,JENKINS_SERVER,SALT_STACK_SERVER,UNENCRYPTED_LOGIN -esort businessUnit.name,severity,port,ip 

    ----------------------------------------------------------------
    List exposures - Insecure certificates
    ----------------------------------------------------------------
    python3 eagle-eye.py -le -o JSON -et DOMAIN_CONTROL_VALIDATED_CERTIFICATE_ADVERTISEMENT,EXPIRED_WHEN_SCANNED_CERTIFICATE_ADVERTISEMENT,INSECURE_SIGNATURE_CERTIFICATE_ADVERTISEMENT,LONG_EXPIRATION_CERTIFICATE_ADVERTISEMENT,SELF_SIGNED_CERTIFICATE_ADVERTISEMENT,SHORT_KEY_CERTIFICATE_ADVERTISEMENT,WILDCARD_CERTIFICATE_ADVERTISEMENT
    
    python3 eagle-eye.py -le -o CSV -et DOMAIN_CONTROL_VALIDATED_CERTIFICATE_ADVERTISEMENT,EXPIRED_WHEN_SCANNED_CERTIFICATE_ADVERTISEMENT,INSECURE_SIGNATURE_CERTIFICATE_ADVERTISEMENT,LONG_EXPIRATION_CERTIFICATE_ADVERTISEMENT,SELF_SIGNED_CERTIFICATE_ADVERTISEMENT,SHORT_KEY_CERTIFICATE_ADVERTISEMENT,WILDCARD_CERTIFICATE_ADVERTISEMENT -esort businessUnit.name,severity,port,ip 

    ----------------------------------------------------------------
    List exposures - Web domains
    ----------------------------------------------------------------
    python3 eagle-eye.py -le -o CSV -et SERVER_SOFTWARE,APPLICATION_SERVER_SOFTWARE

    --------------------------------
    List issue types
    --------------------------------
    python3 eagle-eye.py -lit -o JSON
    python3 eagle-eye.py -lit -o CSV
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

    if Parser.test_connectivity or Parser.authenticate or Parser.list_exposure_types or Parser.list_exposures or \
            Parser.list_exposure_summaries or Parser.list_business_units or Parser.list_asset_entities or \
            Parser.list_issue_types or Parser.get_issues_count or Parser.get_issues:
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

    if Parser.list_asset_entities:
        l_api.get_asset_entities()
        exit(0)

    if Parser.list_business_units:
        l_api.get_entities()
        exit(0)

    if Parser.list_exposure_types:
        l_api.list_exposure_types()
        exit(0)

    if Parser.list_exposure_summaries:
        l_api.summarize_exposed_ip_ports()
        exit(0)

    if Parser.list_exposures:
        l_api.get_exposures()
        exit(0)

    if Parser.list_issue_types:
        l_api.list_issue_types()
        exit(0)

    if Parser.get_issues_count:
        l_api.get_issues_count()
        exit(0)

    if Parser.get_issues:
        l_api.get_issues()
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
    lArgParser.add_argument('-o', '--output-format',
                            help='Output format',
                            type=OutputFormat,
                            choices=list(OutputFormat),
                            default=OutputFormat.CSV,
                            action='store'
    )

    l_utilities_group = lArgParser.add_argument_group(title="Utilities", description=None)
    l_utilities_group.add_argument('-e', '--examples',
                                  help='Show various examples and exit',
                                  action='store_true')
    l_utilities_group.add_argument('-u', '--usage',
                                  help='Show brief usage and exit',
                                  action='store_true')
    l_utilities_group.add_argument('-t', '--test',
                                  help='Test connectivity to API and exit',
                                  action='store_true')
    l_utilities_group.add_argument('-a', '--authenticate',
                                  help='Exchange a refresh token for an access token and exit',
                                  action='store_true')

    l_assets_group = lArgParser.add_argument_group(
        title="Assets API Interface Endpoints",
        description="Methods to interact with the Assets API")
    l_assets_group.add_argument('-lae', '--list-asset-entities',
                                  help='List asset entities and exit',
                                  action='store_true')

    l_asset_options_group = lArgParser.add_argument_group(
        title="Assets API Interface Endpoint Options",
        description="Arguments to methods that interact with the Assets API. Use these options with '-lae', '--list-asset-entities'")
    l_asset_options_group.add_argument('-al', '--asset-limit',
                            help='Page size in pagination',
                            type=int,
                            action='store'
    )
    l_asset_options_group.add_argument('-apt', '--asset-page-token',
                            help='Page token for pagination',
                            type=str,
                            action='store'
    )

    l_issues_group = lArgParser.add_argument_group(
        title="Issues API Interface Endpoints",
        description="Methods to interact with the Issues API")
    l_issues_group.add_argument('-lit', '--list-issue-types',
                                  help='List issue types and exit',
                                  action='store_true')
    l_issues_group.add_argument('-gic', '--get-issues-count',
                                  help='Get a count of issues. Returns the total count of issues matching the provided filters, up to 10K.',
                                  action='store_true')
    l_issues_group.add_argument('-gi', '--get-issues',
                                  help='Get a paginated list of issues.',
                                  action='store_true')

    l_issues_options_group = lArgParser.add_argument_group(
        title="Issues API Interface Endpoint Options",
        description="Arguments to methods that interact with the Issues API.")
    l_issues_options_group.add_argument('-il', '--issue-limit',
                            help='Returns at most this many results in a single api call (default: 100, max: 10,000).',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-ipt', '--issue-page-token',
                            help='Page token for pagination',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-ics', '--issue-content-search',
                            help='Returns only results whose contents match the given query',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-ipid', '--issue-provider-id',
                            help='Comma-separated string; Returns only results that were found on the given providers.',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-ipname', '--issue-provider-name',
                            help='Comma-separated string; Returns only results that were found on the given providers.',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-ibu', '--issue-business-unit',
                            help='Comma-separated string; Returns only results with a business unit whose ID falls in the provided list.',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-ibn', '--issue-business-unit-name',
                            help='Comma-separated string; Returns only results with a business unit whose name falls in the provided list.',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-iau', '--issue-assignee-username',
                            help='Comma-separated string; Returns only results whose assignees username matches one of the given usernames. Use "Unassigned" to fetch issues that are not assigned to any user.',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-itid', '--issue-type-id',
                            help='Comma-separated string; Returns only results whose issue type ID matches one of the given types.',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-itn', '--issue-type-name',
                            help='Comma-separated string; Returns only results whose issue type name matches one of the given types.',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-iis', '--issue-inet-search',
                            help='Search for results in a given IP/CIDR block using a single IP (d.d.d.d), a dashed IP range (d.d.d.d-d.d.d.d), a CIDR block (d.d.d.d/m), a partial CIDR (d.d.), or a wildcard (d.d.*.d). Returns results whose identifier includes an IP matching the query.',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-ids', '--issue-domain-search',
                            help='Search for a a given domain value via substring match. Returns results whose identifier includes a domain matching the query.',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-ipn', '--issue-port-number',
                            help='Comma-separated string; Returns only results whose identifier includes one of the given port numbers.',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-ips', '--issue-progress-status',
                            help='Comma-separated string; Returns only results whose progress status matches one of the given values.',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-ias', '--issue-activity-status',
                            help='Comma-separated string; Returns only results whose activity status matches one of the given values.',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-ip', '--issue-priority',
                            help='Comma-separated string; Returns only results whose priority matches one of the given values.',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-itagid', '--issue-tag-id',
                            help='Comma-separated string; Returns only results that are associated with the provided tag IDs.',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-itname', '--issue-tag-name',
                            help='Comma-separated string; Returns only results that are associated with the provided tag names.',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-ica', '--issue-created-after',
                            help='Returns only results created after the provided timestamp (YYYY-MM-DDTHH:MM:SSZ).',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-icb', '--issue-created-before',
                            help='Returns only results created before the provided timestamp (YYYY-MM-DDTHH:MM:SSZ).',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-ima', '--issue-modified-after',
                            help='Returns only results modified after the provided timestamp (YYYY-MM-DDTHH:MM:SSZ).',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-imb', '--issue-modified-before',
                            help='Returns only results modified before the provided timestamp (YYYY-MM-DDTHH:MM:SSZ).',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-isort', '--issue_sort',
                            help='Sort by specified properties',
                            type=str,
                            action='store'
    )
    l_issues_options_group.add_argument('-icf', '--issue-csv-filename',
                            help='The name of the returned CSV file',
                            type=str,
                            action='store'
    )

    l_exposures_group = lArgParser.add_argument_group(
        title="Exposures API Interface Endpoints",
        description="Methods to interact with the Exposures API")
    l_exposures_group.add_argument('-lbu', '--list-business-units',
                                  help='List business units and exit',
                                  action='store_true')
    l_exposures_group.add_argument('-let', '--list-exposure-types',
                                  help='List exposure types and exit. The results can be filtered by -es, --exposure-severity',
                                  action='store_true')
    l_exposures_group.add_argument('-les', '--list-exposure-summaries',
                                   help='List exposures summaries and exit. The results can be filtered by the options shown below.',
                                   action='store_true')
    l_exposures_group.add_argument('-le', '--list-exposures',
                                  help='List exposures and exit. The results can be filtered by the options shown below.',
                                  action='store_true')

    l_exposure_options_group = lArgParser.add_argument_group(
        title="Exposures API Interface Endpoint Options",
        description="Arguments to methods that interact with the Exposures and Summaries API. Use these options with '-le', '--list-exposures', '-les', '--list-exposure-summaries'")
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
                            help='Filter results by exposure severity',
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

    Parser.parse_configuration(p_args=lArgParser.parse_args(), p_config=__config)
    run_main_program()