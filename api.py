from printer import Printer, Level
from argparser import Parser
from enum import Enum
from database import SQLite

import json
import getpass
import requests
import os

l_script_directory = os.path.dirname(__file__)


class Override(Enum):
    FORCE_OUTPUT = True
    USE_DEFAULTS = False


class OutputFormat(Enum):
    JSON = 'JSON'
    CSV = 'CSV'

    def __str__(self):
        return self.value


class ExposureActivityStatus(Enum):
    ACTIVE = 'active'
    INACTIVE = 'inactive'

    def __str__(self):
        return self.value


class ExposureLastEventWindow(Enum):
    LAST_7_DAYS = 'LAST_7_DAYS'
    LAST_14_DAYS = 'LAST_14_DAYS'
    LAST_30_DAYS = 'LAST_30_DAYS'
    LAST_60_DAYS = 'LAST_60_DAYS'
    LAST_90_DAYS = 'LAST_90_DAYS'
    LAST_180_DAYS = 'LAST_180_DAYS'
    LAST_365_DAYS = 'LAST_365_DAYS'

    def __str__(self):
        return self.value


class ExposureSeverity(Enum):
    ROUTINE = 'ROUTINE'
    WARNING = 'WARNING'
    CRITICAL = 'CRITICAL'

    def __str__(self):
        return self.value


class ExposureEventType(Enum):
    APPEARANCE = 'appearance'
    REAPPEARANCE = 'reappearance'
    DISAPPEARANCE = 'disappearance'

    def __str__(self):
        return self.value


class AcceptHeader(Enum):
    JSON = 'JSON'
    CSV = 'CSV'


class API:

    # ---------------------------------
    # "Private" class variables
    # ---------------------------------
    __cAPI_KEY_HEADER: str = "Authorization"
    __cUSER_AGENT_HEADER: str = "User-Agent"
    __cUSER_AGENT_VALUE: str = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:64.0) Gecko/20100101 Firefox/64.0"
    __ACCEPT_HEADER: str = "Accept"
    __ACCEPT_JSON_VALUE: str = "application/json"
    __ACCEPT_CSV_VALUE: str = "text/csv"

    __cBASE_URL: str = "https://expander.expanse.co/api/"
    __cAPI_VERSION_1_URL: str = "v1/"
    __cAPI_VERSION_2_URL: str = "v2/"

    __cID_TOKEN_URL: str = __cBASE_URL + __cAPI_VERSION_1_URL + "IdToken/"
    __cENTITY_URL:  str = __cBASE_URL + __cAPI_VERSION_1_URL + "Entity/"
    __cENTITY_ID_URL:  str = __cBASE_URL + __cAPI_VERSION_1_URL + "Entity/"

    __cASSETS_IP_RANGE_URL: str = __cBASE_URL + __cAPI_VERSION_2_URL + "ip-range"
    __cEXPOSURE_TYPES_URL:  str = __cBASE_URL + __cAPI_VERSION_2_URL + "configurations/exposures/"
    __cEXPOSURES_IP_PORTS_URL: str = __cBASE_URL + __cAPI_VERSION_2_URL + "exposures/ip-ports"

    __m_verbose: bool = False
    __m_debug: bool = False
    __m_api_key_file:str = ""
    __m_refresh_token: str = ""
    __m_access_token: str = ""
    __m_verify_https_certificate: bool = True
    __m_api_connection_timeout: int = 30
    __mPrinter: Printer = Printer
    __m_use_proxy: bool = False
    __m_proxy_url: str = ""
    __m_proxy_port: int = 0
    __m_proxy_username: str = ""
    __m_proxy_password: str = ""
    __m_output_format: OutputFormat
    __m_accept_header: AcceptHeader = AcceptHeader.JSON

    # ---------------------------------
    # "Public" class variables
    # ---------------------------------

    @property  # getter method
    def verbose(self) -> bool:
        return self.__m_verbose

    @verbose.setter  # setter method
    def verbose(self: object, pVerbose: bool):
        self.__m_verbose = pVerbose
        self.__mPrinter.verbose = pVerbose

    @property  # getter method
    def debug(self) -> bool:
        return self.__m_debug

    @debug.setter  # setter method
    def debug(self: object, pDebug: bool):
        self.__m_debug = pDebug
        self.__mPrinter.debug = pDebug

    @property  # getter method
    def refresh_token(self) -> str:
        return self.__m_refresh_token

    @refresh_token.setter  # setter method
    def refresh_token(self: object, p_refresh_token: str):
        self.__m_refresh_token = p_refresh_token

    @property  # getter method
    def access_token(self) -> str:
        return self.__m_access_token

    @access_token.setter  # setter method
    def access_token(self: object, p_access_token: str):
        self.__m_access_token = p_access_token

    @property  # getter method
    def api_key_file(self) -> str:
        return self.__m_api_key_file

    @api_key_file.setter  # setter method
    def api_key_file(self: object, pApiKeyFile: str):
        self.__m_api_key_file = pApiKeyFile

    @property  # getter method
    def use_proxy(self) -> bool:
        return self.__m_use_proxy

    @use_proxy.setter  # setter method
    def use_proxy(self: object, p_use_proxy: bool):
        self.__m_use_proxy = p_use_proxy

    @property  # getter method
    def proxy_url(self) -> str:
        return self.__m_proxy_url

    @proxy_url.setter  # setter method
    def proxy_url(self: object, p_proxy_url: str):
        self.__m_proxy_url = p_proxy_url

    @property  # getter method
    def proxy_port(self) -> int:
        return self.__m_proxy_port

    @proxy_port.setter  # setter method
    def proxy_port(self: object, p_proxy_port: int):
        self.__m_proxy_port = p_proxy_port

    @property  # getter method
    def proxy_username(self) -> str:
        return self.__m_proxy_username

    @proxy_username.setter  # setter method
    def proxy_username(self: object, p_proxy_username: str):
        self.__m_proxy_username = p_proxy_username

    @property  # getter method
    def proxy_password(self) -> str:
        return self.__m_proxy_password

    @proxy_password.setter  # setter method
    def proxy_password(self: object, p_proxy_password: str):
        self.__m_proxy_password = p_proxy_password

    @property  # getter method
    def verify_https_certificate(self) -> bool:
        return self.__m_verify_https_certificate

    @verify_https_certificate.setter  # setter method
    def verify_https_certificate(self: object, p_verify_https_certificate: bool):
        self.__m_verify_https_certificate = p_verify_https_certificate

    @property  # getter method
    def output_format(self) -> bool:
        return self.__m_output_format

    @output_format.setter  # setter method
    def output_format(self: object, p_output_format: bool):
        self.__m_output_format = p_output_format

    # ---------------------------------
    # public instance constructor
    # ---------------------------------
    def __init__(self, p_parser: Parser) -> None:
        self.__m_verbose: bool = Parser.verbose
        self.__m_debug: bool = Parser.debug
        self.__m_api_key_file = Parser.api_key_file_path
        self.__m_api_connection_timeout = Parser.api_connection_timeout
        self.__m_verify_https_certificate = Parser.verify_https_certificate
        self.__m_use_proxy = Parser.use_proxy
        self.__m_proxy_url = Parser.proxy_url
        self.__m_proxy_port = Parser.proxy_port
        self.__m_proxy_username = Parser.proxy_username
        self.__m_proxy_password = Parser.proxy_password
        self.__mPrinter.verbose = Parser.verbose
        self.__mPrinter.debug = Parser.debug
        self.__m_output_format = Parser.output_format
        SQLite.database_filename = Parser.database_filename
        self.__parse_api_key()

    # ---------------------------------
    # private instance methods
    # ---------------------------------
    def __parse_api_key(self) -> None:
        try:
            l_file = "{}/{}".format(l_script_directory, self.api_key_file)
            self.__mPrinter.print("Parsing refresh token from {}".format(l_file), Level.INFO)
            with open(l_file) as l_key_file:
                l_json_data = json.load(l_key_file)
                self.__m_refresh_token = l_json_data["credentials"]["refresh-token"]
            self.__mPrinter.print("Parsed refresh token", Level.SUCCESS)
            self.__get_access_token()
        except Exception as e:
            self.__mPrinter.print("__parse_api_key() - {0}".format(str(e)), Level.ERROR)

    def __get_access_token(self) -> None:

        self.__mPrinter.print("Trying to retrieve new access token", Level.INFO)

        try:
            l_headers = {
                self.__cAPI_KEY_HEADER: "Bearer {}".format(self.__m_refresh_token),
                self.__cUSER_AGENT_HEADER: self.__cUSER_AGENT_VALUE,
                self.__ACCEPT_HEADER: self.__ACCEPT_JSON_VALUE
            }

            l_http_response = self.__call_api(self.__cID_TOKEN_URL, l_headers)
            self.__m_access_token = json.loads(l_http_response.text)["token"]

            self.__mPrinter.print("Retrieved new access token", Level.SUCCESS)
        except Exception as e:
            self.__mPrinter.print("__get_access_token() - {0}".format(str(e)), Level.ERROR)

    def __connect_to_api(self, p_url: str) -> requests.Response:
        try:
            self.__mPrinter.print("Connecting to API", Level.INFO)

            l_headers = {
                self.__cAPI_KEY_HEADER: "JWT {}".format(self.__m_access_token),
                self.__cUSER_AGENT_HEADER: self.__cUSER_AGENT_VALUE,
                self.__ACCEPT_HEADER: self.__ACCEPT_CSV_VALUE if self.__m_accept_header == OutputFormat.CSV.value else self.__ACCEPT_JSON_VALUE
            }

            l_http_response = self.__call_api(p_url, l_headers)
            self.__mPrinter.print("Connected to API", Level.SUCCESS)
            return l_http_response
        except Exception as e:
            self.__mPrinter.print("__connect_to_api() - {0}".format(str(e)), Level.ERROR)

    def __call_api(self, p_url: str, p_headers: dict):
        try:
            l_proxies: dict = {}
            if self.__m_use_proxy:
                self.__mPrinter.print("Using upstream proxy", Level.INFO)
                l_proxies = self.__get_proxies()
            if Parser.debug:
                Printer.print("URL: {}".format(p_url), Level.DEBUG)
                Printer.print("Headers: {}".format(p_headers), Level.DEBUG)
                Printer.print("Proxy: {}".format(l_proxies), Level.DEBUG)
                Printer.print("Verify certificate: {}".format(self.__m_verify_https_certificate), Level.DEBUG)
            l_http_response = requests.get(url=p_url, headers=p_headers, proxies=l_proxies, timeout=self.__m_api_connection_timeout, verify=self.__m_verify_https_certificate)
            if l_http_response.status_code != 200:
                l_status_code = str(l_http_response.status_code)
                l_detail = ""
                l_error_message =""
                if "detail" in l_http_response.text:
                    l_detail = " - {}".format(json.loads(l_http_response.text)["detail"])
                if "errorMessages" in l_http_response.text:
                    l_error_messages = json.loads(l_http_response.text)["errorMessages"][0]
                    l_error_message = " - {}:{}".format(l_error_messages["code"],l_error_messages["message"])
                l_message = "Call to API returned status {}{}{}".format(l_status_code, l_detail, l_error_message)
                raise ValueError(l_message)
            self.__mPrinter.print("Connected to API", Level.SUCCESS)
            return l_http_response
        except Exception as lRequestError:
            self.__mPrinter.print("Cannot connect to API: {} {}".format(type(lRequestError).__name__, lRequestError), Level.ERROR)
            exit("Fatal Cannot connect to API. Check connectivity to {}. {}".format(
                    self.__cBASE_URL,
                    'Upstream proxy is enabled in config.py. Ensure proxy settings are correct.' if self.__m_use_proxy else 'The proxy is not enabled. Should it be?'))

    def __get_proxies(self):
        try:
            # If proxy in use, create proxy URL in the format of http://user:password@example.com:port
            # Otherwise, return empty dictionary
            SCHEME = 0
            BASE_URL = 1
            l_proxy_handler: str = ""
            if not self.__m_proxy_password:
                self.__m_proxy_password = getpass.getpass('Please Enter Proxy Password: ')
            l_parts = self.__m_proxy_url.split('://')
            l_http_proxy_url: str = 'http://{}{}{}@{}{}{}'.format(
                self.__m_proxy_username if self.__m_proxy_username else '',
                ':' if self.__m_proxy_password else '',
                requests.utils.requote_uri(self.__m_proxy_password) if self.__m_proxy_password else '',
                l_parts[BASE_URL],
                ':' if self.__m_proxy_port else '',
                self.__m_proxy_port if self.__m_proxy_port else ''
            )
            l_https_proxy_url = l_http_proxy_url.replace('http://', 'https://')
            l_password_mask = '*' * len(self.__m_proxy_password)
            l_proxy_handlers = {'http':l_http_proxy_url, 'https':l_https_proxy_url}
            self.__mPrinter.print("Building proxy handlers: {},{}".format(
                l_http_proxy_url.replace(self.__m_proxy_password, l_password_mask),
                l_https_proxy_url.replace(self.__m_proxy_password, l_password_mask)), Level.INFO)
            return l_proxy_handlers
        except Exception as e:
            self.__mPrinter.print("__get_proxies() - {0}".format(str(e)), Level.ERROR)

    def __format_file_size(self, p_file_size_bytes: int, p_suffix: str = 'B'):
        l_file_size: str = ""
        for l_unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
            if abs(p_file_size_bytes) < 1024.0:
                return "{} {}{}".format(round(p_file_size_bytes,2), l_unit, p_suffix)
            p_file_size_bytes /= 1024.0

    def __initialize_database(self) -> None:
        if not self.__verify_database_exists():
            self.__create_database()

    def __verify_database_exists(self) -> bool:
        return SQLite.verify_database_exists()

    def __create_database(self) -> None:
        SQLite.create_database()

    # ---------------------------------
    # public instance methods
    # ---------------------------------
    def test_connectivity(self) -> None:
        try:
            l_url = self.__cASSETS_IP_RANGE_URL
            l_http_response = self.__connect_to_api(l_url)
            if not self.verbose:
                self.__mPrinter.print("Connected to API", Level.SUCCESS, True)
        except Exception as e:
            self.__mPrinter.print("Connection test failed. Unable to connect to API. {0}".format(str(e)), Level.ERROR)

    def test_authentication(self) -> None:
        try:
            self.__get_access_token()
            self.__mPrinter.print("JWT access token: {}".format(self.__m_access_token), Level.SUCCESS, True)
        except Exception as e:
            self.__mPrinter.print("Authentication test failed. {0}".format(str(e)), Level.ERROR)

    def __parse_exposure_types(self, l_data: list) -> list:
        l_list: list = []
        try:
            for l_item in l_data:
                l_tuple = (l_item['severity'] or 'None', l_item['categoryName'] or 'None', l_item['fullNameSingular'], l_item['exposureType'])
                if Parser.verbose:
                    l_tuple = l_tuple + (','.join(l_item['sortableFields']),)
                l_list.append(l_tuple)

            l_list.sort(key=lambda t: (t[0], t[1]))

            l_tuple = ("Severity", "Category", "Exposure", "Type")
            if Parser.verbose:
                l_tuple = l_tuple + ("Sortable Fields",)
            l_tuples = [l_tuple]
            l_tuples.extend(l_list)

            return l_tuples
        except Exception as e:
            self.__mPrinter.print("__parse_exposure_types() - {0}".format(str(e)), Level.ERROR)

    def list_exposure_types(self) -> None:
        try:
            self.__mPrinter.print("Fetching exposure types", Level.INFO)
            l_http_response = self.__connect_to_api(self.__cEXPOSURE_TYPES_URL)
            self.__mPrinter.print("Fetched exposure types", Level.SUCCESS)
            self.__mPrinter.print("Parsing exposure types", Level.INFO)
            l_json = json.loads(l_http_response.text)
            l_data: list = l_json["data"]

            if self.__m_output_format == OutputFormat.JSON.value:
                print(l_data)

            elif self.__m_output_format == OutputFormat.CSV.value:
                l_list: list = self.__parse_exposure_types(l_data)
                for l_tuple in l_list:
                    print(', '.join('"{0}"'.format(l) for l in l_tuple))

        except Exception as e:
            self.__mPrinter.print("list_exposure_types() - {0}".format(str(e)), Level.ERROR)

    def __parse_exposures(self, l_data: list) -> list:
        l_list: list = []
        try:
            for l_item in l_data:
                l_tuple = (l_item['severity'] or 'None', l_item['exposureType'] or 'None', l_item['businessUnit']['name'], l_item['ip'], l_item['portNumber'], l_item['portProtocol'])
                l_list.append(l_tuple)

            l_list.sort(key=lambda t: (t[0], t[1], t[2], t[4]))
            return l_list
        except Exception as e:
            self.__mPrinter.print("__parse_exposures() - {0}".format(str(e)), Level.ERROR)

    def get_exposed_ip_ports(self) -> None:
        try:
            self.__mPrinter.print("Fetching exposed ports", Level.INFO)
            self.__m_accept_header = Parser.output_format

            l_base_url = "{0}?limit={1}&offset={2}&exposureType={3}&inet={4}&content={5}&activityStatus={6}&lastEventTime={7}&lastEventWindow={8}&severity={9}&eventType={10}&tag={11}&businessUnit={12}&portNumber={13}&sort={14}".format(
                self.__cEXPOSURES_IP_PORTS_URL,
                Parser.exposure_limit, Parser.exposure_offset, Parser.exposure_type, Parser.exposure_inet,
                Parser.exposure_content, Parser.exposure_activity_status, Parser.exposure_last_event_time, Parser.exposure_last_event_window,
                Parser.exposure_severity, Parser.exposure_event_type, Parser.exposure_tag, Parser.exposure_business_unit,
                Parser.exposure_port_number, Parser.exposure_sort
            )
            l_http_response = self.__connect_to_api(l_base_url)
            self.__mPrinter.print("Fetched exposed ports", Level.SUCCESS)
            self.__mPrinter.print("Parsing exposed ports", Level.INFO)
            print(l_http_response.text)

            # l_json = json.loads(l_http_response.text)
            # l_data: list = l_json["data"]
            # l_list: list = self.__parse_exposures(l_data)
            # print('"Severity", "Exposure Type", "Business Unit", "IP", "Port", "Protocol"')
            # for l_tuple in l_list:
            #     print(', '.join('"{0}"'.format(l) for l in l_tuple))

        except Exception as e:
            self.__mPrinter.print("get_exposed_ip_ports() - {0}".format(str(e)), Level.ERROR)
