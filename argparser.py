import config as Config

class Parser:

    debug: bool = False
    verbose: bool = False
    test_connectivity: bool = False
    check_quota: bool = False
    show_examples: bool = False
    list_studies: bool = False
    update_studies: bool = False
    list_unparsed_files: bool = False
    api_key_file_path: str = ""
    database_filename: str = ""
    enable_logging: bool = False
    log_filename: str = ""
    log_max_bytes_per_file: int = 0
    log_max_number_log_files: int = 0
    log_level: int = 0
    log_format: str = ""
    use_proxy: bool = False
    proxy_url: str = ""
    proxy_port: int = 0
    proxy_username: str = ""
    proxy_password: str = ""
    verify_https_certificate = True

    # static methods
    @staticmethod
    def parse_configuration(p_args, p_config: Config) -> None:
        Parser.verbose = p_args.verbose
        Parser.debug = (p_args.debug if p_args.debug else p_config.DEBUG)
        Parser.api_key_file_path = p_config.API_KEY_FILE_PATH
        Parser.api_connection_timeout = p_config.API_CONNECTION_TIMEOUT
        Parser.verify_https_certificate = p_config.VERIFY_HTTPS_CERTIFICATE
        Parser.database_filename = p_config.DATABASE_FILENAME
        Parser.enable_logging = p_config.LOG_ENABLE_LOGGING
        Parser.log_filename = p_config.LOG_FILENAME
        Parser.log_max_bytes_per_file = p_config.LOG_MAX_BYTES_PER_FILE
        Parser.log_max_number_log_files = p_config.LOG_MAX_NUMBER_LOG_FILES
        Parser.log_level = p_config.LOG_LEVEL
        Parser.log_format = p_config.LOG_FORMAT
        Parser.use_proxy = p_config.USE_PROXY
        Parser.proxy_url = p_config.PROXY_URL
        Parser.proxy_port = p_config.PROXY_PORT
        Parser.proxy_username = p_config.PROXY_USERNAME
        Parser.proxy_password = p_config.PROXY_PASSWORD
        Parser.show_examples = p_args.examples
        Parser.show_usage = p_args.usage
        Parser.test_connectivity = p_args.test
        Parser.authenticate = p_args.authenticate
        Parser.list_asset_entities = p_args.list_asset_entities
        Parser.asset_limit = p_args.asset_limit or ""
        Parser.asset_page_token = p_args.asset_page_token or ""
        Parser.list_business_units = p_args.list_business_units
        Parser.list_exposure_types = p_args.list_exposure_types
        Parser.list_exposures = p_args.list_exposures
        Parser.list_exposure_summaries = p_args.list_exposure_summaries
        Parser.exposure_limit = p_args.exposure_limit or ""
        Parser.exposure_offset = p_args.exposure_offset or 0
        Parser.exposure_type = p_args.exposure_type or ""
        Parser.exposure_inet = p_args.exposure_inet or ""
        Parser.exposure_content = p_args.exposure_content or ""
        Parser.exposure_activity_status = p_args.exposure_activity_status or ""
        Parser.exposure_last_event_time = p_args.exposure_last_event_time or ""
        Parser.exposure_last_event_window = p_args.exposure_last_event_window or ""
        Parser.exposure_severity = p_args.exposure_severity or ""
        Parser.exposure_event_type = p_args.exposure_event_type or ""
        Parser.exposure_tag = p_args.exposure_tag or ""
        Parser.exposure_business_unit = p_args.exposure_business_unit or ""
        Parser.exposure_port_number = p_args.exposure_port_number or ""
        Parser.exposure_sort = p_args.exposure_sort or ""
        Parser.list_issue_types = p_args.list_issue_types
        Parser.issue_severity = p_args.issue_severity or ""
        Parser.output_format = p_args.output_format.value.upper() if hasattr(p_args.output_format, 'value') else None