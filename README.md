#Eagle Eye

###Usage

    usage: eagle-eye [-h] [-v] [-d] [-e] [-u] [-t] [-a] [-let] [-les] [-le]
                     [-el EXPOSURE_LIMIT] [-eo EXPOSURE_OFFSET]
                     [-et EXPOSURE_TYPE] [-ei EXPOSURE_INET]
                     [-ec EXPOSURE_CONTENT] [-eas {active,inactive}]
                     [-elet EXPOSURE_LAST_EVENT_TIME]
                     [-elew {LAST_7_DAYS,LAST_14_DAYS,LAST_30_DAYS,LAST_60_DAYS,LAST_90_DAYS,LAST_180_DAYS,LAST_365_DAYS}]
                     [-es {ROUTINE,WARNING,CRITICAL}]
                     [-eet {appearance,reappearance,disappearance}]
                     [-etag EXPOSURE_TAG] [-ebu EXPOSURE_BUSINESS_UNIT]
                     [-epn EXPOSURE_PORT_NUMBER] [-esort EXPOSURE_SORT]
                     [-o {JSON,CSV}]

###Options

    optional arguments:
      -h, --help            show this help message and exit
      -v, --verbose         Enable verbose output such as current progress and duration
      -d, --debug           Show debug output
    
    Utilities:
      -e, --examples        Show various examples and exit
      -u, --usage           Show brief usage and exit
      -t, --test            Test connectivity to API and exit
      -a, --authenticate    Exchange a refresh token for an access token and exit
    
    Exposures API Interface Endpoints:
      Methods to interact with the Exposures API
    
      -let, --list-exposure-types
                            List exposure types and exit
      -les, --list-exposure-summaries
                            List exposures summaries and exit. Options are shown below.
      -le, --list-exposures
                            List exposures and exit. Options are shown below.
    
    Exposures API Interface Endpoint Options:
      Arguments to methods that interact with the Exposures and Summaries API. Use these options with '-le', '--list-exposures'
    
      -el EXPOSURE_LIMIT, --exposure-limit EXPOSURE_LIMIT
                            How many items to return at one time (default 100, max 10,000). Note that this parameter will be ignored when requesting CSV data.
      -eo EXPOSURE_OFFSET, --exposure-offset EXPOSURE_OFFSET
                            How many items to skip before beginning to return results. Note that this parameter will be ignored when requesting CSV data.
      -et EXPOSURE_TYPE, --exposure-type EXPOSURE_TYPE
                            Returns only results that have an exposure type that is in the given list. The values which can be used in this parameter should be retrieved from -let, --list-exposure-types.
      -ei EXPOSURE_INET, --exposure-inet EXPOSURE_INET
                            Search for given IP/CIDR block using a single IP (d.d.d.d), a dashed IP range (d.d.d.d-d.d.d.d), a CIDR block (d.d.d.d/m), a partial CIDR (d.d.), or a wildcard (d.d.*). Returns only results whose IP address overlaps with the passed IP Address or CIDR.
      -ec EXPOSURE_CONTENT, --exposure-content EXPOSURE_CONTENT
                            Returns only results whose contents match the given query
      -eas {active,inactive}, --exposure-activity-status {active,inactive}
                            Filter results by exposure activity status
      -elet EXPOSURE_LAST_EVENT_TIME, --exposure-last-event-time EXPOSURE_LAST_EVENT_TIME
                            Returns only results whose last scanned or last disappearance were after the given timestamp
      -elew {LAST_7_DAYS,LAST_14_DAYS,LAST_30_DAYS,LAST_60_DAYS,LAST_90_DAYS,LAST_180_DAYS,LAST_365_DAYS}, --exposure-last-event-window {LAST_7_DAYS,LAST_14_DAYS,LAST_30_DAYS,LAST_60_DAYS,LAST_90_DAYS,LAST_180_DAYS,LAST_365_DAYS}
                            Filter results by exposure last event window
      -es {ROUTINE,WARNING,CRITICAL}, --exposure-severity {ROUTINE,WARNING,CRITICAL}
                            Filter results by exposure event type
      -eet {appearance,reappearance,disappearance}, --exposure-event-type {appearance,reappearance,disappearance}
                            Filter results by exposure event type
      -etag EXPOSURE_TAG, --exposure-tag EXPOSURE_TAG
                            Comma-separated string with no spaces after the comma; Returns only results that have ips corresponding to the given set of tags.
      -ebu EXPOSURE_BUSINESS_UNIT, --exposure-business-unit EXPOSURE_BUSINESS_UNIT
                            Comma-separated string; Returns only results associated with the given businessUnit ids, provided that the requesting user has permissions to view results associated with the given business unit.
      -epn EXPOSURE_PORT_NUMBER, --exposure-port-number EXPOSURE_PORT_NUMBER
                            Comma-separated string; Returns only results that have port numbers corresponding to the given port numbers.
      -esort EXPOSURE_SORT, --exposure-sort EXPOSURE_SORT
                            Comma-separated string; orders results by the given fields. If the field name is prefixed by a -, then the ordering will be descending for that field. Use a dotted notation to order by fields that are nested. This values which can be used in this parameter should be retrieved from /configurations/exposures.
      -o {JSON,CSV}, --output-format {JSON,CSV}
                            Output format. Required if -o, --output-format provided

###Examples

#####Get Help
    python3 eagle-eye.py -h
    python3 eagle-eye.py -u
    python3 eagle-eye.py -e

#####Test Connectivity
    python3 eagle-eye.py -t

#####List exposure types
    python3 eagle-eye.py -let -o JSON
    python3 eagle-eye.py -let -o CSV

#####List exposure summaries
    python3 eagle-eye.py -les
    python3 eagle-eye.py -les -et TELNET_SERVER
    python3 eagle-eye.py -les -es CRITICAL

#####List exposures - Insecure protocols
    python3 eagle-eye.py -le -o JSON -et SIP_SERVER,XMPP_SERVER,BACNET_SERVER,ETHERNET_IP_SERVER,MODBUS_SERVER,VX_WORKS_SERVER,CASSANDRA_SERVER,COUCH_DB_SERVER,ELASTICSEARCH_SERVER,HADOOP_SERVER,MEMCACHED_SERVER,MONGO_SERVER,MS_SQL_SERVER,MY_SQL_SERVER,POSTGRES_SERVER,REDIS_SERVER,SHAREPOINT_SERVER,BUILDING_CONTROL_SYSTEM,DATA_STORAGE_AND_ANALYSIS,EMBEDDED_SYSTEM,NETWORKING_AND_SECURITY_INFRASTRUCTURE,RSYNC_SERVER,SMB_SERVER,UNENCRYPTED_FTP_SERVER,AJP_SERVER,NET_BIOS_NAME_SERVER,PC_ANYWHERE_SERVER,RDP_SERVER,RPC_BIND_SERVER,SNMP_SERVER,TELNET_SERVER,UPNP_SERVER,VNC_OVER_HTTP_SERVER,VNC_SERVER,FTP_SERVER,JENKINS_SERVER,SALT_STACK_SERVER,UNENCRYPTED_LOGIN
    
    python3 eagle-eye.py -le -o CSV -et SIP_SERVER,XMPP_SERVER,BACNET_SERVER,ETHERNET_IP_SERVER,MODBUS_SERVER,VX_WORKS_SERVER,CASSANDRA_SERVER,COUCH_DB_SERVER,ELASTICSEARCH_SERVER,HADOOP_SERVER,MEMCACHED_SERVER,MONGO_SERVER,MS_SQL_SERVER,MY_SQL_SERVER,POSTGRES_SERVER,REDIS_SERVER,SHAREPOINT_SERVER,BUILDING_CONTROL_SYSTEM,DATA_STORAGE_AND_ANALYSIS,EMBEDDED_SYSTEM,NETWORKING_AND_SECURITY_INFRASTRUCTURE,RSYNC_SERVER,SMB_SERVER,UNENCRYPTED_FTP_SERVER,AJP_SERVER,NET_BIOS_NAME_SERVER,PC_ANYWHERE_SERVER,RDP_SERVER,RPC_BIND_SERVER,SNMP_SERVER,TELNET_SERVER,UPNP_SERVER,VNC_OVER_HTTP_SERVER,VNC_SERVER,FTP_SERVER,JENKINS_SERVER,SALT_STACK_SERVER,UNENCRYPTED_LOGIN -esort businessUnit.name,severity,port,ip 

#####List exposures - Insecure certificates
    python3 eagle-eye.py -le -o JSON -et DOMAIN_CONTROL_VALIDATED_CERTIFICATE_ADVERTISEMENT,EXPIRED_WHEN_SCANNED_CERTIFICATE_ADVERTISEMENT,INSECURE_SIGNATURE_CERTIFICATE_ADVERTISEMENT,LONG_EXPIRATION_CERTIFICATE_ADVERTISEMENT,SELF_SIGNED_CERTIFICATE_ADVERTISEMENT,SHORT_KEY_CERTIFICATE_ADVERTISEMENT,WILDCARD_CERTIFICATE_ADVERTISEMENT
    
    python3 eagle-eye.py -le -o CSV -et DOMAIN_CONTROL_VALIDATED_CERTIFICATE_ADVERTISEMENT,EXPIRED_WHEN_SCANNED_CERTIFICATE_ADVERTISEMENT,INSECURE_SIGNATURE_CERTIFICATE_ADVERTISEMENT,LONG_EXPIRATION_CERTIFICATE_ADVERTISEMENT,SELF_SIGNED_CERTIFICATE_ADVERTISEMENT,SHORT_KEY_CERTIFICATE_ADVERTISEMENT,WILDCARD_CERTIFICATE_ADVERTISEMENT -esort businessUnit.name,severity,port,ip