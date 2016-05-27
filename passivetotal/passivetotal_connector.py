#!/usr/bin/env python
"""Phantom connector app to query the PassiveTotal platform.

This connector splits each PassiveTotal data service into a series of actions
that can be used by the user. Each action outputs data that can then be used
to feed other actions for maximum automation.
"""
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

__author__ = 'Brandon Dixon (brandon@passivetotal.org)'
__version__ = '1.0.0'
__description__ = "Phantom connector app to query the PassiveTotal platform."
__keywords__ = ['phantom', 'connector', 'automation', 'integration']
__tested__ = ['1.2.113']
__requirements__ = ['passivetotal']

PT_INST_ACCOUNT = 'AccountClient'
PT_INST_ACTIONS = 'ActionsClient'
PT_INST_ATTRIBUTES = 'AttributeRequest'
PT_INST_DNS = 'DnsRequest'
PT_INST_ENRICHMENT = 'EnrichmentRequest'
PT_INST_INTEL = 'IntelligenceRequest'
PT_INST_SSL = 'SslRequest'
PT_INST_WHOIS = 'WhoisRequest'
PT_KEY_ACCOUNT = 'account'
PT_KEY_ACTIONS = 'actions'
PT_KEY_API = "api_key"
PT_KEY_ATTR_TYPE = 'attributeType'
PT_KEY_ATTR_VALUE = 'attributeValue'
PT_KEY_ATTRS = 'attributes'
PT_KEY_DNS = 'dns'
PT_KEY_ENRICHMENT = 'enrichment'
PT_KEY_FIELD = 'field'
PT_KEY_FIRST_SEEN = 'firstSeen'
PT_KEY_HOSTNAME = 'hostname'
PT_KEY_INTEL = 'intelligence'
PT_KEY_LAST_SEEN = 'lastSeen'
PT_KEY_QUERY = "query"
PT_KEY_RESULTS = 'results'
PT_KEY_SSL = 'ssl'
PT_KEY_TASK = "task"
PT_KEY_USERNAME = "username"
PT_KEY_WHOIS = 'whois'
PT_MSG_BASE_CONNECTION = "Using url: {base_url}"
PT_MSG_CONNECTIVITY_TEST_FAIL = "Connectivity test failed"
PT_MSG_CONNECTIVITY_TEST_PASS = "Connectivity test passed"
PT_MSG_PROCESS_RESP = 'Processing results'
PT_MSG_QUERYING = "Querying {data} data"
PT_VAR_BASE_URL = 'https://api.passivetotal.org/v2'


class PassivetotalConnector(BaseConnector):

    """PassiveTotal connector code."""

    ACTION_ID_ANALYTIC_TRACKERS = "analytic_trackers"
    ACTION_ID_CHECK_BLACKLIST = "check_blacklist"
    ACTION_ID_CHECK_OSINT = "check_osint"
    ACTION_ID_CLASSIFY_ITEM = "classify_item"
    ACTION_ID_CREATE_ALERT = "create_alert"
    ACTION_ID_CREATE_TAG = "create_tag"
    ACTION_ID_FIND_MALWARE = "find_malware"
    ACTION_ID_FIND_OSINT = "find_osint"
    ACTION_ID_FIND_SUBDOMAINS = "find_subdomains"
    ACTION_ID_FIND_TAGS = "find_tags"
    ACTION_ID_GEOLOCATE_IP = "geolocate_ip"
    ACTION_ID_HOST_PAIRS = "host_pairs"
    ACTION_ID_METADATA_DOMAIN = "metadata_domain"
    ACTION_ID_METADATA_IP = "metadata_ip"
    ACTION_ID_MONITOR_ITEM = "monitor_item"
    ACTION_ID_PASSIVE_DNS = "passive_dns"
    ACTION_ID_PASSIVE_DNS_KEYWORD = "passive_dns_keyword"
    ACTION_ID_SSL_CERTIFICATE_DETAILS = "ssl_certificate_details"
    ACTION_ID_SSL_CERTIFICATE_HISTORY = "ssl_certificate_history"
    ACTION_ID_SSL_CERTIFICATE_KEYWORD = "ssl_certificate_keyword"
    ACTION_ID_WEB_ASSET_HISTORY = "web_asset_history"
    ACTION_ID_WHOIS_DOMAIN = "whois_domain"
    ACTION_ID_WHOIS_IP = "whois_ip"
    ACTION_ID_WHOIS_KEYWORD = "whois_keyword"

    def __init__(self):
        """Load details from the base connector class."""
        super(PassivetotalConnector, self).__init__()

    def validate_parameters(self, param):
        """Override the BaseConnector validation routine.

        Disable BaseConnector's validate functionality, since this app supports
        unicode domains and the validation routines don't.

        :param param: Item to type check
        :return: Success all the time
        """
        return phantom.APP_SUCCESS

    def initialize(self):
        """Prep the connector with configuration data."""
        config = self.get_config()
        self._username = config[PT_KEY_USERNAME]
        self._api_key = config[PT_KEY_API]
        self._host = PT_VAR_BASE_URL
        return phantom.APP_SUCCESS

    def _build_header(self):
        """Build a header for debug purposes when making calls."""
        headers = dict()
        pversion = self.get_product_version()
        headers['PT-INTEGRATION'] = 'Phantom %s' % str(pversion)
        headers['PT-Phantom-App-ID'] = self.get_app_id()
        headers['PT-Phantom-App-Config'] = self.get_app_config()
        return headers

    def _generate_request_instance(self, request_type):
        """Automatically generate a request instance to use.

        In the end, this saves us from having to load each request class in a
        explicit way. Loading via a string is helpful to reduce the code per
        call.

        :param request_type: Type of client instance to load
        :return: Loaded class instance with debug headers
        """
        class_lookup = {PT_KEY_DNS: PT_INST_DNS,
                        PT_KEY_WHOIS: PT_INST_WHOIS,
                        PT_KEY_SSL: PT_INST_SSL,
                        PT_KEY_ENRICHMENT: PT_INST_ENRICHMENT,
                        PT_KEY_ATTRS: PT_INST_ATTRIBUTES,
                        PT_KEY_ACCOUNT: PT_INST_ACCOUNT,
                        PT_KEY_ACTIONS: PT_INST_ACTIONS,
                        PT_KEY_INTEL: PT_INST_INTEL}
        class_name = class_lookup[request_type]
        mod = __import__('passivetotal.libs.%s' % request_type,
                         fromlist=[class_name])
        loaded = getattr(mod, class_name)
        headers = self._build_header()
        authenticated = loaded(self._username, self._api_key, headers=headers)
        return authenticated

    def _valid_response(self, response, action_result):
        """Check the response back from the server and handle any errors.

        :param response: Loaded response from PassiveTotal
        :param action_result: Phantom context to populate on error
        :return: bool of success for the response
        """
        if 'error' not in response:
            return True
        error = response['error']
        message = ("PassiveTotal: [HTTP %d] %s, %s" % (
            error.get('http_code', 500),
            error.get('message', 'Failed to grab message'),
            error.get('developer_message', 'Failed to grab message')
        ))
        self.debug_print(message, response)
        action_result.set_status(phantom.APP_ERROR, message)
        return False

    def _format_error(self, action_result):
        """Central location for handling errors on a bad response."""
        self.debug_print(action_result.get_message())
        self.set_status(phantom.APP_ERROR, action_result.get_message())
        self.append_to_message(PT_MSG_CONNECTIVITY_TEST_FAIL)
        return phantom.APP_ERROR

    def _test_connectivity(self, param):
        """Test the connectivity to PassiveTotal."""
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(PT_MSG_BASE_CONNECTION, base_url=self._host)
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES,
                           self._host)
        # Build the PassiveTotal client
        client = self._generate_request_instance(PT_KEY_ACCOUNT)
        self.save_progress(PT_MSG_QUERYING, data="account")

        # Handle the response back
        response = client.get_account_details()
        if not (self._valid_response(response, action_result)):
            return self._format_error(action_result)

        return self.set_status_save_progress(phantom.APP_SUCCESS,
                                             PT_MSG_CONNECTIVITY_TEST_PASS)

    def _generic_query(self, profile, action_result=None):
        """Generic process for getting data out of PassiveTotal.

        This will take in a calling profile and then dynamically create the
        request instance and call the method through a string invoke. Params
        are passed via keywords to the request instance.

        While this is a bit complicated to read, it saves a significant
        amount of code for most of the requests we need to make to
        PassiveTotal.
        """
        param = profile['param']
        if (action_result is None):
            action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(PT_MSG_BASE_CONNECTION, base_url=self._host)
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)
        data = action_result.add_data(dict())

        self.save_progress(profile['msg'])
        # Load the instance based on the query type
        client = self._generate_request_instance(profile['instance'])
        # Invoke the method via our profile string
        response = getattr(client, profile['method'])(**profile['args'])

        self.save_progress(PT_MSG_PROCESS_RESP)
        if not (self._valid_response(response, action_result)):
            return self._format_error(action_result)

        # Send the whole response and deal with it in the data paths
        if 'task' in profile.keys():
            data[PT_KEY_RESULTS] = {profile['task']: response}
        else:
            data[PT_KEY_RESULTS] = response

        # This returns the set status
        return action_result.set_status(phantom.APP_SUCCESS)

    def _analytic_trackers(self, param):
        """Search the host attribute trackers."""
        query = param.get(PT_KEY_QUERY, None)
        task = param.get(PT_KEY_TASK, None)
        msg = PT_MSG_QUERYING.format(data="analytics trackers")
        profile = {'param': param, 'instance': PT_KEY_ATTRS,
                   'method': 'get_host_attribute_trackers',
                   'args': {'query': query}, 'msg': msg, 'task': task}
        return self._generic_query(profile)

    def _host_pairs(self, param):
        """Search the host attribute pairs."""
        query = param.get(PT_KEY_QUERY, None)
        task = param.get(PT_KEY_TASK, None)
        msg = PT_MSG_QUERYING.format(data="host pairs")
        profile = {'param': param, 'instance': PT_KEY_ATTRS,
                   'method': 'get_host_attribute_pairs',
                   'args': {'query': query, 'direction': 'parents'},
                   'msg': msg}
        parent_data = self._generic_query(profile)
        profile = {'param': param, 'instance': PT_KEY_ATTRS,
                   'method': 'get_host_attribute_pairs',
                   'args': {'query': query, 'direction': 'children'},
                   'msg': msg}
        child_data = self._generic_query(profile)
        return {'results': {task: {'results': {'parents': parent_data, 'children': child_data}}}}

    def _check_blacklist(self, param):
        """Check if an item is on a known blacklist."""
        query = param.get(PT_KEY_QUERY, None)
        task = param.get(PT_KEY_TASK, None)
        msg = PT_MSG_QUERYING.format(data="blacklist")
        profile = {'param': param, 'instance': PT_KEY_INTEL,
                   'method': 'get_blacklisted',
                   'args': {'query': query},
                   'msg': msg, 'task': task}
        results = self._generic_query(profile)
        return {'results': {task: {'results': {results}}}}

    def _check_osint(self, param):
        """Check if an item has any OSINT reporting."""
        query = param.get(PT_KEY_QUERY, None)
        task = param.get(PT_KEY_TASK, None)
        msg = PT_MSG_QUERYING.format(data="OSINT")
        profile = {'param': param, 'instance': PT_KEY_ENRICHMENT,
                   'method': 'get_osint',
                   'args': {'query': query}, 'msg': msg, 'task': task}

        action_result = self.add_action_result(ActionResult(dict(param)))
        self._generic_query(profile, action_result)
        action_result.update_summary({'hasOsint': False})

        # get_extra_data and get_data will always return lists
        tmp = action_result.get_data()[0]
        tmp = tmp.get("results", {})
        tmp = tmp.get(task, {})
        if len(tmp.get('results', [])):
            action_result.update_summary({'hasOsint': True})
        return action_result

    def _classify_item(self, param):
        """Classify an item inside of PassiveTotal."""
        query = param.get('query', None)
        classification = param.get('classification', None)
        profile = {'param': param, 'instance': PT_KEY_ACTIONS,
                   'method': 'set_classification_status',
                   'args': {'query': query, 'classification': classification},
                   'msg': "Setting classification", 'task': task}
        return self._generic_query(profile)

    def _create_alert(self, param):
        """."""
        raise NotImplementedError

    def _create_tag(self, param):
        """Add a tag to an item inside of PassiveTotal."""
        query = param.get('query', None)
        task = param.get(PT_KEY_TASK, None)
        tags = param.get('tags', "").split(",")
        profile = {'param': param, 'instance': PT_KEY_ACTIONS,
                   'method': 'add_tags',
                   'args': {'query': query, 'tags': tags},
                   'msg': "Creating tag", 'task': task}
        return self._generic_query(profile)

    def _find_malware(self, param):
        """Find any malware associated with a query."""
        query = param.get(PT_KEY_QUERY, None)
        task = param.get(PT_KEY_TASK, None)
        msg = PT_MSG_QUERYING.format(data="malware")
        profile = {'param': param, 'instance': PT_KEY_ENRICHMENT,
                   'method': 'get_malware',
                   'args': {'query': query}, 'msg': msg, 'task': task}
        return self._generic_query(profile)

    def _find_osint(self, param):
        """Find any OSINT associated with a query."""
        query = param.get(PT_KEY_QUERY, None)
        task = param.get(PT_KEY_TASK, None)
        msg = PT_MSG_QUERYING.format(data="OSINT")
        profile = {'param': param, 'instance': PT_KEY_ENRICHMENT,
                   'method': 'get_osint',
                   'args': {'query': query}, 'msg': msg, 'task': task}
        return self._generic_query(profile)

    def _find_subdomains(self, param):
        """Find any subdomains associated with a query."""
        query = param.get(PT_KEY_QUERY, None)
        task = param.get(PT_KEY_TASK, None)
        msg = PT_MSG_QUERYING.format(data="subdomains")
        profile = {'param': param, 'instance': PT_KEY_ENRICHMENT,
                   'method': 'get_subdomains',
                   'args': {'query': query}, 'msg': msg, 'task': task}

        action_result = self.add_action_result(ActionResult(dict(param)))
        self._generic_query(profile, action_result)
        action_result.update_summary({'subdomains': list()})

        # get_extra_data and get_data will always return lists
        tmp = action_result.get_data()[0]
        tmp = tmp.get("results", {})
        tmp = tmp.get(task, {})
        records = list()
        for item in tmp.get('subdomains', []):
            if query.startswith("*."):
                query = query.lstrip("*.")
            full = '.'.join([item, query])
            records.append({'subdomain': item, 'domain': full})
        action_result.update_summary({'subdomains': records})
        return action_result

    def _find_tags(self, param):
        """Find tags associated with a query."""
        query = param.get('query', None)
        task = param.get(PT_KEY_TASK, None)
        msg = PT_MSG_QUERYING.format(data="tags")
        profile = {'param': param, 'instance': PT_KEY_ENRICHMENT,
                   'method': 'get_enrichment',
                   'args': {'query': query}, 'msg': msg, 'task': task}
        return self._generic_query(profile)

    def _geolocate_ip(self, param):
        """Get geolocation data for an IP address."""
        query = param.get(PT_KEY_QUERY, None)
        task = param.get(PT_KEY_TASK, None)
        msg = PT_MSG_QUERYING.format(data="metadata")
        profile = {'param': param, 'instance': PT_KEY_ENRICHMENT,
                   'method': 'get_enrichment',
                   'args': {'query': query}, 'msg': msg, 'task': task}
        return self._generic_query(profile)

    def _metadata_details(self, param):
        """Get metadata for a query."""
        query = param.get(PT_KEY_QUERY, None)
        task = param.get(PT_KEY_TASK, None)
        msg = PT_MSG_QUERYING.format(data="metadata")
        profile = {'param': param, 'instance': PT_KEY_ENRICHMENT,
                   'method': 'get_enrichment',
                   'args': {'query': query}, 'msg': msg, 'task': task}
        return self._generic_query(profile)

    def _monitor_item(self, param):
        """Monitor an item inside of PassiveTotal."""
        query = param.get('query', None)
        task = param.get(PT_KEY_TASK, None)
        profile = {'param': param, 'instance': PT_KEY_ACTIONS,
                   'method': 'set_monitor_status',
                   'args': {'query': query, 'status': True},
                   'msg': "Setting monitor status", 'task': task}
        return self._generic_query(profile)

    def _passive_dns(self, param):
        """Get passive DNS information for a query."""
        query = param.get(PT_KEY_QUERY, None)
        task = param.get(PT_KEY_TASK, None)
        msg = PT_MSG_QUERYING.format(data="passive DNS")
        profile = {'param': param, 'instance': PT_KEY_DNS,
                   'method': 'get_passive_dns',
                   'args': {'query': query}, 'msg': msg, 'task': task}
        return self._generic_query(profile)

    def _passive_dns_keyword(self, param):
        """Search passive DNS data using a keyword."""
        query = param.get(PT_KEY_QUERY, None)
        task = param.get(PT_KEY_TASK, None)
        msg = PT_MSG_QUERYING.format(data="passive DNS keyword")
        profile = {'param': param, 'instance': PT_KEY_DNS,
                   'method': 'search_keyword',
                   'args': {'query': query}, 'msg': msg, 'task': task}
        return self._generic_query(profile)

    def _certificate_details(self, param):
        """Get certificate details for a SHA-1."""
        query = param.get(PT_KEY_QUERY, None)
        task = param.get(PT_KEY_TASK, None)
        msg = PT_MSG_QUERYING.format(data="SSL certificate details")
        profile = {'param': param, 'instance': PT_KEY_SSL,
                   'method': 'get_ssl_certificate_details',
                   'args': {'query': query}, 'msg': msg, 'task': task}
        return self._generic_query(profile)

    def _certificate_history(self, param):
        """Get the SSL certificate history for a query."""
        query = param.get(PT_KEY_QUERY, None)
        task = param.get(PT_KEY_TASK, None)
        msg = PT_MSG_QUERYING.format(data="SSL certificate history")
        profile = {'param': param, 'instance': PT_KEY_SSL,
                   'method': 'get_ssl_certificate_history',
                   'args': {'query': query}, 'msg': msg, 'task': task}
        return self._generic_query(profile)

    def _certificate_keyword(self, param):
        """Search SSL certificates using a keyword."""
        query = param.get(PT_KEY_QUERY, None)
        task = param.get(PT_KEY_TASK, None)
        msg = PT_MSG_QUERYING.format(data="SSL certificate keyword")
        profile = {'param': param, 'instance': PT_KEY_SSL,
                   'method': 'search_keyword',
                   'args': {'query': query}, 'msg': msg, 'task': task}
        return self._generic_query(profile)

    def _web_asset_history(self, param):
        """Get web asset history based on a keyword."""
        query = param.get(PT_KEY_QUERY, None)
        task = param.get(PT_KEY_TASK, None)
        msg = PT_MSG_QUERYING.format(data="web asset history")
        profile = {'param': param, 'instance': PT_KEY_ATTRS,
                   'method': 'get_host_attribute_components',
                   'args': {'query': query}, 'msg': msg, 'task': task}
        return self._generic_query(profile)

    def _search_whois(self, param):
        """Search for WHOIS data on a specific field."""
        query = param.get(PT_KEY_QUERY, None)
        field = param.get(PT_KEY_FIELD, None)
        task = param.get(PT_KEY_TASK, None)
        msg = "Searching WHOIS %s" % field
        profile = {'param': param, 'instance': PT_KEY_WHOIS,
                   'method': 'search_whois_by_field',
                   'args': {'query': query, 'field': field}, 'msg': msg,
                   'task': task}
        return self._generic_query(profile)

    def _whois_keyword(self, param):
        """Search for WHOIS records using a keyword."""
        query = param.get(PT_KEY_QUERY, None)
        task = param.get(PT_KEY_TASK, None)
        msg = "Searching WHOIS by keyword"
        profile = {'param': param, 'instance': PT_KEY_WHOIS,
                   'method': 'search_keyword',
                   'args': {'query': query}, 'msg': msg, 'task': task}
        return self._generic_query(profile)

    def _whois_details(self, param):
        """Get WHOIS details for a query."""
        query = param.get(PT_KEY_QUERY, None)
        task = param.get(PT_KEY_TASK, None)
        msg = "Searching WHOIS by keyword"
        profile = {'param': param, 'instance': PT_KEY_WHOIS,
                   'method': 'get_whois_details',
                   'args': {'query': query, 'compact_record': True},
                   'msg': msg, 'task': task}
        return self._generic_query(profile)

    def handle_action(self, param):
        """Route the action to the proper function."""
        action = self.get_action_identifier()
        action = param.get(PT_KEY_TASK, None)
        ret_val = phantom.APP_SUCCESS

        if (action == self.ACTION_ID_ANALYTIC_TRACKERS):
            ret_val = self._analytic_trackers(param)
        elif (action == self.ACTION_ID_CHECK_BLACKLIST):
            ret_val = self._check_blacklist(param)
        elif (action == self.ACTION_ID_CHECK_OSINT):
            ret_val = self._check_osint(param)
        elif (action == self.ACTION_ID_CLASSIFY_ITEM):
            ret_val = self._classify_item(param)
        elif (action == self.ACTION_ID_CREATE_ALERT):
            ret_val = self._create_alert(param)
        elif (action == self.ACTION_ID_CREATE_TAG):
            ret_val = self._create_tag(param)
        elif (action == self.ACTION_ID_FIND_MALWARE):
            ret_val = self._find_malware(param)
        elif (action == self.ACTION_ID_FIND_OSINT):
            ret_val = self._find_osint(param)
        elif (action == self.ACTION_ID_FIND_SUBDOMAINS):
            ret_val = self._find_subdomains(param)
        elif (action == self.ACTION_ID_FIND_TAGS):
            ret_val = self._find_tags(param)
        elif (action == self.ACTION_ID_GEOLOCATE_IP):
            ret_val = self._geolocate_ip(param)
        elif (action == self.ACTION_ID_HOST_PAIRS):
            ret_val = self._host_pairs(param)
        elif (action == self.ACTION_ID_METADATA_DOMAIN):
            ret_val = self._metadata_details(param)
        elif (action == self.ACTION_ID_METADATA_IP):
            ret_val = self._metadata_details(param)
        elif (action == self.ACTION_ID_MONITOR_ITEM):
            ret_val = self._monitor_item(param)
        elif (action == self.ACTION_ID_PASSIVE_DNS):
            ret_val = self._passive_dns(param)
        elif (action == self.ACTION_ID_PASSIVE_DNS_KEYWORD):
            ret_val = self._passive_dns_keyword(param)
        elif (action == self.ACTION_ID_SSL_CERTIFICATE_DETAILS):
            ret_val = self._certificate_details(param)
        elif (action == self.ACTION_ID_SSL_CERTIFICATE_HISTORY):
            ret_val = self._certificate_history(param)
        elif (action == self.ACTION_ID_SSL_CERTIFICATE_KEYWORD):
            ret_val = self._certificate_keyword(param)
        elif (action == self.ACTION_ID_WEB_ASSET_HISTORY):
            ret_val = self._web_asset_history(param)
        elif (action == self.ACTION_ID_WHOIS_DOMAIN):
            ret_val = self._whois_details(param)
        elif (action == self.ACTION_ID_WHOIS_IP):
            ret_val = self._whois_details(param)
        elif (action == self.ACTION_ID_WHOIS_KEYWORD):
            ret_val = self._whois_keyword(param)
        elif (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)

        return ret_val

if __name__ == '__main__':
    import json
    import pudb
    import sys

    pudb.set_trace()

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = PassivetotalConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print json.dumps(json.loads(ret_val), indent=4)

    sys.exit(0)
