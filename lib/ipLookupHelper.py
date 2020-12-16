#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# IP Lookup utility aiming to help gather expected details of a specific IPv4 address.
# 
# Usage: ./ipLookupHelper.py <ipaddress> [malleable-redirector-config]
# 
# Use this small utility to collect IP Lookup details on your target IPv4 address and verify whether
# your 'ip_geolocation_requirements' section of proxy2 malleable-redirector-config.yaml would match that
# IP address. If second param is not given - no IP Geolocation evaluation will be performed.
#
# Author:
#   Mariusz B. / mgeeky, 20
#   <mb@binary-offensive.com>
#

VERSION = '0.4'

import sys
import pprint
import json, re
import requests
import random
import yaml
import urllib3, ssl

from urllib.parse import urlparse, parse_qsl

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ssl._create_default_https_context = ssl._create_unverified_context

API_KEYS = {
  'ipgeolocation_io': '',
}


class Logger:
    @staticmethod
    def _out(x): 
        sys.stdout.write(x + '\n')

    @staticmethod
    def dbg(x):
        sys.stdout.write('[dbg] ' + x + '\n')

    @staticmethod
    def out(x): 
        Logger._out('[.] ' + x)
    
    @staticmethod
    def info(x):
        Logger._out('[?] ' + x)
    
    @staticmethod
    def err(x): 
        sys.stdout.write('[!] ' + x + '\n')
    
    @staticmethod
    def fail(x):
        Logger._out('[-] ' + x)
    
    @staticmethod
    def ok(x):  
        Logger._out('[+] ' + x)


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
                    if apiKeys[prov] == None or len(apiKeys[prov].strip()) < 2: continue
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
            return {}

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
                out = r.json()
                if not out: out = ''
                if type(out) != str: out = str(out)

                raise Exception(f'ip-api.com returned unexpected status code: {r.status_code}.\nOutput text:\n{out}')

            return r.json()

        except Exception as e:
            self.logger.err(f'Exception catched while querying ip-api.com with {ipAddress}:\nName: {e}', color='cyan')

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
                out = r.json()
                if not out: out = ''
                if type(out) != str: out = str(out)

                raise Exception(f'ipapi.co returned unexpected status code: {r.status_code}.\nOutput text:\n{out}')

            return r.json()

        except Exception as e:
            self.logger.err(f'Exception catched while querying ipapi.co with {ipAddress}:\nName: {e}', color='cyan')

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
                out = r.json()
                if not out: out = ''
                if type(out) != str: out = str(out)

                raise Exception(f'ipapi.co returned unexpected status code: {r.status_code}.\nOutput text:\n{out}')

            return r.json()

        except Exception as e:
            self.logger.err(f'Exception catched while querying ipapi.co with {ipAddress}:\nName: {e}', color='cyan')

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
            self.logger.err(f'Given IP geolocation results object was either empty or not a dictionary: {ipLookupResult}')
            return ''

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

    @staticmethod
    def getValues(v, n = 0):
        values = []

        if type(v) == str:
            if ' ' in v:
                values.extend(v.split(' '))
            values.append(v)
        elif type(v) == int or type(v) == float:
            values.extend([str(v)])
        elif type(v) == tuple or type(v) == list:
            for w in v:
                values.extend(IPGeolocationDeterminant.getValues(w, n+1))
        elif type(v) == dict and n < 10:
            values.extend(IPGeolocationDeterminant.getValuesDict(v, n+1))

        return values

    @staticmethod
    def getValuesDict(data, n = 0):
        values = []

        for k, v in data.items():
            if type(v) == dict and n < 10:
                values.extend(IPGeolocationDeterminant.getValuesDict(v, n+1))
            elif n < 10:
                values.extend(IPGeolocationDeterminant.getValues(v, n+1))

        return values

    def validateIpGeoMetadata(self, ipLookupDetails):
        if len(ipLookupDetails) == 0: return (True, '')

        words = set(list(filter(None, IPGeolocationDeterminant.getValuesDict(ipLookupDetails))))
        if len(words) == 0: return (True, '')

        self.logger.dbg(f"Extracted keywords from Peer's IP Geolocation metadata: ({words})")

        for w in words:
            for x in BANNED_AGENTS:
                if ((' ' in x) and (x.lower() in w.lower())):
                    self.logger.dbg(f"Peer's IP Geolocation metadata contained banned phrase: ({w})")
                    return (False, w)

                elif (w.lower() == x.lower()):
                    self.logger.dbg(f"Peer's IP Geolocation metadata contained banned keyword: ({w})")
                    return (False, w)

        self.logger.dbg(f"Peer's IP Geolocation metadata didn't raise any suspicion.")
        return (True, '')

def main(argv):
    if len(argv) < 2:
        print ('''

Usage: ./ipLookupHelper.py <ipaddress> [malleable-redirector-config]

Use this small utility to collect IP Lookup details on your target IPv4 address and verify whether
your 'ip_geolocation_requirements' section of proxy2 malleable-redirector-config.yaml would match that
IP address. If second param is not given - no IP Geolocation evaluation will be performed.

''')
        return False

    ipaddr = sys.argv[1]
    conf = ''
    if len(argv) == 3: conf = sys.argv[2]

    logger = Logger()
    lookup = IPLookupHelper(logger, API_KEYS)

    print('[.] Lookup of: ' + ipaddr)
    result = lookup.lookup(ipaddr)
    print('[.] Output:\n' + str(json.dumps(result, indent=2)))

    if conf != '':
        config = {}
        with open('malleable-redirector-config.yml') as f:
            try:
                config = yaml.load(f, Loader=yaml.FullLoader)
            except:
                config = yaml.load(f)

        deter = IPGeolocationDeterminant(config['ip_geolocation_requirements'])
        out = deter.determine(result)
        print('[.] IP Geolocation determination as instructed by malleable config returned: ' + str(out))

if __name__ == '__main__':
    main(sys.argv)