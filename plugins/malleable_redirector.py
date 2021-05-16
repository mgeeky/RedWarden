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
# Requirements:
#   - brotli
#   - yaml
#
# Author:
#   Mariusz B. / mgeeky, '19-'20
#   <mb@binary-offensive.com>
#

import re, sys
import os
import hashlib
import socket
import pprint
import requests
import random
import os.path
import ipaddress
import yaml, json

from urllib.parse import urlparse, parse_qsl, parse_qs, urlsplit
from IProxyPlugin import *
from sqlitedict import SqliteDict
from lib.ipLookupHelper import IPLookupHelper, IPGeolocationDeterminant
from datetime import datetime


BANNED_AGENTS = []
OVERRIDE_BANNED_AGENTS = []
alreadyPrintedPeers = set()

class MalleableParser:
    ProtocolTransactions = ('http-stager', 'http-get', 'http-post')
    TransactionBlocks = ('metadata', 'id', 'output')
    UriParameters = ('uri', 'uri_x86', 'uri_x64')
    CommunicationParties = ('client', 'server')

    GlobalOptionsDefaults = {
        'data_jitter': "0",
        'dns_idle': "0.0.0.0",
        'dns_max_txt': "252",
        'dns_sleep': "0",
        'dns_stager_prepend': "",
        'dns_stager_subhost': ".stage.123456.",
        'dns_ttl': "1",
        'headers_remove': "",
        'host_stage': "true",
        'jitter': "0",
        'maxdns': "255",
        'pipename': "msagent_##",
        'pipename_stager': "status_##",
        'sample_name': "My Profile",
        'sleeptime': "60000",
        'smb_frame_header': "",
        'ssh_banner': "Cobalt Strike 4.2",
        'ssh_pipename': "postex_ssh_####",
        'tcp_frame_header': "",
        'tcp_port': "4444",
        'useragent': "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko",
    }

    def __init__(self, logger):
        self.path = ''
        self.data = ''
        self.datalines = []
        self.logger = logger
        self.parsed = {}
        self.config = self.parsed
        self.variants = []

    def get_config(self):
        return self.config

    def parse(self, path):
        try:
            with open(path, 'r') as f:
                self.data = f.read().replace('\r\n', '\n')
                self.datalines = self.data.split('\n')

        except FileNotFoundError as e:
            self.logger.fatal("Malleable profile specified in redirector's config file (profile) doesn't exist: ({})".format(path))

        pos = 0
        linenum = 0
        depth = 0
        dynkey = []
        parsed = self.parsed

        regexes = {
            # Finds: set name "value";
            'set-name-value' : r"\s*set\s+(\w+)\s+(?=(?:(?<!\w)'(\S.*?)'(?!\w)|\"(\S.*?)\"(?!\w))).*",
            
            # Finds: section { as well as variant-driven: section "variant" {
            'begin-section-and-variant' : r'^\s*([\w-]+)(\s+"[^"]+")?\s*\{\s*',

            # Finds: [set] parameter ["value", ...];
            'set-parameter-value' : r'(?:([\w-]+)\s+(?=")".*")|(?:([\w-]+)(?=;))',

            # Finds: prepend "something"; and append "something";
            'prepend-append-value' : r'\s*(prepend|append)\s*"([^"\\]*(?:\\.[^"\\]*)*)"',
            
            'parameter-value' : r"(?=(?:(?<!\w)'(\S.*?)'(?!\w)|\"(\S.*?)\"(?!\w)))",
        }

        compregexes = {}

        for k, v in regexes.items():
            compregexes[k] = re.compile(v, re.I)

        while linenum < len(self.datalines):
            line = self.datalines[linenum]

            assert len(dynkey) == depth, "Depth ({}) and dynkey differ ({})".format(depth, dynkey)

            if line.strip() == '': 
                pos += len(line)
                linenum += 1
                continue

            if line.lstrip().startswith('#'): 
                pos += len(line) + 1
                linenum += 1
                continue

            if len(line) > 100:
                self.logger.dbg('[key: {}, line: {}, pos: {}] {}...{}'.format(str(dynkey), linenum, pos, line[:50], line[-50:]))
            else:
                self.logger.dbg('[key: {}, line: {}, pos: {}] {}'.format(str(dynkey), linenum, pos, line[:100]))

            parsed = self.parsed
            for key in dynkey:
                sect, variant = key
                if len(variant) > 0:
                    parsed = parsed[sect][variant]
                else:
                    parsed = parsed[sect]

            matched = False

            m = compregexes['begin-section-and-variant'].match(line)
            twolines = self.datalines[linenum]

            if len(self.datalines) >= linenum+1:
                twolines += self.datalines[linenum+1]

            n = compregexes['begin-section-and-variant'].match(twolines)
            if m or n:
                if m == None and n != None: 
                    self.logger.dbg('Section opened in a new line: [{}] = ["{}"]'.format(
                        n.group(1), 
                        twolines.replace('\r', "\\r").replace('\n', "\\n")
                    ))
                    linenum += 1
                    pos += len(self.datalines[linenum])
                    m = n

                depth += 1
                section = m.group(1)
                variant = ''

                if section not in parsed.keys():
                    parsed[section] = {}

                if m.group(2) is not None:
                    variant = m.group(2).strip().replace('"', '')
                    parsed[section][variant] = {}
                    parsed[section]['variant'] = variant

                elif section in MalleableParser.ProtocolTransactions:
                    variant = 'default'
                    parsed[section][variant] = {}
                    parsed[section]['variant'] = variant

                else:
                    parsed[section] = {}

                if len(variant) > 0 and variant not in self.variants:
                    self.variants.append(variant)
                
                self.logger.dbg('Extracted section: [{}] (variant: {})'.format(section, variant))

                dynkey.append((section, variant))

                matched = 'section'
                pos += len(line)
                linenum += 1
                continue

            if line.strip() == '}':
                depth -= 1
                matched = 'endsection'
                sect, variant = dynkey.pop()
                variant = ''

                if sect in parsed.keys() and 'variant' in parsed[sect][variant].keys():
                    variant = '(variant: {})'.format(variant)

                self.logger.dbg('Reached end of section {}.{}'.format(sect, variant))
                pos += len(line)
                linenum += 1
                continue

            m = compregexes['set-name-value'].match(line)
            if m:
                n = list(filter(lambda x: x != None, m.groups()[2:]))[0]
                
                val = n.replace('\\\\', '\\')
                param = m.group(1)

                if param.lower() == 'uri' or param.lower() == 'uri_x86' or param.lower() == 'uri_x64':
                    parsed[param] = val.split(' ')
                    self.logger.dbg('Multiple URIs defined: [{}] = [{}]'.format(param, ', '.join(val.split(' '))))

                else:
                    parsed[param] = val
                    self.logger.dbg('Extracted variable: [{}] = [{}]'.format(param, val))

                matched = 'set'
                pos += len(line)
                linenum += 1
                continue

            # Finds: [set] parameter ["value", ...];
            m = compregexes['set-parameter-value'].search(line)
            if m:
                paramname = list(filter(lambda x: x != None, m.groups()))[0]
                restofline = line[line.find(paramname) + len(paramname):]
                values = []

                n = compregexes['prepend-append-value'].search(line)
                if n != None and len(n.groups()) > 1:
                    paramname = n.groups()[0]
                    paramval = n.groups()[1].replace('\\\\', '\\')
                    values.append(paramval)
                    self.logger.dbg('Extracted {} value: "{}..."'.format(paramname, paramval[:20]))

                else: 
                    for n in compregexes['parameter-value'].finditer(restofline):
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
                pos += len(line)
                linenum += 1
                continue

            a = linenum
            b = linenum+1

            if a > 5: a -= 5

            if b > len(self.datalines): b = len(self.datalines)
            elif b < len(self.datalines) + 5: b += 5

            self.logger.err("Unexpected statement:\n\t{}\n\n----- Context -----\n\n{}\n".format(
                line,
                '\n'.join(self.datalines[a:b])
                ))

            self.logger.err("\nParsing failed.")
            return False

        self.normalize()
        return True

    def normalize(self):
        for k, v in self.config.items():
            if k in MalleableParser.ProtocolTransactions:
                if k == 'http-get' and 'verb' not in self.config[k].keys():
                    self.config[k]['verb'] = 'GET'
                elif k == 'http-post' and 'verb' not in self.config[k].keys():
                    self.config[k]['verb'] = 'POST'

                for a in MalleableParser.CommunicationParties:
                    if a not in self.config[k]:
                        self.config[k][a] = {
                            'header' : [],
                            'variant' : 'default',
                        }
                    else:
                        if 'header' not in self.config[k][a].keys(): self.config[k][a]['header'] = []
                        if 'variant' not in self.config[k][a].keys(): self.config[k][a]['variant'] = 'default'

        for k, v in MalleableParser.GlobalOptionsDefaults.items():
            if k.lower() not in self.config.keys():
                self.config[k] = v
                self.logger.dbg('MalleableParser: Global variable ({}) not defined. Setting default value of: "{}"'.format(k, v))


class ProxyPlugin(IProxyPlugin):
    class AlterHostHeader(Exception):
        pass

    RequestsHashesDatabaseFile = '.anti-replay.sqlite'
    DynamicWhitelistFile = '.peers.sqlite'

    DefaultRedirectorConfig = {
        'profile' : '',
        'teamserver_url' : [],
        'drop_action': 'redirect',
        'action_url': ['https://google.com', ],
        'proxy_pass': {},
        'log_dropped': False,
        'report_only': False,
        'ban_blacklisted_ip_addresses': True,
        'ip_addresses_blacklist_file': 'data/banned_ips.txt',
        'banned_agents_words_file': 'data/banned_words.txt',
        'override_banned_agents_file': 'data/banned_words_override.txt',
        'mitigate_replay_attack': False,
        'whitelisted_ip_addresses' : [],
        'protect_these_headers_from_tampering' : [],
        'verify_peer_ip_details': True,
        'malleable_redirector_hidden_api_endpoint' : '',
        'remove_superfluous_headers': True,
        'ip_details_api_keys': {},
        'ip_geolocation_requirements': {},
        'throttle_down_peer' : {
            'log_request_delay': 30,
            'requests_threshold': 5
        },
        'add_peers_to_whitelist_if_they_sent_valid_requests' : {
            'number_of_valid_http_get_requests': 15,
            'number_of_valid_http_post_requests': 5
        },
        'policy': {
            'allow_proxy_pass' : True,
            'allow_dynamic_peer_whitelisting' : True,
            'drop_invalid_useragent' : True,
            'drop_http_banned_header_names' : True,
            'drop_http_banned_header_value' : True,
            'drop_dangerous_ip_reverse_lookup' : True,
            'drop_ipgeo_metadata_containing_banned_keywords' : True,
            'drop_malleable_without_expected_header' : True,
            'drop_malleable_without_expected_header_value' : True,
            'drop_malleable_without_expected_request_section' : True,
            'drop_malleable_without_request_section_in_uri' : True,
            'drop_malleable_without_prepend_pattern' : True,
            'drop_malleable_without_apppend_pattern' : True,
            'drop_malleable_unknown_uris' : True,
            'drop_malleable_with_invalid_uri_append' : True,
        }
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

        for k, v in ProxyPlugin.DefaultRedirectorConfig.items():
            if k not in self.proxyOptions.keys():
                self.proxyOptions[k] = v

        open(ProxyPlugin.DynamicWhitelistFile, 'w').close()
        with SqliteDict(ProxyPlugin.DynamicWhitelistFile, autocommit=True) as mydict:
            mydict['whitelisted_ips'] = []
            mydict['peers'] = {}

    @staticmethod
    def get_name():
        return 'malleable_redirector'

    def drop_reason(self, text):
        self.logger.err(text, color='magenta')
        if not self.proxyOptions['report_only']:
            if 'X-Drop-Reason' in self.addToResHeaders.keys():
                self.addToResHeaders['X-Drop-Reason'] += '; ' + text
            else:
                self.addToResHeaders['X-Drop-Reason'] = text

    def help(self, parser):
        global BANNED_AGENTS
        global OVERRIDE_BANNED_AGENTS

        parametersRequiringDirectPath = (
            'ip_addresses_blacklist_file',
            'banned_agents_words_file',
            'override_banned_agents_file',
            'profile',
            'output'
        )

        proxy2BasePath = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))

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
                        #redirectorConfig = yaml.load(f, Loader=yaml.FullLoader)
                        redirectorConfig = yaml.load(f)

                    self.proxyOptions.update(redirectorConfig)

                    for k, v in ProxyPlugin.DefaultRedirectorConfig.items():
                        if k not in self.proxyOptions.keys():
                            self.proxyOptions[k] = v

                    p = os.path.join(proxy2BasePath, self.proxyOptions['redir_config'])
                    if os.path.isfile(p) or os.path.isdir(p):
                        configBasePath = p
                    else:
                        configBasePath = os.path.dirname(os.path.abspath(self.proxyOptions['redir_config']))
                else:
                    p = os.path.join(proxy2BasePath, self.proxyOptions['config'])
                    if os.path.isfile(p) or os.path.isdir(p):
                        configBasePath = p
                    else:
                        configBasePath = os.path.dirname(os.path.abspath(self.proxyOptions['config']))

                self.ipLookupHelper = IPLookupHelper(self.logger, self.proxyOptions['ip_details_api_keys'])
                self.ipGeolocationDeterminer = IPGeolocationDeterminant(self.logger, self.proxyOptions['ip_geolocation_requirements'])

                for paramName in parametersRequiringDirectPath:
                    if paramName in self.proxyOptions.keys() and \
                        self.proxyOptions[paramName] != '' and self.proxyOptions[paramName] != None:
                        p = os.path.join(configBasePath, self.proxyOptions[paramName])
                        if not (os.path.isfile(self.proxyOptions[paramName]) or os.path.isdir(self.proxyOptions[paramName])) and (os.path.isfile(p) or os.path.isdir(p)):
                            self.proxyOptions[paramName] = p

            except FileNotFoundError as e:
                self.logger.fatal(f'Malleable-redirector config file not found: ({self.proxyOptions["config"]})!')

            except Exception as e:
                self.logger.fatal(f'Unhandled exception occured while parsing Malleable-redirector config file: {e}')

            profileSkipped = False
            if ('profile' not in self.proxyOptions.keys()) or (not self.proxyOptions['profile']):
                self.logger.err('''

=================================================================================================
 MALLEABLE C2 PROFILE PATH NOT SPECIFIED! LOGIC BASED ON PARSING HTTP REQUESTS WILL BE DISABLED!
=================================================================================================
''')
                self.malleable = None
                profileSkipped = True

            else:
                self.malleable = MalleableParser(self.logger)

                self.logger.dbg(f'Parsing input Malleable profile: ({self.proxyOptions["profile"]})')
                if not self.malleable.parse(self.proxyOptions['profile']):
                    self.logger.fatal('Could not parse specified Malleable C2 profile!')

            if not profileSkipped and (not self.proxyOptions['action_url'] or len(self.proxyOptions['action_url']) == 0):
                if self.proxyOptions['drop_action'] != 'reset':
                    self.logger.fatal('Action/Drop URL must be specified!')

            elif type(self.proxyOptions['action_url']) == str:
                url = self.proxyOptions['action_url']
                if ',' not in url:
                    self.proxyOptions['action_url'] = [url.strip(), ]
                else:
                    self.proxyOptions['action_url'] = [x.strip() for x in url.split(',')]

            elif type(self.proxyOptions['action_url']) == None and profileSkipped:
                self.proxyOptions['action_url'] = []

            if self.proxyOptions['proxy_pass'] == None:
                self.proxyOptions['proxy_pass'] = {}

            elif (type(self.proxyOptions['proxy_pass']) != list) and \
                (type(self.proxyOptions['proxy_pass']) != tuple):
                self.logger.fatal('Proxy Pass must be a list of entries if used!')

            else:
                passes = {}
                num = 0

                for entry in self.proxyOptions['proxy_pass']:
                    if len(entry) < 6:
                        self.logger.fatal('Invalid Proxy Pass entry: ({}): too short!',format(entry))

                    splits = list(filter(None, entry.strip().split(' ')))

                    url = ''
                    host = ''

                    if len(splits) < 2:
                        self.logger.fatal('Invalid Proxy Pass entry: ({}): invalid syntax: <url host [options]> required!'.format(entry))

                    url = splits[0].strip()
                    host = splits[1].strip()
                    scheme = ''

                    if host.startswith('https://') or host.startswith('http://'):
                        parsed = urlparse(host)
                        
                        if len(parsed.scheme) > 0:
                            scheme = parsed.scheme

                            host = scheme + '://' + parsed.netloc

                            if len(parsed.path) > 0:
                                host += parsed.path
                            if len(parsed.query) > 0:
                                host += '?' + parsed.query
                            if len(parsed.fragment) > 0:
                                host += '#' + parsed.fragment

                        elif len(parsed.netloc) > 0:
                            host = parsed.netloc

                        else:
                            host = parsed.path
                            if len(parsed.query) > 0:
                                host += '?' + parsed.query
                            if len(parsed.fragment) > 0:
                                host += '#' + parsed.fragment
                    else:
                        host = host.strip().replace('https://', '').replace('http://', '')

                    passes[num] = {}
                    passes[num]['url'] = url
                    passes[num]['redir'] = host
                    passes[num]['scheme'] = scheme
                    passes[num]['options'] = {}

                    if len(splits) > 2:
                        opts = ' '.join(splits[2:])
                        for opt in opts.split(','):
                            opt2 = opt.split('=')
                            k = opt2[0]
                            v = ''
                            if len(opt2) == 2: 
                                v = opt2[1]
                            else:
                                v = '='.join(opt2[1:])

                            passes[num]['options'][k.strip()] = v.strip()

                    if len(url) == 0 or len(host) < 4:
                        self.logger.fatal('Invalid Proxy Pass entry: (url="{}" host="{}"): either URL or host part were missing or too short (schema is ignored).',format(url, host))

                    if not url.startswith('/'):
                        self.logger.fatal('Invalid Proxy Pass entry: (url="{}" host="{}"): URL must start with slash character (/).',format(url, host))

                    num += 1

                if len(passes) > 0:
                    self.proxyOptions['proxy_pass'] = passes.copy()

                    lines = []
                    for num, e in passes.items():
                        what = 'host'
                        if '/' in e['redir']: what = 'target URL'

                        line = "\tRule {}. Proxy requests with URL: \"^{}$\" to {} {}".format(
                            num, e['url'], what, e['redir']
                        )

                        if len(e['options']) > 0:
                            line += " (options: "
                            opts = []
                            for k,v in e['options'].items():
                                if len(v) > 0:
                                    opts.append("{}: {}".format(k, v))
                                else:
                                    opts.append("{}".format(k))

                            line += ', '.join(opts) + ")"

                        lines.append(line)

                    self.logger.info('Collected {} proxy-pass statements: \n{}'.format(
                        len(passes), '\n'.join(lines)
                    ))

            #if not self.proxyOptions['teamserver_url']:
            #    self.logger.fatal('Teamserver URL must be specified!')

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
                if len(self.proxyOptions['action_url']) == 0:
                    self.logger.fatal('Drop URL must be specified for proxy action - pointing from which host to fetch responses!')
                else:
                    self.logger.info('Will redirect/proxy requests to these hosts: {}'.format(', '.join(self.proxyOptions['action_url'])), color=self.logger.colors_map['cyan'])

            p = os.path.join(proxy2BasePath, self.proxyOptions['banned_agents_words_file'])
            if not os.path.isfile(p):
                p = self.proxyOptions['banned_agents_words_file']

            if not os.path.isfile(p):
                self.logger.fatal('Could not locate banned_agents_words_file file!\nTried following path:\n\t' + p)

            with open(p, 'r') as f:
                for line in f.readlines():
                    if len(line.strip()) == 0: continue
                    if line.strip().startswith('#'): continue
                    BANNED_AGENTS.append(line.strip().lower())

                self.logger.dbg(f'Loaded {len(BANNED_AGENTS)} banned words.')

            p = os.path.join(proxy2BasePath, self.proxyOptions['override_banned_agents_file'])
            if not os.path.isfile(p):
                p = self.proxyOptions['override_banned_agents_file']

            if not os.path.isfile(p):
                self.logger.fatal('Could not locate override_banned_agents_file file!\nTried following path:\n\t' + p)

            with open(p, 'r') as f:
                for line in f.readlines():
                    if len(line.strip()) == 0: continue
                    if line.strip().startswith('#'): continue
                    OVERRIDE_BANNED_AGENTS.append(line.strip().lower())

                self.logger.dbg(f'Loaded {len(OVERRIDE_BANNED_AGENTS)} whitelisted words.')

            if self.proxyOptions['ban_blacklisted_ip_addresses']:
                p = os.path.join(proxy2BasePath, self.proxyOptions['ip_addresses_blacklist_file'])
                if not os.path.isfile(p):
                    p = self.proxyOptions['ip_addresses_blacklist_file']

                if not os.path.isfile(p):
                    self.logger.fatal('Could not locate ip_addresses_blacklist_file file!\nTried following path:\n\t' + p)

                with open(p, 'r') as f:
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

            if self.proxyOptions['mitigate_replay_attack']:
                with SqliteDict(ProxyPlugin.RequestsHashesDatabaseFile) as mydict:
                    self.logger.info('Opening request hashes SQLite from file {} to prevent Replay Attacks.'.format(ProxyPlugin.RequestsHashesDatabaseFile))

            if 'policy' in self.proxyOptions.keys() and self.proxyOptions['policy'] != None \
                and len(self.proxyOptions['policy']) > 0:
                log = 'Enabled policies:\n'
                for k, v in self.proxyOptions['policy'].items():
                    log += '\t{}: {}\n'.format(k, str(v))
                self.logger.dbg(log)
            else:
                self.logger.info("No policies defined in config. Defaults to all-set.")
                for k, v in ProxyPlugin.DefaultRedirectorConfig['policy'].items():
                    self.proxyOptions['policy'][k] = v

            if 'add_peers_to_whitelist_if_they_sent_valid_requests' in self.proxyOptions.keys() and self.proxyOptions['add_peers_to_whitelist_if_they_sent_valid_requests'] != None \
                and len(self.proxyOptions['add_peers_to_whitelist_if_they_sent_valid_requests']) > 0:

                log = 'Dynamic peers whitelisting enabled with thresholds:\n'

                for k, v in self.proxyOptions['add_peers_to_whitelist_if_they_sent_valid_requests'].items():
                    if k not in ProxyPlugin.DefaultRedirectorConfig['add_peers_to_whitelist_if_they_sent_valid_requests'].keys():
                        self.logger.err("Dynamic whitelisting threshold named ({}) not supported! Skipped..".format(k))

                    log += '\t{}: {}\n'.format(k, str(v))
                self.logger.dbg(log)

            else:
                self.logger.info("Dynamic peers whitelisting disabled.")
                self.proxyOptions['add_peers_to_whitelist_if_they_sent_valid_requests'] = {}


    def report(self, ret, ts = '', peerIP = '', path = '', userAgentValue = ''):
        prefix = 'ALLOW'
        col = 'green'
        logit = True

        if ret: 
            prefix = 'DROP'
            col = 'magenta'

        if self.proxyOptions['report_only']:
            if ret:
                prefix = 'WOULD-BE-DROPPED'
                col = 'magenta'
                #self.logger.info(' (Report-Only) =========[X] REQUEST WOULD BE BLOCKED =======', color='magenta')
            ret = False

        if 'throttle_down_peer' in self.proxyOptions.keys() and len(self.proxyOptions['throttle_down_peer']) > 0:
            with SqliteDict(ProxyPlugin.DynamicWhitelistFile, autocommit=True) as mydict:
                if 'peers' not in mydict.keys():
                    mydict['peers'] = {}

                if peerIP in mydict['peers'].keys():
                    last = mydict['peers'][peerIP]['last']
                    cur = datetime.now().timestamp()

                    prev = mydict.get('peers', {})

                    if (cur - last).seconds < self.proxyOptions['throttle_down_peer']['log_request_delay']:
                        prev[peerIP]['count'] += 1
                    else:
                        prev[peerIP]['count'] = 0

                    if prev[peerIP]['count'] > self.proxyOptions['throttle_down_peer']['requests_threshold']:
                        logit = False

                    mydict['peers'] = prev

        if logit or self.proxyOptions['debug']:
            self.logger.info('[{}, {}, {}] "{}" - UA: "{}"'.format(prefix, ts, peerIP, path, userAgentValue), 
                color=col, 
                forced = True,
                noprefix = True
            )
        return ret

    @staticmethod
    def get_mock_req(peerIP, command, path, headers):
        class Request(object):
            pass

        req = Request()
        req.method = command
        req.client_address = [peerIP, ]
        req.headers = {}
        req.uri = path
        if headers: req.headers = headers

        return req

    def get_peer_ip(self, req):
        regexes = {
            'first-ip' : r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            'forwarded-ip' : r'for=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        }

        originating_ip_headers = {
            'x-forwarded-for' : regexes['first-ip'],
            'forwarded' : regexes['forwarded-ip'],
            'cf-connecting-ip' : regexes['first-ip'],
            'true-client-ip' : regexes['first-ip'],
            'x-real-ip' : regexes['first-ip'],
        }

        peerIP = req.client_address[0]

        for k, v in req.headers.items():
            if k.lower() in originating_ip_headers.keys():
                res = re.findall(originating_ip_headers[k.lower()], v, re.I)
                if res and len(res) > 0:
                    peerIP = res[0]
                    break

        return peerIP

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

    def pickTeamserver(self, req, req_body = None, res = None, res_body = None):
        if len(self.proxyOptions['teamserver_url']) == 0:
            self.logger.err('No Teamserver origins specified: dropping request.')
            raise Exception(self.drop_action(req, req_body, res, res_body, False))

        self.logger.dbg('Peer reached the server at port: ' + str(req.server_port))
        for s in self.proxyOptions['teamserver_url']:
            u = urlparse(req.uri)
            inport, scheme, host, port = self.interpretTeamserverUrl(s)
            if inport == req.server_port:
                return s
            elif inport == '':
                return s

        #return req.uri
        return random.choice(self.proxyOptions['teamserver_url'])

    def redirect(self, req, _target, malleable_meta):
        # Passing the request forward.
        u = urlparse(req.uri)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        target = _target
        newhost = ''
        orighost = req.headers['Host']

        if target in self.proxyOptions['teamserver_url']:
            inport, scheme, host, port = self.interpretTeamserverUrl(target)
            if not scheme: scheme = 'https'

            w = urlparse(target)
            scheme2, netloc2, path2 = w.scheme, w.netloc, (w.path + '?' + w.query if w.query else w.path)
            req.uri = '{}://{}:{}{}'.format(scheme, host, port, (u.path + '?' + u.query if u.query else u.path))
            newhost = host
            if port:
                newhost += ':' + str(port)

        else:
            if not target.startswith('http'):
                if req.is_ssl:
                    target = 'https://' + target
                else:
                    target = 'http://' + target

            w = urlparse(target)
            scheme2, netloc2, path2 = w.scheme, w.netloc, (w.path + '?' + w.query if w.query else w.path)
            if netloc2 == '': netloc2 = req.headers['Host']

            req.uri = '{}://{}{}'.format(scheme2, netloc2, (u.path + '?' + u.query if u.query else u.path))
            newhost = netloc2

        if self.proxyOptions['remove_superfluous_headers'] and len(self.proxyOptions['profile']) > 0:
            self.logger.dbg('Stripping HTTP request from superfluous headers...')
            self.strip_headers(req, malleable_meta)

        self.logger.dbg('Redirecting to "{}"'.format(req.uri))

        req.headers[proxy2_metadata_headers['ignore_response_decompression_errors']] = "1"
        req.headers[proxy2_metadata_headers['override_host_header']] = newhost

        if 'host' in malleable_meta.keys() and len(malleable_meta['host']) > 0:
            req.headers[proxy2_metadata_headers['domain_front_host_header']] = malleable_meta['host']

        return None

    def strip_headers(self, req, malleable_meta):
        if not malleable_meta or len(malleable_meta) == 0:
            self.logger.dbg("strip_headers: No malleable_meta provided!", color = 'red')
            return False

        section = malleable_meta['section']
        variant = malleable_meta['variant']

        if section == '' and variant == '':
            return False

        if section == '' or variant == '':
            self.logger.dbg("strip_headers: No section name ({}) or variant ({}) provided!".format(section, variant), color = 'red')
            return False

        if section not in self.malleable.config.keys():
            self.logger.dbg("strip_headers: Section name ({}) not found in malleable.config!".format(section), color = 'red')
            return False

        if variant not in self.malleable.config[section].keys():
            self.logger.dbg("strip_headers: Variant name ({}) not found in malleable.config[{}]!".format(variant, section), color = 'red')
            return False

        configblock = self.malleable.config[section][variant]

        reqhdrs = [x.lower() for x in req.headers.keys()]
        expectedheaders = [x[0].lower() for x in configblock['client']['header']]

        dont_touch_these_headers = [
            'user-agent', 'host'
        ]

        if 'http-config' in self.malleable.config.keys() and 'trust_x_forwarded_for' in self.malleable.config['http-config'].keys():
            if self.malleable.config['http-config']['trust_x_forwarded_for'] == True:
                dont_touch_these_headers.append('x-forwarded-for')

        for b in MalleableParser.TransactionBlocks:
            if b in configblock['client'].keys():
                if type(configblock['client'][b]) != dict: continue

                for k, v in configblock['client'][b].items():
                    if k == 'header': 
                        dont_touch_these_headers.append(v.lower())

        for h in reqhdrs:
            if h not in expectedheaders and h not in dont_touch_these_headers:
                del req.headers[h]

        strip_headers_during_forward = []
        if 'accept-encoding' not in expectedheaders: strip_headers_during_forward.append('Accept-Encoding')
        #if 'host' not in expectedheaders: strip_headers_during_forward.append('Host')

        if len(strip_headers_during_forward) > 0:
            req.headers[proxy2_metadata_headers['strip_headers_during_forward']] = ','.join(strip_headers_during_forward)

        return True

    def response_handler(self, req, req_body, res, res_body):
        self.is_request = False
        self.logger.dbg('malleable_redirector: response_handler')
        (ret, jsonParsed) = self.checkIfHiddenAPICall(req, req_body)

        if ret:
            return self.prepareResponseForHiddenAPICall(jsonParsed, req, req_body, res, res_body)

        return self._response_handler(req, req_body, res, res_body)

    def request_handler(self, req, req_body, res = '', res_body = ''):
        self.is_request = True
        (ret, jsonParsed) = self.checkIfHiddenAPICall(req, req_body)

        if ret:
            self.logger.dbg("Will process hidden API request for peerIP at a later stage: " + jsonParsed['peerIP'])
            return DontFetchResponseException('Hidden API call request. Moving along to generate response.')

        return self._request_handler(req, req_body)

    def _request_handler(self, req, req_body):
        self.req = req
        self.req_body = req_body
        self.res = None
        self.res_body = None

        peerIP = self.get_peer_ip(req)

        drop_request = False
        newhost = ''
        malleable_meta = {
            'section' : '',
            'host' : '',
            'variant' : '',
            'uri' : '',
        }

        try:
            drop_request = self.drop_check(req, req_body, malleable_meta)
            host_action = 1

        except ProxyPlugin.AlterHostHeader as e:
            host_action = 2
            drop_request = True
            newhost = str(e)

        req.connection.no_keep_alive = drop_request

        if drop_request and host_action == 1:
            if self.proxyOptions['drop_action'] == 'proxy' and self.proxyOptions['action_url']:

                url = self.proxyOptions['action_url']
                if (type(self.proxyOptions['action_url']) == list or \
                    type(self.proxyOptions['action_url']) == tuple) and \
                    len(self.proxyOptions['action_url']) > 0: 

                    url = random.choice(self.proxyOptions['action_url'])
                    self.logger.dbg('Randomly choosen redirect to URL: "{}"'.format(url))

                self.logger.err('[PROXYING invalid request from {}] {} {}'.format(
                    req.client_address[0], req.method, req.uri
                ), color = 'cyan')
                return self.redirect(req, url, malleable_meta)

            return self.drop_action(req, req_body, None, None)

        elif drop_request and host_action == 2:
            if newhost.startswith('http://') or newhost.startswith('https://'):
                self.logger.dbg('Altering URL to: "{}"'.format(newhost))
            else:
                self.logger.dbg('Altering host header to: "{}"'.format(newhost))

            return self.redirect(req, newhost, malleable_meta)

        if not self.proxyOptions['report_only'] and self.proxyOptions['mitigate_replay_attack']:
            with SqliteDict(ProxyPlugin.RequestsHashesDatabaseFile, autocommit=True) as mydict:
                mydict[self.computeRequestHash(req, req_body)] = 1

        if 'throttle_down_peer' in self.proxyOptions.keys() and len(self.proxyOptions['throttle_down_peer']) > 0:
            with SqliteDict(ProxyPlugin.DynamicWhitelistFile, autocommit=True) as mydict:
                if 'peers' not in mydict.keys():
                    mydict['peers'] = {}
                    
                prev = mydict.get('peers', {})

                if peerIP not in mydict.get('peers', {}):
                    prev[peerIP] = {
                        'last': 0,
                        'count': 0
                    }

                prev['last'] = datetime.now().timestamp()
                mydict['peers'] = prev

        if self.proxyOptions['policy']['allow_dynamic_peer_whitelisting'] and \
            len(self.proxyOptions['add_peers_to_whitelist_if_they_sent_valid_requests']) > 0 and \
            len(malleable_meta['section']) > 0 and malleable_meta['section'] in MalleableParser.ProtocolTransactions:
            with SqliteDict(ProxyPlugin.DynamicWhitelistFile, autocommit=True) as mydict:
                if peerIP not in mydict.get('whitelisted_ips', []):
                    key = '{}-{}'.format(malleable_meta['section'], peerIP)
                    prev = mydict.get(key, 0) + 1
                    mydict[key] = prev

                    a = mydict.get('http-get-{}'.format(peerIP), 0)
                    b = mydict.get('http-post-{}'.format(peerIP), 0)

                    a2 = int(self.proxyOptions['add_peers_to_whitelist_if_they_sent_valid_requests']['number_of_valid_http_get_requests'])
                    b2 = int(self.proxyOptions['add_peers_to_whitelist_if_they_sent_valid_requests']['number_of_valid_http_post_requests'])

                    self.logger.info('Connected peer sent {} valid http-get and {} valid http-post requests so far, out of {}/{} required to consider him temporarily trusted'.format(
                        a, b, a2, b2
                    ), color = 'yellow')

                    if a > a2:
                        if b > b2:
                            self.logger.info('Adding connected peer ({}) to a dynamic whitelist as it reached its thresholds: ({}, {})'.format(peerIP, a, b), color='green')
                            val = mydict.get('whitelisted_ips', [])
                            val.append(peerIP.strip())
                            mydict['whitelisted_ips'] = val

        ts = ''
        try:
            ts = self.pickTeamserver(req, req_body, self.res, self.res_body)
        except Exception as e:
            s = self.proxyOptions['drop_action']
            self.logger.err(f'No Teamserver provided. Falling back to drop request strategy.: {s}')
            raise Exception(str(e))

        return self.redirect(req, ts, malleable_meta)

    def _response_handler(self, req, req_body, res, res_body):
        self.is_request = False
        self.req = req
        self.req_body = req_body
        self.res = res
        self.res_body = res_body

        host_action = -1
        newhost = ''
        malleable_meta = {
            'section' : '',
            'host' : '',
            'variant' : '',
            'uri' : '',
        }

        drop_request = False
        req.connection.no_keep_alive = True

        try:
            drop_request = self.drop_check(req, req_body, malleable_meta)
            host_action = 1
        except ProxyPlugin.AlterHostHeader as e:
            host_action = 2
            drop_request = True
            newhost = str(e)

        if drop_request:
            if host_action == 1:
                self.logger.dbg('Not returning body from response handler')
                return self.drop_action(req, req_body, res, res_body, True)

            elif host_action == 2:
                self.logger.dbg('Altering host header in response_handler to: "{}"'.format(newhost))
                del req.headers['Host']
                req.headers['Host'] = newhost
                req.headers[proxy2_metadata_headers['override_host_header']] = newhost

        # A nifty hack to make the proxy2 believe we actually modified the response
        # so that the proxy will not encode it to gzip (or anything specified) and just
        # return the response as-is, in an "Content-Encoding: identity" kind of fashion
        res.headers[proxy2_metadata_headers['override_response_content_encoding']] = 'identity'

        req.connection.no_keep_alive = False

        return res_body

    def drop_action(self, req, req_body, res, res_body, quiet = False):

        if self.proxyOptions['report_only']:
            self.logger.info('(Report-Only) Not taking any action on invalid request.')
            if self.is_request: 
                return req_body
            return res_body

        todo = ''
        if self.proxyOptions['drop_action'] == 'reset': todo = 'DROPPING'
        elif self.proxyOptions['drop_action'] == 'redirect': todo = 'REDIRECTING'
        elif self.proxyOptions['drop_action'] == 'proxy': todo = 'PROXYING'

        u = urlparse(req.uri)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)

        peer = req.client_address[0]

        try:
            resolved = socket.gethostbyaddr(req.client_address[0])[0]
            peer += ' ({})'.format(resolved)
        except:
            pass

        if not quiet: 
            self.logger.err('[{} invalid request from {}] {} {}'.format(
                todo, peer, req.method, path
            ), color='cyan')

        if self.proxyOptions['log_dropped'] == True:
            req_headers = req.headers
            rb = req_body
            if rb != None and len(rb) > 0:
                if type(rb) == type(b''): 
                    rb = rb.decode()
                rb = '\r\n' + rb
            else:
                rb = ''

            request = '{} {} {}\r\n{}{}'.format(
                req.method, path, 'HTTP/1.1', req_headers, rb
            )

            if not quiet: self.logger.err('\n\n{}'.format(request), color='cyan')

        if self.proxyOptions['drop_action'] == 'reset':
            return DropConnectionException('Not a conformant beacon request.')

        elif self.proxyOptions['drop_action'] == 'redirect':
            if self.is_request:
                return DontFetchResponseException('Not a conformant beacon request.')

            if res == None: 
                self.logger.err('Response handler received a None res object.')
                return res_body 

            url = self.proxyOptions['action_url']
            if (type(self.proxyOptions['action_url']) == list or \
                type(self.proxyOptions['action_url']) == tuple) and \
                len(self.proxyOptions['action_url']) > 0: 

                url = random.choice(self.proxyOptions['action_url'])

            res.status = 301
            res.response_version = 'HTTP/1.1'
            res.reason = 'Moved Permanently'
            res_body = '''<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="{}">here</A>.
</BODY></HTML>'''.format(url)

            res.headers = {
                'Server' : 'nginx',
                'Location': url,
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

    def computeRequestHash(self, req, req_body):
        m = hashlib.md5()
        req_headers = req.headers
        rb = req_body
        if rb != None and len(rb) > 0:
            if type(rb) == type(b''): 
                rb = rb.decode()
            rb = '\r\n' + rb
        else:
            rb = ''

        request = '{} {} {}\r\n{}{}'.format(
            req.method, req.uri, 'HTTP/1.1', req_headers, rb
        )

        m.update(request.encode())
        h = m.hexdigest()
        self.logger.dbg("Requests's MD5 hash computed: {}".format(h))

        return h


    def validatePeerAndHttpHeaders(self, peerIP, ts, req, req_body, res, res_body, parsedJson):
        respJson = {}
        returnJson = (parsedJson != None and res != None)

        ipLookupDetails = None
        userAgentValue = req.headers.get('User-Agent')
        respJson['drop_type'] = self.proxyOptions['drop_action']
        respJson['action_url'] = self.proxyOptions['action_url']

        if self.proxyOptions['whitelisted_ip_addresses'] != None and len(self.proxyOptions['whitelisted_ip_addresses']) > 0:
            for cidr in self.proxyOptions['whitelisted_ip_addresses']:
                cidr = cidr.strip()
                if ipaddress.ip_address(peerIP) in ipaddress.ip_network(cidr, False):
                    msg = '[ALLOW, {}, reason:1, {}] peer\'s IP address is whitelisted: ({})'.format(
                        ts, peerIP, cidr
                    )

                    if returnJson:
                        respJson['action'] = 'allow'
                        respJson['reason'] = '1'
                        respJson['message'] = msg
                        respJson['ipgeo'] = self.printPeerInfos(peerIP, True)
                        return (True, respJson)
                    else:
                        self.logger.info(msg, color='green')
                        return (True, self.report(False, ts, peerIP, req.uri, userAgentValue))

        if self.proxyOptions['policy']['allow_dynamic_peer_whitelisting'] and \
            len(self.proxyOptions['add_peers_to_whitelist_if_they_sent_valid_requests']) > 0:
            with SqliteDict(ProxyPlugin.DynamicWhitelistFile) as mydict:
                if peerIP in mydict.get('whitelisted_ips', []):
                    msg = '[ALLOW, {}, reason:2, {}] Peer\'s IP was added dynamically to a whitelist based on a number of allowed requests.'.format(
                        ts, peerIP
                    )

                    if returnJson:
                        respJson['action'] = 'allow'
                        respJson['reason'] = '2'
                        respJson['message'] = msg
                        respJson['ipgeo'] = self.printPeerInfos(peerIP, True)
                        return (True, respJson)
                    else:
                        self.logger.info(msg, color='green')
                        return (True, self.report(False, ts, peerIP, req.uri, userAgentValue))

        if self.proxyOptions['ban_blacklisted_ip_addresses']:
            for cidr, _comment in self.banned_ips.items():
                if ipaddress.ip_address(peerIP) in ipaddress.ip_network(cidr, False):
                    reverseIp = ''
                    try:
                        reverseIp = socket.gethostbyaddr(peerIP)[0]
                    except:
                        pass

                    blockAnyway = True
                    entry = ''

                    for w in OVERRIDE_BANNED_AGENTS:
                        if w.lower() in reverseIp.lower():
                            blockAnyway = False
                            entry = w
                            break

                    if blockAnyway:
                        comment = ''
                        if len(_comment) > 0:
                            comment = ' - ' + _comment

                        msg = '[DROP, {}, reason:4a, {}] Peer\'s IP address is blacklisted: ({}{} - rev_ip: "{}")'.format(
                                ts, peerIP, cidr, comment, reverseIp
                            )

                        if returnJson:
                            respJson['action'] = 'drop'
                            respJson['reason'] = '4a'
                            respJson['message'] = msg
                            respJson['ipgeo'] = self.printPeerInfos(peerIP, True)
                            return (True, respJson)
                        else:
                            self.drop_reason(msg)
                            self.printPeerInfos(peerIP)
                            return (True, self.report(True, ts, peerIP, req.uri, userAgentValue))

                    else:
                        self.logger.dbg(f'The peer with IP: {peerIP} (rev_ip: {reverseIp}) would be banned if there was no blacklist override entry ({entry}).')

        # Reverse-IP lookup check
        if self.proxyOptions['policy']['drop_dangerous_ip_reverse_lookup']:
            whitelisted = False
            try:
                resolved = socket.gethostbyaddr(req.client_address[0])[0]
                for part in resolved.split('.')[:-1]:
                    if whitelisted: break
                    if not part: continue
                    foo = any(re.search(r'\b'+re.escape(part)+r' \b', b, re.I) for b in BANNED_AGENTS)
                    if foo or part.lower() in BANNED_AGENTS and part.lower() not in OVERRIDE_BANNED_AGENTS:
                        a = part.lower() in OVERRIDE_BANNED_AGENTS
                        b = (x in part.lower() for x in OVERRIDE_BANNED_AGENTS)
                        if a or b:
                            self.logger.dbg('Peer\'s reverse-IP lookup would be banned because of word "{}" but was whitelisted.'.format(part))
                            whitelisted = True
                            break

                        msg = '[DROP, {}, reason:4b, {}] peer\'s reverse-IP lookup contained banned word: "{}"'.format(ts, peerIP, part)
                        
                        if returnJson:
                            respJson['action'] = 'drop'
                            respJson['reason'] = '4b'
                            respJson['message'] = msg
                            respJson['ipgeo'] = self.printPeerInfos(peerIP, True)
                            return (True, respJson)
                        else:
                            self.drop_reason(msg)
                            self.printPeerInfos(peerIP)
                            return (True, self.report(True, ts, peerIP, req.uri, userAgentValue))

            except Exception as e:
                pass

        # Banned words check
        if self.proxyOptions['policy']['drop_http_banned_header_names'] or self.proxyOptions['policy']['drop_http_banned_header_value']:
            whitelisted = False
            for k, v in req.headers.items():
                if whitelisted: break
                kv = k.split('-')
                vv = v.split(' ') + v.split('-')
                if self.proxyOptions['policy']['drop_http_banned_header_names']:
                    for kv1 in kv:
                        if whitelisted: break
                        if not kv1: continue
                        foo = any(re.search(r'\b'+re.escape(kv1)+r' \b', b, re.I) for b in BANNED_AGENTS)
                        if foo or kv1.lower() in BANNED_AGENTS:
                            a = kv1.lower() in OVERRIDE_BANNED_AGENTS
                            b = any(x in kv1.lower() for x in OVERRIDE_BANNED_AGENTS)
                            c = any(x in k.lower() for x in OVERRIDE_BANNED_AGENTS)
                            if a or b or c: 
                                self.logger.dbg('HTTP header name would be banned because of word "{}" but was overridden by whitelist file entries.'.format(kv1))
                                whitelisted = True
                                break

                            msg = '[DROP, {}, reason:2, {}] HTTP header name contained banned word: "{}" ({}: {})'.format(
                                    ts, peerIP, kv1, kv, vv)

                            if returnJson:
                                respJson['action'] = 'drop'
                                respJson['reason'] = '2'
                                respJson['message'] = msg
                                respJson['ipgeo'] = self.printPeerInfos(peerIP, True)
                                return (True, respJson)
                            else:
                                self.drop_reason(msg)
                                self.printPeerInfos(peerIP)
                                return (True, self.report(True, ts, peerIP, req.uri, userAgentValue))


                if self.proxyOptions['policy']['drop_http_banned_header_value']:
                    whitelisted = False
                    for vv1 in vv:
                        if whitelisted: break
                        if not vv1: continue
                        foo = any(re.search(r'\b'+re.escape(vv1)+r' \b', b, re.I) for b in BANNED_AGENTS)
                        if foo or vv1.lower() in BANNED_AGENTS:
                            a = vv1.lower() in OVERRIDE_BANNED_AGENTS
                            b = any(x in vv1.lower() for x in OVERRIDE_BANNED_AGENTS)
                            c = any(x in v.lower() for x in OVERRIDE_BANNED_AGENTS)
                            if a or b or c: 
                                self.logger.dbg('HTTP header value would be banned because of word "{}" but was overridden by whitelist file entries.'.format(vv1))
                                whitelisted = True
                                break

                            msg = '[DROP, {}, reason:3, {}] HTTP header value contained banned word: "{}" ({}: {})'.format(
                                    ts, peerIP, vv1, kv, vv)

                            if returnJson:
                                respJson['action'] = 'drop'
                                respJson['reason'] = '3'
                                respJson['message'] = msg
                                respJson['ipgeo'] = self.printPeerInfos(peerIP, True)
                                return (True, respJson)
                            else:
                                self.drop_reason(msg)
                                self.printPeerInfos(peerIP)
                                return (True, self.report(True, ts, peerIP, req.uri, userAgentValue))

        if self.proxyOptions['verify_peer_ip_details']:
            try:
                ipLookupDetails = self.ipLookupHelper.lookup(peerIP)
                whitelisted = False

                if ipLookupDetails and len(ipLookupDetails) > 0:
                    if 'organization' in ipLookupDetails.keys():
                        for orgWord in ipLookupDetails['organization']:
                            if whitelisted: break
                            for word in orgWord.split(' '):
                                if whitelisted: break
                                if not word: continue
                                foo = any(re.search(r'\b'+re.escape(word)+r' \b', b, re.I) for b in BANNED_AGENTS)
                                if foo or word.lower() in BANNED_AGENTS:
                                    a = word.lower() in OVERRIDE_BANNED_AGENTS
                                    b = any(x in orgWord.lower() for x in OVERRIDE_BANNED_AGENTS)
                                    if a or b: 
                                        self.logger.dbg('IP lookup organization field "{}" would be banned because of word "{}" but was overridden by whitelist file entries.'.format(orgWord, word))
                                        whitelisted = True
                                        break

                                    msg = '[DROP, {}, reason:4c, {}] peer\'s IP lookup organization field ({}) contained banned word: "{}"'.format(
                                        ts, peerIP, orgWord, word)

                                    if returnJson:
                                        respJson['action'] = 'drop'
                                        respJson['reason'] = '4c'
                                        respJson['message'] = msg
                                        respJson['ipgeo'] = ipLookupDetails
                                        return (True, respJson)
                                    else:
                                        self.drop_reason(msg)
                                        return (True, self.report(True, ts, peerIP, req.uri, userAgentValue))

            except Exception as e:
                self.logger.err(f'IP Lookup failed for some reason on IP ({peerIP}): {e}', color='cyan')

            try:
                if not self.ipGeolocationDeterminer.determine(ipLookupDetails):
                    msg = '[DROP, {}, reason:4d, {}] peer\'s IP geolocation ("{}", "{}", "{}", "{}", "{}") DID NOT met expected conditions'.format(
                        ts, peerIP, ipLookupDetails['continent'], ipLookupDetails['continent_code'], ipLookupDetails['country'], ipLookupDetails['country_code'], ipLookupDetails['city'], ipLookupDetails['timezone']
                    )
                    
                    if returnJson:
                        respJson['action'] = 'drop'
                        respJson['reason'] = '4d'
                        respJson['message'] = msg
                        respJson['ipgeo'] = ipLookupDetails
                        return (True, respJson)
                    else:
                        self.drop_reason(msg)
                        return (True, self.report(True, ts, peerIP, req.uri, userAgentValue))

            except Exception as e:
                self.logger.err(f'IP Geolocation determinant failed for some reason on IP ({peerIP}): {e}', color='cyan')

            if self.proxyOptions['policy']['drop_ipgeo_metadata_containing_banned_keywords']:
                self.logger.dbg("Analysing IP Geo metadata keywords...")
                try:
                    metaAnalysis = self.ipGeolocationDeterminer.validateIpGeoMetadata(ipLookupDetails, BANNED_AGENTS, OVERRIDE_BANNED_AGENTS)

                    if metaAnalysis[0] == False:
                        a = (metaAnalysis[1].lower() in OVERRIDE_BANNED_AGENTS)
                        b = any(x in metaAnalysis[1] for x in OVERRIDE_BANNED_AGENTS)
                        if a or b:
                            self.logger.dbg('Peer\'s IP geolocation metadata would be banned because it contained word "{}" but was overridden by whitelist file.'.format(metaAnalysis[1]))

                        else:
                            msg = '[DROP, {}, reason:4e, {}] Peer\'s IP geolocation metadata ("{}", "{}", "{}", "{}", "{}") contained banned keyword: ({})! Peer banned in generic fashion.'.format(
                                ts, peerIP, ipLookupDetails['continent'], ipLookupDetails['continent_code'], 
                                ipLookupDetails['country'], ipLookupDetails['country_code'], ipLookupDetails['city'], ipLookupDetails['timezone'], 
                                metaAnalysis[1]
                            )

                            if returnJson:
                                respJson['action'] = 'drop'
                                respJson['reason'] = '4e'
                                respJson['message'] = msg
                                respJson['ipgeo'] = ipLookupDetails
                                return (True, respJson)
                            else:
                                self.drop_reason(msg)
                                return (True, self.report(True, ts, peerIP, req.uri, userAgentValue))

                except Exception as e:
                    self.logger.dbg(f"Exception was thrown during drop_ipgeo_metadata_containing_banned_keywords verifcation:\n\t({e})")

        if returnJson:

            msg = '[ALLOW, {}, reason:99, {}] Peer IP and HTTP headers did not contain anything suspicious.'.format(
                            ts, peerIP)

            if not ipLookupDetails or \
                (type(ipLookupDetails) == dict and len(ipLookupDetails) == 0):
                respJson['ipgeo'] = self.printPeerInfos(peerIP, True)
            else:
                respJson['ipgeo'] = ipLookupDetails

            respJson['action'] = 'allow'
            respJson['reason'] = '99'
            respJson['message'] = msg
            return (False, respJson)
        else:
            return (False, False)

    def processProxyPass(self, ts, peerIP, req, processNodrops):
        if self.proxyOptions['proxy_pass'] != None and len(self.proxyOptions['proxy_pass']) > 0 \
            and self.proxyOptions['policy']['allow_proxy_pass']:

            for num, entry in self.proxyOptions['proxy_pass'].items():
                scheme = entry['scheme']
                url = entry['url']
                host = entry['redir']
                opts = ''

                if processNodrops:
                    if ('options' not in entry.keys()) or ('nodrop' not in entry['options'].keys()):
                        continue

                if 'nodrop' in entry['options'].keys():
                    opts += ', nodrop'

                if re.match('^' + url + '$', req.uri, re.I) != None:
                    self.logger.info(
                        '[ALLOW, {}, reason:0, {}]  Request conforms ProxyPass entry {} (url="{}" redir="{}"{}). Passing request to specified host.'.format(
                        ts, peerIP, num, url, host, opts
                    ), color='green')
                    self.printPeerInfos(peerIP)
                    self.report(False, ts, peerIP, req.uri, req.headers.get('User-Agent'))

                    #del req.headers['Host']
                    #req.headers['Host'] = host
                    if '/' in host:
                        req.headers[proxy2_metadata_headers['override_host_header']] = host[:host.find('/')]
                        req.uri = host
                    else:
                        req.headers[proxy2_metadata_headers['override_host_header']] = host
                    
                    if scheme and (scheme+'://' not in req.uri):
                        req.uri = '{}://{}'.format(scheme, host)

                    raise ProxyPlugin.AlterHostHeader(host)

                else:
                    self.logger.dbg('(ProxyPass) Processed request with URL ("{}"...) didnt match ProxyPass entry {} URL regex: "^{}$".'.format(req.uri[:32], num, url))


    def drop_check(self, req, req_body, malleable_meta):
        peerIP = self.get_peer_ip(req)
        ts = datetime.now().strftime('%Y-%m-%d/%H:%M:%S')
        userAgentValue = req.headers.get('User-Agent')

        self.processProxyPass(ts, peerIP, req, True)

        (outstatus, outresult) = self.validatePeerAndHttpHeaders(peerIP, ts, req, req_body, '', '', None)
        if outstatus:
            return outresult
        
        self.processProxyPass(ts, peerIP, req, False)

        # User-agent conformancy
        if self.malleable != None:
            if userAgentValue != self.malleable.config['useragent']\
            and self.proxyOptions['policy']['drop_invalid_useragent']:
                if self.is_request:
                    self.drop_reason(f'[DROP, {ts}, reason:1, {peerIP}] inbound User-Agent differs from the one defined in C2 profile.')
                    self.logger.dbg('Inbound UA: "{}", Expected: "{}"'.format(
                        userAgentValue, self.malleable.config['useragent']))
                return self.report(True, ts, peerIP, req.uri, userAgentValue)
        else:
            self.logger.dbg("(No malleable profile) User-agent test skipped, as there was no profile provided.", color='magenta')

        if self.proxyOptions['mitigate_replay_attack']:
            with SqliteDict(ProxyPlugin.RequestsHashesDatabaseFile) as mydict:
                if mydict.get(self.computeRequestHash(req, req_body), 0) != 0:
                    self.drop_reason(f'[DROP, {ts}, reason:0, {peerIP}] identical request seen before. Possible Replay-Attack attempt.')
                    return self.report(True, ts, peerIP, req.uri, userAgentValue)

        fetched_uri = ''
        fetched_host = req.headers['Host']

        if self.malleable != None:
            for section in MalleableParser.ProtocolTransactions:
                found = False
                variant = 'default'

                if section not in self.malleable.config.keys():
                    continue

                block = self.malleable.config[section]

                for uri in MalleableParser.UriParameters:
                    for var in self.malleable.variants:
                        if var not in block.keys(): continue
                        if type(block[var]) != dict: continue

                        if uri in block[var].keys():
                            _uri = block[var][uri]

                            if type(_uri) == str:
                                found = (_uri in req.uri)

                            elif (type(_uri) == list or type(_uri) == tuple) and len(_uri) > 0:
                                for u in _uri:
                                    if u in req.uri:
                                        found = True
                                        break

                            if found: 
                                variant = var
                                if 'client' in block[var].keys():
                                    if 'header' in block[var]['client'].keys():
                                        for header in block[var]['client']['header']:
                                            k, v = header
                                            if k.lower() == 'host':
                                                fetched_host = v
                                                break
                                break
                    if found: break

                if found:
                    malleable_meta['host'] = fetched_host if len(fetched_host) > 0 else req.headers['Host'],
                    if type(malleable_meta['host']) != str and len(malleable_meta['host']) > 0:
                        malleable_meta['host'] = malleable_meta['host'][0]

                    malleable_meta['variant'] = variant

                    if self._client_request_inspect(section, variant, req, req_body, malleable_meta, ts, peerIP): 
                        return self.report(True, ts, peerIP, req.uri, userAgentValue)

                    if self.is_request:
                        self.logger.info('== Valid malleable {} (variant: {}) request inbound.'.format(section, variant))
                        self.printPeerInfos(peerIP)

                    break

            if (not found) and (self.proxyOptions['policy']['drop_malleable_unknown_uris']):
                self.drop_reason('[DROP, {}, reason:11a, {}] Requested URI does not align any of Malleable defined variants: "{}"'.format(ts, peerIP, req.uri))
                return self.report(True, ts, peerIP, req.uri, userAgentValue)
        else:
            self.logger.dbg("(No malleable profile) Request contents validation skipped, as there was no profile provided.", color='magenta')

        return self.report(False, ts, peerIP, req.uri, userAgentValue)

    def printPeerInfos(self, peerIP, returnInstead = False):
        global alreadyPrintedPeers
        try:
            ipLookupDetails = self.ipLookupHelper.lookup(peerIP)
            if ipLookupDetails and len(ipLookupDetails) > 0:
                if returnInstead:
                    return ipLookupDetails

                printit = self.logger.info
                if peerIP in alreadyPrintedPeers:
                    printit = self.logger.dbg

                printit('Here is what we know about that address ({}): ({})'.format(peerIP, ipLookupDetails), color='grey')

                alreadyPrintedPeers.add(peerIP)

                return ipLookupDetails
        except Exception as e:
            pass

        return {}

    def _client_request_inspect(self, section, variant, req, req_body, malleable_meta, ts, peerIP):
        uri = req.uri
        rehdrskeys = [x.lower() for x in req.headers.keys()]

        if self.malleable == None:
            self.logger.dbg("(No malleable profile) Request contents validation skipped, as there was no profile provided.", color='magenta')
            return False

        self.logger.dbg("Deep request inspection of URI ({}) parsed as section:{}, variant:{}".format(
                req.uri, section, variant
            ))

        if section in self.malleable.config.keys() and variant in self.malleable.config[section].keys():
            uris = []

            configblock = self.malleable.config[section][variant]

            for u in MalleableParser.UriParameters:
                if u in configblock.keys(): 
                    if type(configblock[u]) == str: 
                        uris.append(configblock[u])
                    else: 
                        uris.extend(configblock[u])

            found = False
            exactmatch = True
            malleable_meta['section'] = section

            foundblocks = []
            blocks = MalleableParser.TransactionBlocks

            for _block in blocks: 
                if 'client' not in configblock.keys():
                    continue

                if _block not in configblock['client'].keys(): 
                    #self.logger.dbg('No block {} in [{}]'.format(_block, str(configblock['client'].keys())))
                    continue

                foundblocks.append(_block)
                if 'uri-append' in configblock['client'][_block].keys() or \
                    'parameter' in configblock['client'][_block].keys():
                    exactmatch = False

            for _uri in uris:
                if exactmatch == True and uri == _uri: 
                    found = True
                    if malleable_meta != None:
                        malleable_meta['uri'] = uri
                    break
                elif exactmatch == False:
                    if uri.startswith(_uri): 
                        found = True
                        malleable_meta['uri'] = uri
                        break

            if not found and self.proxyOptions['policy']['drop_malleable_unknown_uris']:
                if uri.startswith('//'):
                    uri = uri[1:]

                    for _uri in uris:
                        if exactmatch == True and uri == _uri: 
                            found = True
                            if malleable_meta != None:
                                malleable_meta['uri'] = uri
                            break
                        elif exactmatch == False:
                            if uri.startswith(_uri): 
                                found = True
                                malleable_meta['uri'] = uri
                                break
                if not found:
                    self.drop_reason('[DROP, {}, reason:11b, {}] Requested URI does not align any of Malleable defined variants: "{}"'.format(ts, peerIP, req.uri))
                    return True

            if section.lower() == 'http-stager' and \
                (('uri_x64' in configblock.keys() and malleable_meta['uri'] == configblock['uri_x64']) or
                    ('uri_x86' in configblock.keys() and malleable_meta['uri'] == configblock['uri_x86'])):
                if 'host_stage' in self.malleable.config.keys() and self.malleable.config['host_stage'] == 'false':
                    self.drop_reason('[DROP, {}, reason:11c, {}] Requested URI referes to http-stager section however Payload staging was disabled: "{}"'.format(ts, peerIP, req.uri))
                return True


            hdrs2 = {}
            for h in configblock['client']['header']:
                hdrs2[h[0].lower()] = h[1]

            for header in configblock['client']['header']:
                k, v = header

                if k.lower() not in rehdrskeys \
                    and self.proxyOptions['policy']['drop_malleable_without_expected_header']:

                    if 'protect_these_headers_from_tampering' in self.proxyOptions.keys() and \
                        len(self.proxyOptions['protect_these_headers_from_tampering']) > 0 and \
                        k.lower() in [x.lower() for x in self.proxyOptions['protect_these_headers_from_tampering']]:

                        self.logger.dbg('Inbound request did not contain expected by Malleable profile HTTP header named: {} . Restoring it to expected value as instructed by redirector config.'.format(
                            k
                        ))

                        req.headers[k] = hdrs2[k.lower()]
                    else:
                        self.drop_reason('[DROP, {}, reason:5, {}] HTTP request did not contain expected header: "{}"'.format(ts, peerIP, k))
                        return True

                if v not in req.headers.values() \
                    and self.proxyOptions['policy']['drop_malleable_without_expected_header_value']:
                    ret = False
                    if k.lower() == 'host' and 'host' in rehdrskeys and v.lower() in [x.lower() for x in req.headers.values()]:
                        ret = True
                        #del req.headers['Host']
                        #req.headers['Host'] = v
                        req.headers[proxy2_metadata_headers['override_host_header']] = v

                    if not ret:
                        if 'protect_these_headers_from_tampering' in self.proxyOptions.keys() and \
                            len(self.proxyOptions['protect_these_headers_from_tampering']) > 0 and \
                            k.lower() in [x.lower() for x in self.proxyOptions['protect_these_headers_from_tampering']]:

                            self.logger.dbg('Inbound request had HTTP Header ({})=({}) however ({}) was expected. Since this header was marked for protection - restoring expected value.'.format(
                                k, req.headers[k], hdrs2[k.lower()]
                            ))

                            del req.headers[k]
                            req.headers[k] = hdrs2[k.lower()]

                        else:
                            self.drop_reason('[DROP, {}, reason:6, {}] HTTP request did not contain expected header value: "{}: {}"'.format(ts, peerIP, k, v))
                            return True

            for _block in foundblocks:
                if _block in configblock['client'].keys():
                    metadata = configblock['client'][_block]
                    metadatacontainer = ''

                    if 'header' in metadata.keys():
                        if (metadata['header'].lower() not in rehdrskeys) \
                        and self.proxyOptions['policy']['drop_malleable_without_expected_request_section']:
                            self.drop_reason('[DROP, {}, reason:7, {}] HTTP request did not contain expected {} section header: "{}"'.format(ts, peerIP, _block, metadata['header']))
                            return True

                        if rehdrskeys.count(metadata['header'].lower()) == 1:
                            metadatacontainer = req.headers[metadata['header']]
                        else:
                            metadatacontainer = [v for k, v in req.headers.items() if k.lower() == metadata['header'].lower()]

                    elif 'parameter' in metadata.keys():
                        out = parse_qs(urlsplit(req.uri).query)

                        paramname = metadata['parameter']
                        if metadata['parameter'] not in out.keys() \
                        and self.proxyOptions['policy']['drop_malleable_without_request_section_in_uri']:
                            self.drop_reason('[DROP, {}, reason:8, {}] HTTP request was expected to contain {} section with parameter in URI: "{}"'.format(ts, peerIP, _block, metadata['parameter']))
                            return True

                        metadatacontainer = [metadata['parameter'], out[metadata['parameter']][0]]

                    elif 'uri-append' in metadata.keys():
                        if not self.proxyOptions['policy']['drop_malleable_with_invalid_uri_append']:
                            self.logger.dbg('Skipping uri-append validation according to drop_malleable_with_invalid_uri_append policy turned off.')
                            continue

                        metadatacontainer = req.uri

                    self.logger.dbg('Metadata container: {}'.format(metadatacontainer))

                    if 'prepend' in metadata.keys():
                        if type(metadata['prepend']) == list:
                            for p in metadata['prepend']:
                                if p not in metadatacontainer \
                                and self.proxyOptions['policy']['drop_malleable_without_prepend_pattern']:
                                    self.drop_reason('[DROP, {}, reason:9, {}] Did not found prepend pattern: "{}"'.format(ts, peerIP, p))
                                    if len(metadata['prepend']) > 1:
                                        self.logger.err('Caution: Your malleable profile defines multiple prepend patterns. This is known to cause connectivity issues between Teamserver and Beacon! Try to use only one prepend value.')
                                    return True

                        elif type(metadata['prepend']) == str:
                            if metadata['prepend'] not in metadatacontainer \
                                and self.proxyOptions['policy']['drop_malleable_without_prepend_pattern']:
                                self.drop_reason('[DROP, {}, reason:9, {}] Did not found prepend pattern: "{}"'.format(ts, peerIP, metadata['prepend']))
                                if len(metadata['prepend']) > 1:
                                        self.logger.err('Caution: Your malleable profile defines multiple prepend patterns. This is known to cause connectivity issues between Teamserver and Beacon! Try to use only one prepend value.')
                                return True

                    if 'append' in metadata.keys():
                        if type(metadata['append']) == list:
                            for p in metadata['append']:
                                if p not in metadatacontainer \
                                and self.proxyOptions['policy']['drop_malleable_without_apppend_pattern']:
                                    self.drop_reason('[DROP, {}, reason:10, {}] Did not found append pattern: "{}"'.format(ts, peerIP, p))
                                    if len(metadata['append']) > 1:
                                        self.logger.err('Caution: Your malleable profile defines multiple append patterns. This is known to cause connectivity issues between Teamserver and Beacon! Try to use only one append value.')
                                    return True

                        elif type(metadata['append']) == str:
                            if metadata['append'] not in metadatacontainer \
                                and self.proxyOptions['policy']['drop_malleable_without_apppend_pattern']:
                                self.drop_reason('[DROP, {}, reason:10, {}] Did not found append pattern: "{}"'.format(ts, peerIP, metadata['append']))
                                if len(metadata['append']) > 1:
                                    self.logger.err('Caution: Your malleable profile defines multiple append patterns. This is known to cause connectivity issues between Teamserver and Beacon! Try to use only one append value.')
                                return True

        else:
            self.logger.err('_client_request_inspect: No section ({}) or variant ({}) specified or ones provided are invalid!'.format(section, variant))
            return True

        self.logger.dbg('[{}: ALLOW] Peer\'s request is accepted'.format(peerIP), color='green')
        return False

    def checkIfHiddenAPICall(self, req, req_body):
        if 'malleable_redirector_hidden_api_endpoint' in self.proxyOptions.keys() and \
            len(self.proxyOptions['malleable_redirector_hidden_api_endpoint']):

            urlMatch = req.uri == self.proxyOptions['malleable_redirector_hidden_api_endpoint']
            methodMatch = req.method.lower() == 'post'

            if not urlMatch or not methodMatch:
                return (False, None)

            bodyJson = ''
            bodyValid = False
            try:
                bodyJson = json.loads(req_body)

                if not ('peerIP' in bodyJson.keys() and len(bodyJson['peerIP']) > 0):
                    if 'headers' in bodyJson.keys() and len(bodyJson['headers']) > 0:
                        ProxyPlugin.get_mock_req('0.0.0.0', req.method, req.uri, bodyJson['headers'])
                        bodyJson['peerIP'] = self.get_peer_ip(req)
                        bodyValid = True
                else:
                    bodyValid = True

            except Exception as e:
                self.logger.err(f"Given JSON in Hidden RedWarden API wasn't properly decoded. Corrupted structure? Error: ({e})")

            if urlMatch and methodMatch and bodyValid:
                return (True, bodyJson)

            else:
                self.logger.err("Request only resembled Hidden API call but didn't go through closer inspection ({}, {}, {})".format(
                    urlMatch, methodMatch, bodyValid
                ))

        return (False, None)

    def prepareResponseForHiddenAPICall(self, jsonParsed, req, req_body, res, res_body):
        out = ''
        respJson = {}

        if jsonParsed['peerIP'] == '0.0.0.0':
            respJson = {
                'error' : '1',
                'message': 'Could not extract peerIP from neither JSON nor HTTP headers!'
            }

            jsonParsed['peerIP'] = ''
            res.status = 404
            res.reason = 'Not Found'
        else:
            self.logger.dbg("Preparing hidden API response for peerIP: " + jsonParsed['peerIP'])
            ts = datetime.now().strftime('%Y-%m-%d/%H:%M:%S')
            (outstatus, outresult) = self.validatePeerAndHttpHeaders(
                jsonParsed['peerIP'], ts, req, req_body, res, res_body, jsonParsed
            )

            respJson = outresult
            res.status = 200
            res.reason = 'OK'

        res.response_version = 'HTTP/1.1'
        res.headers = {
            'Server' : 'nginx',
            'Cache-Control' : 'no-cache',
            'Content-Type':'application/json',
        }

        if 'ipgeo' not in respJson.keys(): 
            respJson['ipgeo'] = {}
        respJson['peerIP'] = jsonParsed['peerIP']
        out = json.dumps(respJson)

        self.logger.dbg(f"Returning response for a hidden API call:\n{out}")

        peerIP = req.client_address[0]

        self.logger.info(f"Served Hidden API call from ({peerIP}), asking for peerIP = {respJson['peerIP']}", color='green')

        return out.encode()
