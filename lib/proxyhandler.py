#!/usr/bin/python3
# -*- coding: utf-8 -*-
#

import time
import html
import sys, os
import brotli
import base64
import string
import http.client
import gzip, zlib
import json, re
import traceback
import requests
import urllib3
import socket, ssl, select
import threading

from datetime import datetime
from urllib.parse import urlparse, parse_qsl
from subprocess import Popen, PIPE
from io import StringIO, BytesIO
from html.parser import HTMLParser

import lib.optionsparser
from lib.proxylogger import ProxyLogger
from lib.pluginsloader import PluginsLoader
from lib.sslintercept import SSLInterception
from lib.utils import *

from http.server import BaseHTTPRequestHandler

from tornado.httpclient import AsyncHTTPClient
import tornado.web
import tornado.httpserver

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ssl._create_default_https_context = ssl._create_unverified_context

# Global instance that will be passed to every loaded plugin at it's __init__.
logger = None

# For holding loaded plugins' instances
pluginsloaded = None

# SSL Interception setup object
sslintercept = None

options = {}

class RemoveXProxy2HeadersTransform(tornado.web.OutputTransform):
    def transform_first_chunk(self, status_code, headers, chunk, finishing):
        xhdrs = [x.lower() for x in plugins.IProxyPlugin.proxy2_metadata_headers.values()]

        for k, v in headers.items():
            if k.lower() in xhdrs:
                headers.pop(k)
        
        return status_code, headers, chunk


class ProxyRequestHandler(tornado.web.RequestHandler):
    client = AsyncHTTPClient(max_buffer_size=1024*1024*150)

    SUPPORTED_METHODS = tornado.web.RequestHandler.SUPPORTED_METHODS + ('PROPFIND', 'CONNECT')
    SUPPORTED_ENCODINGS = ('gzip', 'x-gzip', 'identity', 'deflate', 'br')

    def __init__(self, *args, **kwargs):
        global pluginsloaded
        global logger

        self.options = options
        logger.options.update(options)

        self.plugins = pluginsloaded.get_plugins()
        self.server_address, self.all_server_addresses = ProxyRequestHandler.get_ip()

        for name, plugin in self.plugins.items():
            plugin.logger = logger

        super().__init__(*args, **kwargs)

    def initialize(self, server_bind, server_port):
        self.server_port = server_port
        self.server_bind = server_bind

    def set_default_headers(self):
        if 'Server' in self._headers.keys():
            self.set_header('Server', 'nginx')

    @staticmethod
    def get_ip():
        all_addresses = sorted([f[4][0] for f in socket.getaddrinfo(socket.gethostname(), None)] + ['127.0.0.1'])
        if '0.0.0.0' not in options['bind']:
            out = urlparse(options['bind'])
            if len(out.netloc) > 1: return out.netloc
            else:
                return (out.path.replace('/', ''), all_addresses)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # doesn't even have to be reachable
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except:
            IP = '127.0.0.1'
        finally:
            s.close()

        return (IP, all_addresses)

    def log_message(self, format, *args):
        if (self.options['verbose'] or \
            self.options['debug']) or (type(self.options['log']) == str and self.options['log'] != 'none'):

            txt = "%s - - [%s] %s\n" % \
                 (self.address_string(),
                  self.log_date_time_string(),
                  format%args)

            logger.out(txt, self.options['log'], '')

    def log_error(self, format, *args):
        # Surpress "Request timed out: timeout('timed out',)" if not in debug mode.
        if isinstance(args[0], socket.timeout) and not self.options['debug']:
            return

        if not options['debug']:
            return

        self.log_message(format, *args)

    def connectMethod(self):
        if options['no_proxy']: return
        logger.dbg(str(sslintercept))
        if sslintercept.status:
            self.connect_intercept()
        else:
            self.connect_relay()

    def compute_etag(self):
        return None

    @staticmethod
    def isValidRequest(req, req_body):
        def readable(x):
            return all(c in string.printable for c in x)

        try:
            if not readable(req.method): return False
            if not readable(req.uri): return False

            for k, v in req.headers.items():
                if not readable(k): return False
                if not readable(v): return False
        except:
            return False

        return True

    @staticmethod
    def generate_ssl_certificate(hostname):
        certpath = os.path.join(options['certdir'], hostname + '.crt')
        stdout = stderr = ''

        if not os.path.isfile(certpath):
            logger.dbg('Generating valid SSL certificate for ({})...'.format(hostname))
            epoch = "%d" % (time.time() * 1000)

            # Workaround for the Windows' RANDFILE bug
            if not 'RANDFILE' in os.environ.keys():
                os.environ["RANDFILE"] = os.path.normpath("%s/.rnd" % (options['certdir'].rstrip('/')))

            cmd = ["openssl", "req", "-new", "-key", options['certkey'], "-subj", "/CN=%s" % hostname]
            cmd2 = ["openssl", "x509", "-req", "-days", "3650", "-CA", options['cacert'], "-CAkey", options['cakey'], "-set_serial", epoch, "-out", certpath]

            try:
                p1 = Popen(cmd, stdout=PIPE, stderr=PIPE)
                p2 = Popen(cmd2, stdin=p1.stdout, stdout=PIPE, stderr=PIPE)
                (stdout, stderr) = p2.communicate()

            except FileNotFoundError as e:
                logger.err("Can't serve HTTPS traffic because there is no 'openssl' tool installed on the system!")
                return ''

        else:
            #logger.dbg('Using supplied SSL certificate: {}'.format(certpath))
            pass

        if not certpath or not os.path.isfile(certpath):
            if stdout or stderr:
                logger.err('Openssl x509 crt request failed:\n{}'.format((stdout + stderr).decode()))

            logger.fatal('Could not create interception Certificate: "{}"'.format(certpath))
            return ''

        return certpath

    def connect_intercept(self):
        hostname = self.request.uri.split(':')[0]
        certpath = ''

        logger.dbg('CONNECT intercepted: "%s"' % self.request.uri)

        certpath = ProxyRequestHandler.generate_ssl_certificate(hostname)
        if not certpath:
            self._set_status(500, 'Internal Server Error')

        self._set_status(200, 'Connection Established')

        try:
            self.request.connection.stream = tornado.iostream.IOStream(ssl.wrap_socket(
                self.request.connection.stream, 
                keyfile=self.options['certkey'], 
                certfile=certpath, 
                server_side=True
            ))
        except:
            logger.err('Connection reset by peer: "{}"'.format(self.request.uri))
            self._send_error(502)
            return

        conntype = self.request.headers.get('Proxy-Connection', '')
        if conntype.lower() == 'close':
            self.request.connection.no_keep_alive = True

        elif (conntype.lower() == 'keep-alive' and self.protocol_version >= "HTTP/1.1"):
            self.request.connection.no_keep_alive = False

    def connect_relay(self):
        address = self.request.uri.split(':', 1)
        address[1] = int(address[1]) or 443

        logger.dbg('CONNECT relaying: "%s"' % self.request.uri)

        try:
            s = socket.create_connection(address, timeout=self.options['timeout'])
        except Exception as e:
            logger.err("Could not relay connection: ({})".format(str(e)))
            self._send_error(502)
            return

        self._set_status(200, 'Connection Established')

        conns = [self.request.connection.stream, s]
        self.request.connection.no_keep_alive = False

        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.options['timeout'])
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.request.connection.no_keep_alive = True
                    break
                other.sendall(data)

    def reverse_proxy_loop_detected(self, command, fetchurl, req_body):
        logger.err('[Reverse-proxy loop detected from peer {}] {} {}'.format(
            self.client_address[0], command, fetchurl
        ))

        self._send_error(500)
        return

    def my_handle_request(self, *args, **kwargs):
        # http://httpd.apache.org/docs/current/logs.html#combined
        # [day/month/year:hour:minute:second zone]
        # day = 2*digit
        # month = 3*letter
        # year = 4*digit
        # hour = 2*digit
        # minute = 2*digit
        # second = 2*digit
        # zone = (`+' | `-') 4*digit
        timestamp = datetime.utcnow()

        if hasattr(self, 'request') and hasattr(self.request, 'uri') and type(self.request.uri) == str:
            if self.request.uri.startswith('//'):
                self.request.uri = self.request.uri[1:]

        self._internal_my_handle_request(*args, **kwargs)

        remote_host = self.request.client_address
        if (type(self.request.client_address) == list or type(self.request.client_address) == tuple) and len(self.request.client_address) > 0:
            remote_host = self.request.client_address[0]

        user_identity = '-'
        http_basic_auth = '-'

        if len(self.request.headers.get('Authorization', '')) > 0:
            auth = self.request.headers.get('Authorization', '').strip()
            if auth.lower().startswith('basic '):
                try:
                    auth_decoded = base64.b64decode(auth[len('Basic '):])
                    if ':' in auth_decoded:
                        http_basic_auth = auth_decoded.split(':')[0]
                except:
                    pass

        timezone = '+0000'
        month = timestamp.strftime('%b')
        request_timestamp = f'[{timestamp.day:02}/{month}/{timestamp.year:04}:{timestamp.hour:02}:{timestamp.minute:02}:{timestamp.second:02} {timezone}]'
        request_line = f'{self.request.method} {self.request.uri} {self.request_version}'
        http_referer = '-'
        http_useragent = '-'

        if len(self.request.headers.get('Referer', '')) > 0:
            http_referer = self.request.headers.get('Referer', '')

        if len(self.request.headers.get('User-Agent', '')) > 0:
            http_useragent = self.request.headers.get('User-Agent', '')

        line = f'{remote_host} {user_identity} {http_basic_auth} {request_timestamp} "{request_line}" {self.response_status} {self.response_length} "{http_referer}" "{http_useragent}"'

        if 'access_log' in self.options.keys() and self.options['access_log'] != None and len(self.options['access_log']) > 0:
            with open(self.options['access_log'], 'a') as f:
                f.write(line + '\n')

        print(line)

    def _internal_my_handle_request(self, *args, **kwargs):
        handler = self._my_handle_request
        if self.request.method.lower() == 'connect':
            handler = self.connectMethod
        
        self.headers = self.request.headers.copy()
        self.request.headers = self.headers
        self.request.method = self.request.method
        self.request.client_address = [self.request.remote_ip,]
        self.request.connection.no_keep_alive = False
        self.request_version = 'HTTP/1.1'
        self.request.server_port = self.server_port
        self.request.server_bind = self.server_bind

        self.response_status = 0
        self.response_reason = ''
        self.response_headers = {}
        self.response_length = 0

        if self.request.uri.startswith('http://') or self.request.uri.startswith('https://'):
            newpath = ''
            parsed = urlparse(self.request.uri)
            if len(parsed.path) > 0:
                newpath += parsed.path
            if len(parsed.query) > 0:
                newpath += '?' + parsed.query
            if len(parsed.fragment) > 0:
                newpath += '#' + parsed.fragment

            self.request.uri = newpath

        output = handler()

        self.request.method = self.request.method
        self.request.host = self.request.headers['Host']

    def _send_error(self, code, msg = ''):
        self.response_status = code
        self.response_reason = ''
        if len(msg) > 0:
            self.response_reason = msg
        else:
            try:
                self.response_reason = requests.status_codes._codes[code][0]
            except: 
                pass

        self.send_error(code)

    def _set_status(self, code, msg = ''):
        self.response_status = code
        self.response_reason = ''
        if len(msg) > 0:
            self.response_reason = msg
        else:
            try:
                self.response_reason = requests.status_codes._codes[code][0]
            except: 
                pass
        
        self.set_status(code, self.response_reason)

    def on_finish(self):
        if self.request.connection.no_keep_alive:
            logger.dbg("Closing connection with peer due to no_keep_alive.")
            self.request.connection.stream.close()

    def _my_handle_request(self):
        if self.request.uri == self.options['proxy_self_url']:
            logger.dbg('Sending CA certificate.')
            self.send_cacert()
            return

        self.is_ssl = isinstance(self.request.connection.stream, tornado.iostream.SSLIOStream)
        self.request.is_ssl = self.is_ssl

        content_length = int(self.request.headers.get('Content-Length', 0))
        if not self.options['allow_invalid']:
            if not ProxyRequestHandler.isValidRequest(self.request, self.request.body):
                self.logger.dbg('[DROP] Invalid HTTP request from: {}'.format(self.client_address[0]))
                return

        req_body_modified = ""
        dont_fetch_response = False
        res = None
        res_body_plain = None
        content_encoding = 'identity'
        inbound_origin = self.request.host
        outbound_origin = inbound_origin
        origuri = self.request.uri
        newuri = self.request.uri
        originChanged = False
        ignore_response_decompression_errors = False
        if 'Host' not in self.request.headers.keys():
            self.request.headers['Host'] = self.request.host

        logger.info('[REQUEST] {} {}'.format(self.request.method, self.request.uri), color=ProxyLogger.colors_map['green'])
        self.save_handler(self.request, self.request.body, None, None)

        try:
            (modified, req_body_modified) = self.request_handler(self.request, self.request.body)
            newuri = self.request.uri

            if modified != None and type(modified) == bool:
                modified |= (origuri != newuri)

            if 'DropConnectionException' in str(type(req_body_modified)) or \
                'DontFetchResponseException' in str(type(req_body_modified)):
                raise req_body_modified

            elif modified and req_body_modified is not None:
                self.request.body = req_body_modified
                if self.request.body != None: 
                    reqhdrs = [x.lower() for x in self.request.headers.keys()]
                    if 'content-length' in reqhdrs: del self.request.headers['Content-Length']
                    self.request.headers['Content-length'] = str(len(self.request.body))

            parsed = urlparse(newuri)
            if parsed.netloc != inbound_origin and parsed.netloc != None and len(parsed.netloc) > 1:
                logger.info('Plugin redirected request from [{}] to [{}]'.format(inbound_origin, parsed.netloc))
                outbound_origin = parsed.netloc
                originChanged = True
                #newuri = (parsed.path + '?' + parsed.query if parsed.query else parsed.path)

        except Exception as e:
            if 'DropConnectionException' in str(e):
                logger.err("Plugin demanded to drop the request: ({})".format(str(e)))
                self.request.connection.no_keep_alive = True
                return

            elif 'DontFetchResponseException' in str(e):
                dont_fetch_response = True
                self.request.connection.no_keep_alive = True
                res_body_plain = 'DontFetchResponseException'
                class Response(object):
                    pass
                res = Response()

            else:
                logger.err('Exception catched in request_handler: {}'.format(str(e)))
                if options['debug']: 
                    raise

        req_path_full = ''
        if not newuri: newuri = '/'
        if newuri[0] == '/':
            if self.is_ssl:
                req_path_full = "https://%s%s" % (self.request.headers['Host'], newuri)
            else:
                req_path_full = "http://%s%s" % (self.request.headers['Host'], newuri)

        elif newuri.startswith('http://') or newuri.startswith('https://'):
            logger.dbg(f"Plugin redirected request to a full URL: ({newuri})")
            req_path_full = newuri
            parsed = urlparse(req_path_full)
            newpath = ''
            if len(parsed.path) > 0:
                newpath = parsed.path
            else:
                newpath = '/'

            if len(parsed.query) > 0:
                newpath += '?' + parsed.query
            
            if len(parsed.fragment) > 0:
                newpath += '#' + parsed.fragment

            req_path_full = parsed.scheme + '://' + parsed.netloc + newpath

        if not req_path_full: 
            req_path_full = newuri

        u = urlparse(req_path_full)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        
        if netloc == '':
            netloc = inbound_origin

        origin = (scheme, inbound_origin)
        neworigin = (scheme, netloc)

        class MyResponse(http.client.HTTPResponse):
            def __init__(self, req, origreq):
                self.headers = {}
                self.msg = self.headers
                self.response_version = origreq.protocol_version

                if req != None:
                    self.status = req.status_code
                    self.headers = req.headers.copy()
                    self.reason = req.reason
                else:
                    self.status = origreq.status
                    self.reason = origreq.reason
                    self.reason = origreq.headers.copy()

        if not dont_fetch_response:
            try:
                assert scheme in ('http', 'https')

                fetchurl = req_path_full.replace(netloc, outbound_origin)

                ip = ''
                try:
                    #ip = socket.gethostbyname(urlparse(fetchurl).netloc)
                    ip = socket.gethostbyname(outbound_origin)

                except:
                    ip = urlparse(fetchurl).netloc
                    if not ip:
                        ip = outbound_origin

                if ':' in ip:
                    ip = ip.split(':')[0]

                if plugins.IProxyPlugin.proxy2_metadata_headers['ignore_response_decompression_errors'] in self.request.headers.keys():
                    ignore_response_decompression_errors = True

                #if (ip == self.server_address or ip in self.all_server_addresses) or \
                if (outbound_origin != '' and outbound_origin == inbound_origin) and \
                    (ip == self.server_address or ip in self.all_server_addresses):
                    logger.dbg(f'About to catch reverse-proxy loop detection: outbound_origin: {outbound_origin}, ip: {ip}, server_address: {self.server_address}')
                    return self.reverse_proxy_loop_detected(self.request.method, fetchurl, self.request.body)

                reqhdrskeys = [x.lower() for x in self.request.headers.keys()]
                if plugins.IProxyPlugin.proxy2_metadata_headers['override_host_header'].lower() in reqhdrskeys:
                    if 'Host' not in self.request.headers.keys():
                        self.request.headers['Host'] = self.request.host
                        self.set_header('Host', self.request.host)

                    o = self.request.headers['Host']
                    n = self.request.headers[plugins.IProxyPlugin.proxy2_metadata_headers['override_host_header']]
                    logger.dbg(f'Plugin overidden host header: [{o}] => [{n}]')
                    fetchurl = fetchurl.replace(o, n)

                    while 'Host' in self.request.headers.keys():
                        del self.request.headers['Host']

                    self.request.headers['Host'] = n
                
                #ProxyRequestHandler.filter_headers(self.request.headers)
                req_body = ''
                if self.request.body == None: req_body = ''
                else: 
                    try:
                        if type(self.request.body) == bytes:
                            req_body = self.request.body
                        else:
                            req_body = self.request.body.encode()

                    except UnicodeDecodeError:
                        pass
                    except AttributeError: 
                        pass

                new_req_headers = self.request.headers.copy()
                #del new_req_headers['Host']

                if plugins.IProxyPlugin.proxy2_metadata_headers['domain_front_host_header'] in new_req_headers.keys():
                    if 'Host' in new_req_headers.keys():
                        del new_req_headers['Host']

                    logger.dbg('Adjusting Host header for Domain-Fronting needs as requested by Plugin')
                    new_req_headers['Host'] = self.request.headers[plugins.IProxyPlugin.proxy2_metadata_headers['domain_front_host_header']]

                fetchurl = req_path_full.replace(netloc, outbound_origin)
                logger.dbg('DEBUG REQUESTS: request("{}", "{}", "{}", ...'.format(
                    self.request.method, fetchurl, req_body.decode(errors='ignore')[:30].strip()
                ))

                myreq = None
                try:
                    myreq = requests.request(
                        method = self.request.method, 
                        url = fetchurl, 
                        data = req_body,
                        headers = new_req_headers,
                        timeout = self.options['timeout'],
                        allow_redirects = False,
                        stream = ignore_response_decompression_errors,
                        verify = False
                    )

                except Exception as e:
                    logger.err(f'COULD NOT FETCH RESPONSE FROM REMOTE AGENT: {e}')
                    
                    if self.options['debug']:
                        raise

                res = MyResponse(myreq, self)
                self.response_headers = res.headers

                res_body = ""
                if ignore_response_decompression_errors:
                    res_body = myreq.raw.read()
                else:
                    res_body = myreq.content

                logger.dbg("Response from reverse-proxy fetch came at {} bytes.".format(len(res_body)))

                if 'Content-Length' not in res.headers.keys() and len(res_body) != 0:
                    res.headers['Content-Length'] = str(len(res_body))
                    self.response_length = len(res_body)

                myreq.close()

                if type(res_body) == str: res_body = str.encode(res_body)

            except requests.exceptions.ConnectionError as e:
                logger.err("Exception occured while reverse-proxy fetching resource : URL({}).\nException: ({})".format(
                    fetchurl, str(e)
                ))
   
                self.request.connection.no_keep_alive = True

                if res == None:
                    res = MyResponse(None, self)

                self.response_headers = res.headers
                self._send_error(502)
                #if options['debug']: raise
                return

            except Exception as e:
                logger.err("Could not proxy request: ({})".format(str(e)))
                if 'RemoteDisconnected' in str(e) or 'Read timed out' in str(e):
                    return

                if res == None:
                    res = MyResponse(None, self)

                self.request.connection.no_keep_alive = True
                self.response_headers = res.headers
                self._send_error(502)
                if options['debug']: raise
                return

            setattr(res, 'headers', res.msg)
            self.response_headers = res.msg

            content_encoding = res.headers.get('Content-Encoding', 'identity')
            if ignore_response_decompression_errors: 
                content_encoding = 'identity'

            res_body_plain = self.decode_content_body(res_body, content_encoding)

        else:
            logger.dbg("Response deliberately not fetched as for plugin's request.")

        self.request.uri = origuri

        (modified, res_body_modified) = self.response_handler(
            self.request, self.request.body, res, res_body_plain
        )

        newuri = self.request.uri
        self.request.uri = origuri

        if type(modified) == bool:
            modified |= (newuri != origuri)

        if modified: 
            logger.dbg('Plugin has modified the response body. Using it instead')
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)

            reshdrs = [x.lower() for x in res.headers.keys()]
            if 'content-length' in reshdrs: del res.headers['Content-Length']

            try:
                res.headers['Content-Length'] = str(len(res_body))
                self.response_length = len(res_body)
            except Exception as e:
                logger.dbg("Could not set proper Content-Length as running len on res_body failed")

        if 'Transfer-Encoding' in res.headers.keys() and \
            res.headers['Transfer-Encoding'] == 'chunked':
            del res.headers['Transfer-Encoding']

        if (not ignore_response_decompression_errors) and ('Accept-Encoding' in self.request.headers.keys()):
            encToUse = self.request.headers['Accept-Encoding'].split(' ')[0].replace(',','')

            override_resp_enc = plugins.IProxyPlugin.proxy2_metadata_headers['override_response_content_encoding'] 

            if override_resp_enc in res.headers.keys():
                logger.dbg('Plugin asked to override response content encoding without changing header\'s value.')
                logger.dbg('Yielding content in {} whereas header pointing at: {}'.format(
                   res.headers[override_resp_enc], self.request.headers['Accept-Encoding']))
                enc = res.headers[override_resp_enc]
                del res.headers[override_resp_enc]

            else:
                encs = [x.strip() for x in self.request.headers['Accept-Encoding'].split(',')]
                if content_encoding not in encs:
                    reencoded = False
                    for enc in encs:
                        if enc in ProxyRequestHandler.SUPPORTED_ENCODINGS:
                            encToUse = encs[0]
                            reencoded = True
                            break
                    if not reencoded:
                        logger.err("Server returned response encoded in {} but client expected one of: {} - we couldn't handle any of these. The client will receive INCORRECTLY formatted response!".format(
                                res.headers.get('Content-Encoding', 'identity'),
                                ','.join(encs)
                            ))

            logger.dbg('Encoding response body to: {}'.format(encToUse))
            res_body = self.encode_content_body(res_body, encToUse)
            reskeys = [x.lower() for x in res.headers.keys()]
            if 'content-length' in reskeys: del res.headers['Content-Length']
            if 'content-encoding' in reskeys: del res.headers['Content-Encoding']
            res.headers['Content-Length'] = str(len(res_body))
            self.response_length = len(res_body)
            res.headers['Content-Encoding'] = encToUse

        if 'DropConnectionException' in str(res_body) or 'DontFetchResponseException' in str(res_body):
            res_body = ''

        if type(res_body) == str: res_body = str.encode(res_body)

        #ProxyRequestHandler.filter_headers(res.headers)
        res_headers = res.headers
        self.response_status = res.status
        self.response_reason = res.reason
        self.response_headers = res.headers

        ka = 'no' if self.request.connection.no_keep_alive else 'yes'
        
        if plugins.IProxyPlugin.proxy2_metadata_headers['keep_alive_this_connection'] in res.headers.keys():
            self.request.connection.no_keep_alive = False
            ka = 'yes'

        logger.info('[RESPONSE] HTTP {} {}, length: {}, keep-alive: {}'.format(res.status, res.reason, len(res_body), ka), color=ProxyLogger.colors_map['yellow'])

        self._set_status(res.status, res.reason)

        for k, v in res_headers.items():
            if k in plugins.IProxyPlugin.proxy2_metadata_headers.values(): continue

            self.set_header(k, v)

        try:
            self.response_length = len(res_body)
            self.write(res_body)

            if options['debug']:
                if originChanged:
                    del self.request.headers['Host']
                    if plugins.IProxyPlugin.proxy2_metadata_headers['override_host_header'] in self.request.headers.keys():
                        outbound_origin = self.request.headers[plugins.IProxyPlugin.proxy2_metadata_headers['override_host_header']]

                    self.request.headers['Host'] = outbound_origin
                self.save_handler(self.request, self.request.body, res, res_body_plain)

        except BrokenPipeError as e:
            logger.err("Broken pipe. Client must have disconnected/timed-out.")

    @staticmethod
    def filter_headers(headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = (
            'connection', 
            'keep-alive', 
            'proxy-authenticate', 
            'proxy-authorization', 
            'te', 
            'trailers', 
            'transfer-encoding', 
            'upgrade'
        )
        for k in hop_by_hop:
            if k in headers.keys():
                del headers[k]
        return headers

    def encode_content_body(self, text, encoding):
        logger.dbg('Encoding content to {}'.format(encoding))
        data = text
        if encoding == 'identity':
            pass
        elif encoding in ('gzip', 'x-gzip'):
            _io = BytesIO()
            with gzip.GzipFile(fileobj=_io, mode='wb') as f:
                f.write(text)
            data = _io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        elif encoding == 'br':
            # Brotli algorithm
            try:
                data = brotli.compress(text)
            except Exception as e:
                #raise Exception('Could not compress Brotli stream: "{}"'.format(str(e)))
                logger.err('Could not compress Brotli stream: "{}"'.format(str(e)))
        else:
            #raise Exception("Unknown Content-Encoding: %s" % encoding)
            logger.err('Unknown Content-Encoding: "{}"'.format(encoding))
        return data

    def decode_content_body(self, data, encoding):
        logger.dbg('Decoding content from {}'.format(encoding))
        text = data
        if encoding == 'identity':
            pass
        elif encoding in ('gzip', 'x-gzip'):
            try:
                _io = BytesIO(data)
                with gzip.GzipFile(fileobj=_io) as f:
                    text = f.read()
            except:
                return data
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        elif encoding == 'br':
            # Brotli algorithm
            try:
                text = brotli.decompress(data)
            except Exception as e:
                #raise Exception('Could not decompress Brotli stream: "{}"'.format(str(e)))
                logger.err('Could not decompress Brotli stream: "{}"'.format(str(e)))
        else:
            #raise Exception("Unknown Content-Encoding: %s" % encoding)
            logger.err('Unknown Content-Encoding: "{}"'.format(encoding))
        return text

    def send_cacert(self):
        with open(self.options['cacert'], 'rb') as f:
            data = f.read()

        self._set_status(200)
        self.set_header('Content-Type', 'application/x-x509-ca-cert')
        self.set_header('Content-Length', len(data))
        self.set_header('Connection', 'close')

        self.response_length = len(data)
        self.write(data)

    def print_info(self, req, req_body, res, res_body):
        def _parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in parse_qsl(s, keep_blank_values=True))

        if not options['debug']:
            return

        req_header_text = "%s %s %s\n%s" % (req.method, req.uri, self.request_version, req.headers)

        if res is not None:
            reshdrs = res.headers

            if type(reshdrs) == dict or 'CaseInsensitiveDict' in str(type(reshdrs)):
                reshdrs = ''
                for k, v in res.headers.items():
                    if k in plugins.IProxyPlugin.proxy2_metadata_headers.values(): continue
                    if k.lower().startswith('x-proxy2-'): continue
                    reshdrs += '{}: {}\n'.format(k, v)

            res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, reshdrs)

        logger.trace("==== REQUEST ====\n%s" % req_header_text, color=ProxyLogger.colors_map['yellow'])

        u = urlparse(req.uri)
        if u.query:
            query_text = _parse_qsl(u.query)
            logger.trace("==== QUERY PARAMETERS ====\n%s\n" % query_text, color=ProxyLogger.colors_map['green'])

        cookie = req.headers.get('Cookie', '')
        if cookie:
            cookie = _parse_qsl(re.sub(r';\s*', '&', cookie))
            logger.trace("==== COOKIES ====\n%s\n" % cookie, color=ProxyLogger.colors_map['green'])

        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].decode('base64')
            logger.trace("==== BASIC AUTH ====\n%s\n" % token, color=ProxyLogger.colors_map['red'])

        if req_body is not None:
            req_body_text = None
            content_type = req.headers.get('Content-Type', '')

            if content_type.startswith('application/x-www-form-urlencoded'):
                req_body_text = _parse_qsl(req_body)
            elif content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(req_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        req_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        req_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    req_body_text = req_body
            elif len(req_body) < 1024:
                req_body_text = req_body

            if req_body_text:
                logger.trace("==== REQUEST BODY ====\n%s\n" % req_body_text.strip(), color=ProxyLogger.colors_map['white'])

        if res is not None:
            logger.trace("\n==== RESPONSE ====\n%s" % res_header_text, color=ProxyLogger.colors_map['cyan'])

            cookies = res.headers.get('Set-Cookie')
            if cookies:
                if type(cookies) == list or type(cookies) == tuple:
                    cookies = '\n'.join(cookies)

                logger.trace("==== SET-COOKIE ====\n%s\n" % cookies, color=ProxyLogger.colors_map['yellow'])

        if res_body is not None:
            res_body_text = res_body
            content_type = res.headers.get('Content-Type', '')

            if content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(res_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        res_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        res_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    res_body_text = res_body
            elif content_type.startswith('text/html'):
                if type(res_body) == str: res_body = str.encode(res_body)
                m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', res_body.decode(errors='ignore'), re.I)
                if m:
                    logger.trace("==== HTML TITLE ====\n%s\n" % html.unescape(m.group(1)), color=ProxyLogger.colors_map['cyan'])
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body

            if res_body_text:
                res_body_text2 = ''
                maxchars = 4096
                halfmax = int(maxchars/2)
                try:
                    if type(res_body_text) == bytes:
                        dec = res_body_text.decode()
                    else:
                        dec = res_body_text

                    if dec != None and len(dec) > maxchars:
                        res_body_text2 = dec[:halfmax] + ' <<< ... >>> ' + dec[-halfmax:]
                    else:
                        res_body_text2 = dec

                except UnicodeDecodeError:
                    if len(res_body_text) > maxchars:
                        res_body_text2 = hexdump(list(res_body_text[:halfmax]))
                        res_body_text2 += '\n\t................\n'
                        res_body_text2 += hexdump(list(res_body_text[-halfmax:]))
                    else:
                        res_body_text2 = hexdump(list(res_body_text))

                logger.trace("==== RESPONSE BODY ====\n%s\n" % res_body_text2, color=ProxyLogger.colors_map['green'])

    def request_handler(self, req, req_body):
        altered = False
        req_body_current = req_body

        for plugin_name in self.plugins:
            instance = self.plugins[plugin_name]
            try:
                handler = getattr(instance, 'request_handler')
                #logger.dbg("Calling `request_handler' from plugin %s" % plugin_name)
                origheaders = dict(req.headers).copy()

                req_body_current = handler(req, req_body_current)

                altered = (req_body != req_body_current and req_body_current is not None)
                if req_body_current == None: req_body_current = req_body
                for k, v in origheaders.items():
                    if k not in req.headers.keys(): 
                        altered = True

                    elif origheaders[k] != req.headers[k]:
                        #logger.dbg('Plugin modified request header: "{}", from: "{}" to: "{}"'.format(
                        #    k, origheaders[k], req.headers[k]))
                        altered = True

            except AttributeError as e:
                if 'object has no attribute' in str(e):
                    logger.dbg('Plugin "{}" does not implement `request_handler\''.format(plugin_name))
                    if options['debug']:
                        raise
                else:
                    logger.err("Plugin {} has thrown an exception: '{}'".format(plugin_name, str(e)))
                    if options['debug']:
                        raise

        return (altered, req_body_current)

    def response_handler(self, req, req_body, res, res_body):
        res_body_current = res_body
        altered = False

        for plugin_name in self.plugins:
            instance = self.plugins[plugin_name]
            try:
                handler = getattr(instance, 'response_handler')
                #logger.dbg("Calling `response_handler' from plugin %s" % plugin_name)
                origheaders = {}
                try:
                    origheaders = res.headers.copy()
                except: pass

                res_body_current = handler(req, req_body, res, res_body_current)
                
                altered = (res_body_current != res_body)
                for k, v in origheaders.items():
                    if origheaders[k] != res.headers[k]:
                        #logger.dbg('Plugin modified response header: "{}", from: "{}" to: "{}"'.format(
                        #    k, origheaders[k], res.headers[k]))
                        altered = True

                if len(origheaders.keys()) != len(res.headers.keys()):
                    #logger.dbg('Plugin modified response headers.')
                    altered = True

                if altered:
                    logger.dbg('Plugin has altered the response.')
            except AttributeError as e:
                raise
                if 'object has no attribute' in str(e):
                    logger.dbg('Plugin "{}" does not implement `response_handler\''.format(plugin_name))
                else:
                    logger.err("Plugin {} has thrown an exception: '{}'".format(plugin_name, str(e)))
                    if options['debug']:
                        raise

        if not altered:
            return (False, res_body)

        return (True, res_body_current)

    def save_handler(self, req, req_body, res, res_body):
        self.print_info(req, req_body, res, res_body)

    async def get(self, *args, **kwargs):
        self.my_handle_request()

    async def post(self, *args, **kwargs):
        self.my_handle_request()

    async def head(self, *args, **kwargs):
        self.my_handle_request()

    async def options(self, *args, **kwargs):
        self.my_handle_request()

    async def put(self, *args, **kwargs):
        self.my_handle_request()

    async def delete(self, *args, **kwargs):
        self.my_handle_request()

    async def patch(self, *args, **kwargs):
        self.my_handle_request()

    async def propfind(self, *args, **kwargs):
        self.my_handle_request()

    async def connect(self, *args, **kwargs):
        self.my_handle_request()


def init(opts, VERSION):
    global options
    global pluginsloaded
    global logger
    global sslintercept

    options = opts.copy()

    lib.optionsparser.parse_options(options, VERSION)
    logger = ProxyLogger(options)
    pluginsloaded = PluginsLoader(logger, options)
    sslintercept = SSLInterception(logger, options)

    if options['log'] and options['log'] != None and options['log'] != sys.stdout:
        if options['tee']:
            logger.info("Teeing stdout output to {} log file.".format(options['log']))
        else:
            logger.info("Writing output to {} log file.".format(options['log']))

    monkeypatching(logger)

    for name, plugin in pluginsloaded.get_plugins().items():
        plugin.logger = logger
        plugin.help(None)

    return (options, logger)

def cleanup():
    global options

    # Close logging file descriptor unless it's stdout
    #if options['log'] and options['log'] not in (sys.stdout, 'none'):
    #    options['log'].close()
    #    options['log'] = None
    
    if sslintercept:
        sslintercept.cleanup()
