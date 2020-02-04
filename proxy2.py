#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Proxy2
#
# TODO:
#   - implement dynamic plugins directory scanning method in the PluginsLoader
#   - perform severe code refactoring as for now it's kinda ugly
#   - add more advanced logging capabilities, redesign packets contents dumping
#
# Changelog:
#   0.1     original fork from inaz2 repository.
#   0.2     added plugins loading functionality, 
#           ssl interception as a just-in-time setup,
#           more elastic logging facilities, 
#           separation of program options in form of a globally accessible dictonary, 
#           program's help text with input parameters handling,
#   0.3     added python3 support, enhanced https capabilities and added more versatile
#           plugins support.
#   0.4     improved reverse-proxy's capabilities, added logic to avoid inifinite loops
#
# Author:
#   Mariusz B. / mgeeky, '16-'20
#   <mb@binary-offensive.com>
#
#   (originally based on: @inaz2 implementation: https://github.com/futuresimple/proxy2)
#   (now obsoleted)
#

VERSION = '0.4'

import time
import html
import sys, os
import brotli
import socket, ssl, select
import http.client
import threading
import gzip, zlib
import json, re
import optionsparser
import traceback
import threading
import requests
import urllib3
from urllib.parse import urlparse, parse_qsl
from subprocess import Popen, PIPE
from proxylogger import ProxyLogger
from pluginsloader import PluginsLoader
from sslintercept import SSLInterception
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import plugins.IProxyPlugin
from io import StringIO, BytesIO
from html.parser import HTMLParser

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ssl._create_default_https_context = ssl._create_unverified_context

normpath = lambda p: os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), p))

# Global options dictonary, that will get modified after parsing 
# program arguments. Below state represents default values.
options = {
    'hostname': 'http://0.0.0.0',
    'port': [8080, ],
    'debug': False,                  # Print's out debuging informations
    'verbose': True,
    'trace': False,                  # Displays packets contents
    'log': None,
    'proxy_self_url': 'http://proxy2.test/',
    'timeout': 5,
    'no_ssl': False,
    'no_proxy': False,
    'cakey':  normpath('ca-cert/ca.key'),
    'cacert': normpath('ca-cert/ca.crt'),
    'certkey': normpath('ca-cert/cert.key'),
    'certdir': normpath('certs/'),
    'cacn': 'proxy2 CA',
    'plugins': set(),
    'plugin_class_name': 'ProxyPlugin',
}

# Global instance that will be passed to every loaded plugin at it's __init__.
logger = None

# For holding loaded plugins' instances
pluginsloaded = None

# SSL Interception setup object
sslintercept = None

# Asynchronously serving HTTP server class.
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET

    # ThreadMixIn, Should the server wait for thread termination?
    # If True, python will exist despite running server threads.
    daemon_threads = True

    def handle_error(self, request, client_address):
        # surpress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        global pluginsloaded

        self.tls = threading.local()
        self.tls.conns = {}
        self.options = options
        self.plugins = pluginsloaded.get_plugins()
        self.server_address, self.all_server_addresses = ProxyRequestHandler.get_ip()

        for name, plugin in self.plugins.items():
            plugin.logger = logger

        try:
            BaseHTTPRequestHandler.__init__(self, *args, **kwargs)
        except Exception as e:
            if 'Connection reset by peer' in str(e):
                logger.dbg('Connection reset by peer.')
            else:
                logger.dbg('Failure along __init__ of BaseHTTPRequestHandler: {}'.format(str(e)))
                if options['debug']:
                    raise

    @staticmethod
    def get_ip():
        all_addresses = sorted([f[4][0] for f in socket.getaddrinfo(socket.gethostname(), None)] + ['127.0.0.1'])
        if '0.0.0.0' not in options['hostname']:
            out = urlparse(options['hostname'])
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


    def version_string(self):
        return 'nginx'

    def log_message(self, format, *args):
        if (self.options['verbose'] or \
            self.options['debug'] or self.options['trace']) or \
            (type(self.options['log']) == str and self.options['log'] != 'none'):

            txt = "%s - - [%s] %s\n" % \
                 (self.address_string(),
                  self.log_date_time_string(),
                  format%args)

            logger.out(txt, self.options['log'], '')

    def log_error(self, format, *args):
        # Surpress "Request timed out: timeout('timed out',)" if not in debug mode.
        if isinstance(args[0], socket.timeout) and not self.options['debug']:
            return

        if not options['trace'] or not options['debug']:
            return

        self.log_message(format, *args)

    def _handle_request(self):
        return self.overloaded_do_GET()

    def do_CONNECT(self):
        if options['no_proxy']: return
        logger.dbg(str(sslintercept))
        if sslintercept.status:
            self.connect_intercept()
        else:
            self.connect_relay()

    @staticmethod
    def generate_ssl_certificate(hostname):
        certpath = os.path.normpath("%s/%s.crt" % (options['certdir'].rstrip('/'), hostname))
        stdout = stderr = ''

        if not os.path.isfile(certpath):
            logger.dbg('Generating valid SSL certificate...')
            epoch = "%d" % (time.time() * 1000)

            # Workaround for the Windows' RANDFILE bug
            if not 'RANDFILE' in os.environ.keys():
                os.environ["RANDFILE"] = os.path.normpath("%s/.rnd" % (options['certdir'].rstrip('/')))

            cmd = ["openssl", "req", "-new", "-key", options['certkey'], "-subj", "/CN=%s" % hostname]
            cmd2 = ["openssl", "x509", "-req", "-days", "3650", "-CA", options['cacert'], "-CAkey", options['cakey'], "-set_serial", epoch, "-out", certpath]

            p1 = Popen(cmd, stdout=PIPE, stderr=PIPE)
            p2 = Popen(cmd2, stdin=p1.stdout, stdout=PIPE, stderr=PIPE)
            (stdout, stderr) = p2.communicate()

        else:
            logger.dbg('Using supplied SSL certificate: {}'.format(certpath))

        if not certpath or not os.path.isfile(certpath):
            if stdout or stderr:
                logger.err('Openssl x509 crt request failed:\n{}'.format((stdout + stderr).decode()))
            logger.fatal('Could not create interception Certificate: "{}"'.format(certpath))
            return ''

        return certpath

    def connect_intercept(self):
        hostname = self.path.split(':')[0]

        logger.dbg('CONNECT intercepted: "%s"' % self.path)

        with self.lock:
            certpath = ProxyRequestHandler.generate_ssl_certificate(hostname)
            if not certpath:
                self.send_response(500, 'Internal Server Error')
                self.end_headers()

        self.send_response(200, 'Connection Established')
        self.end_headers()

        self.connection = ssl.wrap_socket(self.connection, keyfile=self.options['certkey'], certfile=certpath, server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get('Proxy-Connection', '')
        if conntype.lower() == 'close':
            self.close_connection = 1
        elif (conntype.lower() == 'keep-alive' and self.protocol_version >= "HTTP/1.1"):
            self.close_connection = 0

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443

        logger.dbg('CONNECT relaying: "%s"' % self.path)

        try:
            s = socket.create_connection(address, timeout=self.options['timeout'])
        except Exception as e:
            logger.err("Could not relay connection: ({})".format(str(e)))
            self.send_error(502)
            return

        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0

        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.options['timeout'])
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    def reverse_proxy_loop_detected(self, command, fetchurl, req_body):
        logger.err('[Reverse-proxy loop detected from peer {}] {} {}'.format(
            self.client_address[0], command, fetchurl
        ))

        self.send_error(500)
        return

    def overloaded_do_GET(self):
        if self.path == self.options['proxy_self_url']:
            logger.dbg('Sending CA certificate.')
            self.send_cacert()
            return

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        req_body_modified = ""
        dont_fetch_response = False
        res = None
        res_body_plain = None
        content_encoding = 'identity'
        inbound_origin = req.headers['Host']
        outbound_origin = inbound_origin

        logger.info('[REQUEST] {} {}'.format(self.command, req.path), color=ProxyLogger.colors_map['green'])
        with self.lock:
            self.save_handler(req, req_body, None, None)

        try:
            (modified, req_body_modified) = self.request_handler(req, req_body)
            if 'IProxyPlugin.DropConnectionException' in str(type(req_body_modified)) or \
                'IProxyPlugin.DontFetchResponseException' in str(type(req_body_modified)):
                raise req_body_modified

            elif modified or req_body_modified is not None:
                req_body = req_body_modified
                if req_body != None: req.headers['Content-length'] = str(len(req_body))

            parsed = urlparse(req.path)
            if parsed.netloc != inbound_origin and parsed.netloc != None and len(parsed.netloc) > 1:
                logger.info('Plugin redirected request from [{}] to [{}]'.format(inbound_origin, parsed.netloc))
                outbound_origin = parsed.netloc
                req.path = (parsed.path + '?' + parsed.query if parsed.query else parsed.path)

        except Exception as e:
            if 'DropConnectionException' in str(e):
                if origin in self.tls.conns:
                    del self.tls.conns[origin]
                logger.err("Plugin demanded to drop the request: ({})".format(str(e)))
                return

            elif 'DontFetchResponseException' in str(e):
                dont_fetch_response = True
                res_body_plain = 'DontFetchResponseException'
                class Response(object):
                    pass
                res = Response()

            else:
                logger.err('Exception catched in request_handler: {}'.format(str(e)))
                if options['debug']: 
                    raise

        req_path_full = ''
        if not req.path: req.path = '/'
        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req_path_full = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req_path_full = "http://%s%s" % (req.headers['Host'], req.path)

        if not req_path_full: req_path_full = req.path
        u = urlparse(req_path_full)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        origin = (scheme, inbound_origin)

        if not dont_fetch_response:
            try:
                assert scheme in ('http', 'https')

                #req_headers = ProxyRequestHandler.filter_headers(req.headers)
                req_headers = req.headers
                if req_body == None: req_body = ''
                else: 
                    try:
                        req_body = req_body.decode()
                    except AttributeError: 
                        pass

                request = '{} {} {}\r\n{}\r\n{}'.format(
                    self.command, path, 'HTTP/1.1', req_headers, req_body
                )

                logger.dbg('Reverse-proxy fetch request from [{}]:\n\n{}'.format(outbound_origin, request))

                fetchurl = req_path_full.replace(netloc, outbound_origin)
                logger.dbg('DEBUG REQUESTS: request("{}", "{}", "{}", ...'.format(
                    self.command, fetchurl, req_body.strip()
                ))

                ip = ''
                try:
                    ip = socket.gethostbyname(urlparse(fetchurl).netloc)
                except:
                    ip = urlparse(fetchurl).netloc

                if ':' in ip:
                    ip = ip.split(':')[0]

                #if ip == self.server_address or ip in self.all_server_addresses:
                #    return self.reverse_proxy_loop_detected(self.command, fetchurl, req_body)
                #else:
                if True:
                    myreq = requests.request(
                        method = self.command, 
                        url = fetchurl, 
                        data = req_body.strip().encode(),
                        headers = req_headers,
                        timeout = self.options['timeout'],
                        allow_redirects = False,
                        verify = False
                    )

                class MyResponse(http.client.HTTPResponse):
                    def __init__(self, req, origreq):
                        self.status = myreq.status_code
                        self.response_version = origreq.protocol_version
                        self.headers = myreq.headers.copy()
                        self.reason = myreq.reason
                        self.msg = self.headers

                res = MyResponse(myreq, self)
                res_body = myreq.content
                logger.dbg("Response from reverse-proxy fetch came at {} bytes.".format(len(res_body)))
                if 'Content-Length' not in res.headers.keys() and len(res_body) != 0:
                    res.headers['Content-Length'] = str(len(res_body))
                myreq.close()

                if type(res_body) == str: res_body = str.encode(res_body)

            except Exception as e:
                logger.dbg("Could not proxy request: ({})".format(str(e)))
                if 'RemoteDisconnected' in str(e) or 'Read timed out' in str(e):
                    return
                    
                if options['debug']: raise
                self.send_error(502)
                return

            setattr(res, 'headers', res.msg)

            content_encoding = res.headers.get('Content-Encoding', 'identity')
            res_body_plain = self.decode_content_body(res_body, content_encoding)

        (modified, res_body_modified) = self.response_handler(req, req_body, res, res_body_plain)

        if modified or res_body_modified != None: 
            logger.dbg('Plugin has modified the response body. Using it instead')
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        if 'Accept-Encoding' in req.headers.keys():
            enc = req.headers['Accept-Encoding'].split(' ')[0].replace(',','')

            override_resp_enc = plugins.IProxyPlugin.proxy2_metadata_headers['override_response_content_encoding'] 
            if override_resp_enc in res.headers.keys():
                logger.dbg('Plugin asked to override response content encoding without changing header\'s value.')
                logger.dbg('Yielding content in {} whereas header pointing at: {}'.format(
                   res.headers[override_resp_enc], req.headers['Accept-Encoding']))
                enc = res.headers[override_resp_enc]
                del res.headers[override_resp_enc]

            logger.dbg('Encoding response body to: {}'.format(enc))
            res_body = self.encode_content_body(res_body, enc)
            res.headers['Content-Length'] = str(len(res_body))

        logger.info('[RESPONSE] HTTP {} {}, length: {}'.format(res.status, res.reason, len(res_body)), color=ProxyLogger.colors_map['yellow'])
            
        #res_headers = ProxyRequestHandler.filter_headers(res.headers)
        res_headers = res.headers
        o = "%s %d %s\r\n" % (self.protocol_version, res.status, res.reason)
        self.wfile.write(o.encode())

        for k, v in res_headers.items():
            line = '{}: {}\r\n'.format(k, v)
            self.wfile.write(line.encode())
        try:
            self.end_headers()
        except: 
            self.wfile.write(b'\r\n')

        if type(res_body) == str: res_body = str.encode(res_body)
        self.wfile.write(res_body)

        if options['trace'] and options['debug']:
            with self.lock:
                self.save_handler(req, req_body, res, res_body_plain)

    @staticmethod
    def filter_headers(headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            if k in headers.keys():
                del headers[k]
        return headers

    def encode_content_body(self, text, encoding):
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            _io = BytesIO()
            with gzip.GzipFile(fileobj=_io, mode='wb') as f:
                f.write(text)
            data = _io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
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
                raise Exception('Could not decompress Brotli stream: "{}"'.format(str(e)))
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def send_cacert(self):
        with open(self.options['cacert'], 'rb') as f:
            data = f.read()

        o = "%s %d %s\r\n" % (self.protocol_version, 200, 'OK')
        self.wfile.write(o.encode())
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def print_info(self, req, req_body, res, res_body):
        def _parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in parse_qsl(s, keep_blank_values=True))

        if not options['trace'] or not options['debug']:
            return

        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        if res is not None:
            reshdrs = res.headers
            if type(reshdrs) == dict:
                reshdrs = ''
                for k, v in res.headers.items():
                    reshdrs += '{}: {}\n'.format(k, v)

            res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, reshdrs)

        logger.trace("==== REQUEST ====\n%s" % req_header_text, color=ProxyLogger.colors_map['yellow'])

        u = urlparse(req.path)
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
                m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', res_body.decode(), re.I)
                if m:
                    logger.trace("==== HTML TITLE ====\n%s\n" % html.unescape(m.group(1)), color=ProxyLogger.colors_map['cyan'])
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body

            if res_body_text:
                logger.trace("==== RESPONSE BODY ====\n%s\n" % res_body_text.decode(), color=ProxyLogger.colors_map['green'])

    def request_handler(self, req, req_body):
        altered = False
        req_body_current = req_body

        for plugin_name in self.plugins:
            instance = self.plugins[plugin_name]
            try:
                handler = getattr(instance, 'request_handler')
                logger.dbg("Calling `request_handler' from plugin %s" % plugin_name)
                origheaders = dict(req.headers).copy()

                req_body_current = handler(req, req_body_current)

                altered = (req_body != req_body_current)
                for k, v in origheaders.items():
                    if origheaders[k] != req.headers[k]:
                        logger.dbg('Plugin modified request header: "{}", from: "{}" to: "{}"'.format(
                            k, origheaders[k], req.headers[k]))
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
                logger.dbg("Calling `response_handler' from plugin %s" % plugin_name)
                origheaders = {}
                try:
                    origheaders = res.headers.copy()
                except: pass

                res_body_current = handler(req, req_body, res, res_body_current)
                
                altered = (res_body_current != res_body)
                for k, v in origheaders.items():
                    if origheaders[k] != res.headers[k]:
                        logger.dbg('Plugin modified response header: "{}", from: "{}" to: "{}"'.format(
                            k, origheaders[k], res.headers[k]))
                        altered = True

                if len(origheaders.keys()) != len(res.headers.keys()):
                    logger.dbg('Plugin modified response headers.')
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

    do_HEAD = _handle_request
    do_GET = _handle_request
    do_POST = _handle_request
    do_OPTIONS = _handle_request
    do_DELETE = _handle_request
    do_PUT = _handle_request
    do_TRACE = _handle_request
    do_PATCH = _handle_request

def init():
    global options
    global pluginsloaded
    global logger
    global sslintercept

    optionsparser.parse_options(options, VERSION)
    logger = ProxyLogger(options)
    pluginsloaded = PluginsLoader(logger, options)
    sslintercept = SSLInterception(logger, options)

    for name, plugin in pluginsloaded.get_plugins().items():
        plugin.logger = logger
        plugin.help(None)

def cleanup():
    global options

    # Close logging file descriptor unless it's stdout
    #if options['log'] and options['log'] not in (sys.stdout, 'none'):
    #    options['log'].close()
    #    options['log'] = None
    
    if sslintercept:
        sslintercept.cleanup()

def serve_proxy(port, _ssl = False):
    ProxyRequestHandler.protocol_version = "HTTP/1.1"
    scheme = None
    hostname = None

    if options['hostname'].startswith('http') and '://' in options['hostname']:
        colon = options['hostname'].find(':')
        scheme = options['hostname'][:colon].lower()
        if scheme == 'https' and not _ssl:
            logger.fatal('You can\'t specify different schemes in bind address (-H) and on the port at the same time! Pick one place for that.\nSTOPPING THIS SERVER.')

        hostname = options['hostname'][colon + 3:].replace('/', '').lower()
    else:
        hostname = options['hostname']

    if _ssl: 
        scheme = 'https'

    if scheme == None: scheme = 'http'

    server_address = (hostname, port)
    httpd = ThreadingHTTPServer(server_address, ProxyRequestHandler)

    sa = httpd.socket.getsockname()
    s = sa[0] if not sa[0] else options['hostname']

    logger.info("Serving " + scheme + " proxy on: " + s + ", port: " + str(sa[1]) + "...", 
        color=ProxyLogger.colors_map['yellow'])

    if scheme == 'https':
        certpath = ProxyRequestHandler.generate_ssl_certificate(hostname)
        if not certpath:
            return False

        context = ssl._create_unverified_context()
        context.load_cert_chain(certfile=certpath, keyfile=options['certkey'])
        context.check_hostname=False
        context.verify_mode=ssl.CERT_NONE
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    httpd.serve_forever()

def main():
    try:
        init()

        threads = []
        if len(options['port']) == 0:
            options['port'].append('8080/http')

        for port in options['port']:
            p = 0
            scheme = 'http'
            try:
                _port = port
                if '/http' in port:
                    _port, scheme = port.split('/')
                p = int(_port)
                if p < 0 or p > 65535: raise Exception()
            except:
                logger.error('Specified port ({}) is not a valid number in range of 1-65535!'.format(port))
                return False

            th = threading.Thread(target=serve_proxy, args = (p, scheme.lower() == 'https'))
            threads.append(th)
            th.daemon = True
            th.start()
        
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        logger.info('\nProxy serving interrupted by user.', noprefix=True)

    except Exception as e:
        print(ProxyLogger.with_color(ProxyLogger.colors_map['red'], 'Fatal error has occured.'))
        print(ProxyLogger.with_color(ProxyLogger.colors_map['red'], '\t%s\nTraceback:' % e))
        print(ProxyLogger.with_color(ProxyLogger.colors_map['red'], '-'*30))
        traceback.print_exc()
        print(ProxyLogger.with_color(ProxyLogger.colors_map['red'], '-'*30))

    finally:
        cleanup()

if __name__ == '__main__':
    main()
