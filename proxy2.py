# -*- coding: utf-8 -*-
import sys
import os
import socket
import ssl
import select
import httplib
import urlparse
import threading
import gzip
import zlib
import time
import json
import re
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from cStringIO import StringIO
from subprocess import Popen, PIPE
from HTMLParser import HTMLParser


# Global options dictonary, that will get modified after
# parsing program arguments. 
options = {
    'debug': True,                  # Print's out debuging informations
    'trace': True,                  # Displays packets contents
    'proxy_self_url': 'http://proxy2.test/',
    'timeout': 5,
    'cakey': 'ca.key',
    'cacert': 'ca.crt',
    'certkey': 'cert.key',
    'certdir': 'certs/',
    'ca_common_name': 'proxy2 CA',
}

COLORS_MAP = {
    'red': 31, 'green': 32, 'yellow': 33,
    'blue': 34, 'magenta': 35, 'cyan': 36,
    'white': 37, 'grey': 38
}

ssl_interception_prepared = False


def out(txt, mode='info ', color=None, noprefix=False):
    if txt == None:
        return 

    def with_color(c, s):
        return "\x1b[%dm%s\x1b[0m" % (c, s)

    colors = {
        'error': COLORS_MAP['red'],
        'trace': COLORS_MAP['magenta'],
        'info ': COLORS_MAP['white'],
        'debug': COLORS_MAP['yellow'],
        'other': COLORS_MAP['grey']
    }
    c = colors.setdefault(mode, COLORS_MAP['grey']) if color == None else color
    t = str(time.strftime("%H:%M:%S", time.gmtime()))
    prefix = with_color(colors['other'], '[%s] %s: ' % (mode.upper(), t)) if not noprefix else ''
    print prefix + with_color(c, txt)

def dbg(txt, color=None, noprefix=False):
    global options
    if options['debug']:
        out(txt, 'debug', color, noprefix)

def trace(txt, color=None, noprefix=False):
    global options 
    if options['trace']:   
        out(txt, 'trace', color, noprefix)

def err(txt, color=None, noprefix=False):
    out(txt, 'error', color, noprefix)



# Asynchronously serving HTTP server class.
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6

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

        self.tls = threading.local()
        self.tls.conns = {}
        self.options = options

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):

        # Surpress "Request timed out: timeout('timed out',)" if not in debug mode.
        if isinstance(args[0], socket.timeout) and not self.options['debug']:
            return

        self.log_message(format, *args)

    def do_CONNECT(self):
        dbg('SSL: %s' % str(ssl_interception_prepared))
        if ssl_interception_prepared:
            self.connect_intercept()
        else:
            self.connect_relay()

    def connect_intercept(self):
        hostname = self.path.split(':')[0]

        dbg('CONNECT intercepted: "%s"' % self.path)

        with self.lock:
            certpath = "%s/%s.crt" % (self.options['certdir'].rstrip('/'), hostname)
            if not os.path.isfile(certpath):
                dbg('Generating valid SSL certificate...')
                epoch = "%d" % (time.time() * 1000)
                p1 = Popen(["openssl", "req", "-new", "-key", self.options['certkey'], "-subj", "/CN=%s" % hostname], stdout=PIPE)
                p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.options['cacert'], "-CAkey", self.options['cakey'], "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
                p2.communicate()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established'))
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

        dbg('CONNECT relaying: "%s"' % self.path)

        try:
            s = socket.create_connection(address, timeout=self.options['timeout'])
        except Exception as e:
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

    def do_GET(self):
        if self.path == self.options['proxy_self_url']:
            dbg('Sending CA certificate.')
            self.send_cacert()
            return

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)


        (dbg if self.options['trace'] else out)('Request:\t"%s"' % req.path)

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urlparse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        req_headers = self.filter_headers(req.headers)

        try:
            origin = (scheme, netloc)
            if not origin in self.tls.conns:
                if scheme == 'https':
                    self.tls.conns[origin] = httplib.HTTPSConnection(netloc, timeout=self.options['timeout'])
                else:
                    self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.options['timeout'])
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(req_headers))
            res = conn.getresponse()
            res_body = res.read()
        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            return

        version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
        setattr(res, 'headers', res.msg)
        setattr(res, 'response_version', version_table[res.version])

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
        if res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        res_headers = self.filter_headers(res.headers)

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res_headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain)

    do_HEAD = do_GET
    do_POST = do_GET
    do_OPTIONS = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]
        return headers

    def encode_content_body(self, text, encoding):
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            data = io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                text = f.read()
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def send_cacert(self):
        with open(self.options['cacert'], 'rb') as f:
            data = f.read()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def print_info(self, req, req_body, res, res_body):
        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urlparse.parse_qsl(s, keep_blank_values=True))

        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, res.headers)

        trace(req_header_text, 33, True)

        u = urlparse.urlsplit(req.path)
        if u.query:
            query_text = parse_qsl(u.query)
            trace("==== QUERY PARAMETERS ====\n%s\n" % query_text, COLORS_MAP['green'], True)

        cookie = req.headers.get('Cookie', '')
        if cookie:
            cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
            trace("==== COOKIE ====\n%s\n" % cookie, COLORS_MAP['green'], True)

        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].decode('base64')
            trace("==== BASIC AUTH ====\n%s\n" % token, COLORS_MAP['red'], True)

        if req_body is not None:
            req_body_text = None
            content_type = req.headers.get('Content-Type', '')

            if content_type.startswith('application/x-www-form-urlencoded'):
                req_body_text = parse_qsl(req_body)
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
                trace("==== REQUEST BODY ====\n%s\n" % req_body_text, COLORS_MAP['white'], True)

        trace(res_header_text, 36, True)

        cookies = res.headers.getheaders('Set-Cookie')
        if cookies:
            cookies = '\n'.join(cookies)
            trace("==== SET-COOKIE ====\n%s\n" % cookies, COLORS_MAP['yellow'], True)

        if res_body is not None:
            res_body_text = None
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
                m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', res_body, re.I)
                if m:
                    h = HTMLParser()
                    trace("==== HTML TITLE ====\n%s\n" % h.unescape(m.group(1).decode('utf-8')), COLORS_MAP['cyan'], True)
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body

            if res_body_text:
                trace("==== RESPONSE BODY ====\n%s\n" % res_body_text, COLORS_MAP['green'], True)

    def request_handler(self, req, req_body):
        pass

    def response_handler(self, req, req_body, res, res_body):
        pass

    def save_handler(self, req, req_body, res, res_body):
        self.print_info(req, req_body, res, res_body)



def ssl_interception_setup():
    global ssl_interception_prepared
    global options

    def setup():
        dbg('Setting up SSL interception certificates')

        if not os.path.isabs(options['certdir']):
            dbg('Certificate directory path was not absolute. Assuming relative to current programs\'s directory')
            path = os.path.join(os.path.dirname(os.path.realpath(__file__)), options['certdir'])
            options['certdir'] = path
            dbg('Using path: "%s"' % options['certdir'])

        # Step 1: Create directory for certificates and asynchronous encryption keys
        if not os.path.isdir(options['certdir']):
            try:
                dbg("Creating directory for certificate: '%s'" % options['certdir'])
                os.mkdir(options['certdir'])
            except Exception as e:
                err("Couldn't make directory for certificates: '%s'" % e)
                return False

        # Step 2: Create CA key
        options['cakey'] = os.path.join(options['certdir'], options['cakey'])
        if not os.path.isdir(options['cakey']):
            dbg("Creating CA key file: '%s'" % options['cakey'])
            p = Popen(["openssl", "genrsa", "-out", options['cakey'], "2048"], stdout=PIPE, stderr=PIPE)
            (out, error) = p.communicate()
            dbg(out + error)
            
            if not options['cakey']:
                err('Creating of CA key process has failed.')
                return False

        # Step 3: Create CA certificate
        options['cacert'] = os.path.join(options['certdir'], options['cacert'])
        if not os.path.isdir(options['cacert']):
            dbg("Creating CA certificate file: '%s'" % options['cacert'])
            p = Popen(["openssl", "req", "-new", "-x509", "-days", "3650", "-key", options['cakey'], "-out", options['cacert'], "-subj", "/CN="+options['ca_common_name']], stdout=PIPE, stderr=PIPE)
            (out, error) = p.communicate()
            dbg(out + error)

            if not options['cacert']:
                err('Creating of CA certificate process has failed.')
                return False

        # Step 4: Create certificate key file
        options['certkey'] = os.path.join(options['certdir'], options['certkey'])
        if not os.path.isdir(options['certkey']):
            dbg("Creating Certificate key file: '%s'" % options['certkey'])
            dbg("Creating CA key file: '%s'" % options['cakey'])
            p = Popen(["openssl", "genrsa", "-out", options['certkey'], "2048"], stdout=PIPE, stderr=PIPE)
            (out, error) = p.communicate()
            dbg(out + error)

            if not options['certkey']:
                err('Creating of Certificate key process has failed.')
                return False

        dbg('SSL interception has been setup.')
        return True

    out('Preparing SSL certificates and keys for https traffic interception...')
    ssl_interception_prepared = setup()
    return ssl_interception_prepared


def ssl_interception_cleanup():
    if not ssl_interception_prepared:
        return

    try:
        import shutil
        shutil.rmtree(options['certdir'])
        dbg('SSL interception files cleaned up.')
    except Exception as e:
        err("Couldn't perform SSL interception files cleaning: '%s'" % e)


def main(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):

    if sys.argv[1:]:
        port = int(sys.argv[1])
    else:
        port = 8080
    server_address = ('', port)

    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)

    try:
        ssl_interception_setup() # optional, based on program arguments
        sa = httpd.socket.getsockname()
        s = sa[0] if not sa[0] else '127.0.0.1'
        out("Serving HTTP Proxy on: " + s + ", port: " + str(sa[1]) + "...")
        httpd.serve_forever()

    except KeyboardInterrupt:
        trace('\nProxy serving interrupted by user.', noprefix=True)

    finally:
        ssl_interception_cleanup()

if __name__ == '__main__':
    main()
