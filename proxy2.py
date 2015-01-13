import sys
import socket
import select
import httplib
import urlparse
import threading
import gzip
import zlib
from collections import OrderedDict
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from cStringIO import StringIO


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6


class ProxyRequestHandler(BaseHTTPRequestHandler):
    timeout = 5
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        # surpress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def do_CONNECT(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            self.send_response(502, 'Bad Gateway')
            self.send_header('Connection', 'close')
            self.end_headers()
            return
        self.send_response(200, 'Connection Established')
        self.send_header('Connection', 'close')
        self.end_headers()

        conns = [self.connection, s]
        close_connection = False
        while not close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    close_connection = True
                    break
                other.sendall(data)

        s.close()

    def do_GET(self):
        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urlparse.urlsplit(self.path)
        assert u.scheme == 'http'
        host, path = u.netloc, (u.path + '?' + u.query if u.query else u.path)
        if host:
            req.headers['Host'] = host
        req_headers = self.filter_headers(req.headers)

        try:
            if not host in self.tls.conns:
                self.tls.conns[host] = httplib.HTTPConnection(host, timeout=self.timeout)
            conn = self.tls.conns[host]
            conn.request(self.command, path, req_body, dict(req_headers))
            res = conn.getresponse()
            setattr(res, 'headers', res.msg)
            res_body = res.read()
        except Exception as e:
            self.send_response(502, 'Bad Gateway')
            self.send_header('Content-Type', 'text/html')
            self.send_header('Connection', 'close')
            self.end_headers()
            print >>self.wfile, "<!DOCTYPE html><title>502 Bad Gateway</title><p>%s: %s</p>" % (type(e).__name__, e)
            if host in self.tls.conns:
                del self.tls.conns[host]
            return

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        res_body_modified = self.response_handler(res, res_body_plain)
        if res_body_modified is not None:
            res_body = self.encode_content_body(res_body_modified, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        res_headers = self.filter_headers(res.headers)

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res_headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body)

    do_HEAD = do_GET
    do_POST = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]
        return headers

    def encode_content_body(self, text, encoding):
        if encoding in ('gzip', 'x-gzip'):
            io = StringIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            data = io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        elif encoding == 'identity':
            data = text
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data, encoding):
        if encoding in ('gzip', 'x-gzip'):
            io = StringIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                text = f.read()
        elif encoding == 'deflate':
            text = zlib.decompress(data)
        elif encoding == 'identity':
            text = data
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def request_handler(self, req, req_body):
        pass

    def response_handler(self, res, res_body):
        pass

    def save_handler(self, req, req_body, res, res_body):
        version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}

        print "%s%s %s %s\n%s%s" % ('\x1b[33m', req.command, req.path, req.request_version, req.headers, '\x1b[0m')
        if req_body is not None:
            print "%s%r%s\n" % ('\x1b[32m', req_body[:1024], '\x1b[0m')
        print "%s%s %d %s\n%s%s" % ('\x1b[36m', version_table[res.version], res.status, res.reason, res.headers, '\x1b[0m')


def test(HandlerClass = ProxyRequestHandler, ServerClass = ThreadingHTTPServer, protocol="HTTP/1.1"):
    if sys.argv[1:]:
        port = int(sys.argv[1])
    else:
        port = 8080
    server_address = ('', port)

    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)

    sa = httpd.socket.getsockname()
    print "Serving HTTP Proxy on", sa[0], "port", sa[1], "..."
    httpd.serve_forever()


if __name__ == '__main__':
    test()
