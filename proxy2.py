import sys
import socket
import select
import httplib
import urlparse
import threading
from collections import OrderedDict
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6


class ProxyRequestHandler(BaseHTTPRequestHandler):
    timeout = 5

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        # surpress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        return BaseHTTPRequestHandler.log_error(self, format, *args)

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
        req_headers = self.headers.items()
        req_headers = self.rewrite_headers(req_headers)
        content_length = int(req_headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        u = urlparse.urlsplit(self.path)
        assert u.scheme == 'http'
        host, path = u.netloc, (u.path + '?' + u.query if u.query else u.path)

        try:
            if host:
                req_headers['Host'] = host
            if not host in self.tls.conns:
                self.tls.conns[host] = httplib.HTTPConnection(host, timeout=self.timeout)
            conn = self.tls.conns[host]
            conn.request(self.command, path, req_body, req_headers)
            res = conn.getresponse()
            res_headers = res.getheaders()
            res_headers = self.rewrite_headers(res_headers)
            res_body = res.read()
        except Exception as e:
            self.send_response(502, 'Bad Gateway')
            self.send_header('Content-Type', 'text/html')
            self.send_header('Connection', 'close')
            self.end_headers()
            print >>self.wfile, "<!DOCTYPE html><title>502 Bad Gateway</title><p>%s: %s</p>" % (type(e).__name__, e)
            del self.tls.conns[host]
            return

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for k, v in res_headers.iteritems():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

    do_HEAD = do_GET
    do_POST = do_GET

    def rewrite_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')

        pairs = [(k.title(), v) for k, v in headers if not k in hop_by_hop]
        return OrderedDict(pairs)


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
