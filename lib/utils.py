#!/usr/bin/python3
# -*- coding: utf-8 -*-
#

import http.client
import plugins.IProxyPlugin

logger = None

drop_this_header = 'IN-THE-NAME-OF-PROXY2-REMOVE-THIS-HEADER-COMPLETELY'

def hexdump(data):
    s = ''
    n = 0
    lines = []
    tableline = '-----+' + '-' * 24 + '|' \
        + '-' * 25 + '+' + '-' * 18 + '+\n'
    if isinstance(data, str):
        data = data.encode()

    if len(data) == 0:
        return '<empty>'

    for i in range(0, len(data), 16):
        line = ''
        line += '%04x | ' % (i)
        n += 16

        for j in range(n-16, n):
            if j >= len(data): break
            line += '%02x' % (data[j] & 0xff)
            if j % 8 == 7 and j % 16 != 15:
                line += '-'
            else:
                line += ' '

        line += ' ' * (3 * 16 + 7 - len(line)) + ' | '
        for j in range(n-16, n):
            if j >= len(data): break
            c = data[j] if not (data[j] < 0x20 or data[j] > 0x7e) else '.'
            line += '%c' % c

        line = line.ljust(74, ' ') + ' |'
        lines.append(line)

    return tableline + '\n'.join(lines) + '\n' + tableline


def putheader_decorator(method):
    def new_putheader(self, header, *values):
        for v in values:
            if v == drop_this_header:
                return

        xhdrs = [x.lower() for x in plugins.IProxyPlugin.proxy2_metadata_headers.values()]
        if header.lower() in xhdrs:
            return

        return method(self, header, *values)
    return new_putheader

def send_request_decorator(method):
    def new_send_request(self, _method, url, body, headers, encode_chunked):
        strips = ''
        headers2 = {}
        hdrnames = list(headers.keys())
        for k, v in headers.items():
            headers2[k.lower()] = v

        strip_these_headers = []

        if plugins.IProxyPlugin.proxy2_metadata_headers['strip_headers_during_forward'].lower() in headers2.keys():
            strips = headers2[plugins.IProxyPlugin.proxy2_metadata_headers['strip_headers_during_forward'].lower()]
            strip_these_headers = [x.strip() for x in strips.split(',')]
            strip_these_headers.append(plugins.IProxyPlugin.proxy2_metadata_headers['strip_headers_during_forward'])

        for k, v in plugins.IProxyPlugin.proxy2_metadata_headers.items():
            if v.lower() in headers2.keys():
                strip_these_headers.append(v)

        if len(strip_these_headers) > 0:
            for h in strip_these_headers:
                for h2 in hdrnames:
                    if len(h2) > 0 and h.lower() == h2.lower():
                        headers[h2] = drop_this_header

                if len(h) > 0 and h.lower() not in headers2.keys():
                    headers[h] = drop_this_header

        headers3 = {}

        for k, v in headers.items():
            if k.lower().startswith('x-proxy2-'): continue
            if v == drop_this_header: continue
            headers3[k] = v
        
        reqhdrs = ''
        host = ''
        for k, v in headers3.items():
            if k.lower() == 'host': host = v
            if v == drop_this_header: continue
            reqhdrs += '\t{}: {}\r\n'.format(k, v)
        
        b = body
        if b != None and type(b) == bytes:
            b = body.decode(errors='ignore')

        request = '\t{} {} {}\r\n{}\r\n\t{}\n'.format(
            _method, url, 'HTTP/1.1', reqhdrs, b
        )
        
        logger.dbg('SENDING REVERSE-PROXY REQUEST to [{}]:\n\n{}'.format(host, request))
        return method(self, _method, url, body, headers3, encode_chunked)
        
    return new_send_request

def monkeypatching(log):
    global logger
    logger = log
    
    setattr(http.client.HTTPConnection, 'putheader', putheader_decorator(http.client.HTTPConnection.putheader))
    setattr(http.client.HTTPConnection, '_send_request', send_request_decorator(http.client.HTTPConnection._send_request))
