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
#   0.5     fixed plenty of bugs, improved a bit server's resilience against slow/misbehaving peers
#           by disconnecting them/timeouting connections, improved logging facility and output format,
#           added options to protecte HTTP headers, apply fine-grained DROP policy, and plenty more.
#
# Author:
#   Mariusz B. / mgeeky, '16-'20
#   <mb@binary-offensive.com>
#
#   (originally based on: @inaz2 implementation: https://github.com/futuresimple/proxy2)
#   (now obsoleted)
#

VERSION = '0.5'

import sys, os

import tornado.web
import tornado.ioloop
import tornado.httpserver

from lib.proxylogger import ProxyLogger
from lib.proxyhandler import *


normpath = lambda p: os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), p))


# Global options dictonary, that will get modified after parsing 
# program arguments. Below state represents default values.
options = {
    'bind': 'http://0.0.0.0',
    'port': [8080, ],
    'debug': False,                  # Print's out debuging informations
    'verbose': True,
    'tee': False,
    'trace': False,                  # Displays packets contents
    'log': None,
    'proxy_self_url': 'http://proxy2.test/',
    'timeout': 45,
    'no_ssl': False,
    'drop_invalid_http_requests': True,
    'no_proxy': False,
    'cakey':  normpath('ca-cert/ca.key'),
    'cacert': normpath('ca-cert/ca.crt'),
    'certkey': normpath('ca-cert/cert.key'),
    'certdir': normpath('certs/'),
    'cacn': 'proxy2 CA',
    'plugins': set(),
    'plugin_class_name': 'ProxyPlugin',
}

logger = None


def create_ssl_context():
    ssl_ctx  = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(options['cacert'], options['cakey'])

    return ssl_ctx 

def serve_proxy(bind, port, _ssl = False):
    ProxyRequestHandler.protocol_version = "HTTP/1.1"
    scheme = None
    certpath = ''

    if not bind or len(bind) == 0:
        if options['bind'].startswith('http') and '://' in options['bind']:
            colon = options['bind'].find(':')
            scheme = options['bind'][:colon].lower()
            if scheme == 'https' and not _ssl:
                logger.fatal('You can\'t specify different schemes in bind address (-B) and on the port at the same time! Pick one place for that.\nSTOPPING THIS SERVER.')

            bind = options['bind'][colon + 3:].replace('/', '').lower()
        else:
            bind = options['bind']

    if _ssl: 
        scheme = 'https'

    if scheme == None: scheme = 'http'

    server_address = (bind, port)
    app = None

    try:
        params = dict(server_bind=bind, server_port=port)
        app = tornado.web.Application([
            (r'/.*', ProxyRequestHandler, params),
            (scheme + r'://.*', ProxyRequestHandler, params),
        ],
        transforms=[RemoveXProxy2HeadersTransform, ])

    except OSError as e:
        if 'Address already in use' in str(e):
            logger.err("Could not bind to specified port as it is already in use!")
            return
        else:
            raise

    logger.info("Serving proxy on: {}://{}:{} ...".format(scheme, bind, port), 
        color=ProxyLogger.colors_map['yellow'])

    if scheme == 'https':
        ssl_ctx = create_ssl_context()
        server = tornado.httpserver.HTTPServer(app, ssl_options=ssl_ctx)
        server.listen(port, address = bind)
    else:
        server = tornado.httpserver.HTTPServer(app)
        server.listen(port, address = bind)


def main():
    global options
    global logger

    try:
        (options, logger) = init(options, VERSION)

        threads = []
        if len(options['port']) == 0:
            options['port'].append('8080/http')

        for port in options['port']:
            p = 0
            scheme = 'http'
            bind = ''

            try:
                _port = port

                if type(port) == int:
                    bind = options['bind']

                if ':' in port:
                    bind, port = _port.split(':')

                if '/http' in port:
                    _port, scheme = port.split('/')

                p = int(_port)
                if p < 0 or p > 65535: raise Exception()

            except:
                logger.err('Specified port ({}) is not a valid number in range of 1-65535!'.format(port))
                return False

            serve_proxy(bind, p, scheme.lower() == 'https')

        tornado.ioloop.IOLoop.instance().start()

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
