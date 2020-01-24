#!/usr/bin/python3

from IProxyPlugin import IProxyPlugin

# Dummy plugin presenting necessary structure of 
# a proxy2 plugin to be loaded correctly.

class ProxyPlugin(IProxyPlugin):
    def __init__(self, logger, proxyOptions):
        self.logger = logger
        self.proxyOptions = proxyOptions
        logger.info('hello world from __init__ in ProxyPlugin.')

    @staticmethod
    def get_name():
        return 'dummy'

    def help(self, parser):
        if parser:
            parser.add_argument('--hello', metavar = 'TEXT', help = 'Prints hello message')

    def request_handler(self, req, req_body):
        self.logger.info('hello world from request_handler! Message: "%s", Req: "%s"' % (self.proxyOptions['hello'], req.path))

    def response_handler(self, req, req_body, res, res_body):
        self.logger.info('hello world from response_handler! Message: "%s", Req: "%s"' % (self.proxyOptions['hello'], req.path))
