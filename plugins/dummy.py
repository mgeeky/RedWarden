#!/usr/bin/python3

from IProxyPlugin import IProxyPlugin

# Dummy plugin presenting necessary structure of 
# a proxy2 plugin to be loaded correctly.

class ProxyPlugin(IProxyPlugin):

    #
    # `logger' stands for logging object instance, `params' will be 
    # a dictonary of input paramerers for the script. Having passed to the
    # program a string like:
    #
    # $ ./proxy2 -p "plugins/my_plugin.py",argument1="test",argument2,argument3=test2
    #
    # This plugin shall receive:
    #
    # params =  {'path':'plugins/my_plugin.py', 
    #           'argument1':'test', 'argument2':'', 'argument3':'test2'}
    #
    def __init__(self, logger, proxyOptions):
        self.logger = logger
        self.proxyOptions = proxyOptions
        logger.info('hello world from __init__ in ProxyPlugin.')

    @staticmethod
    def get_name():
        return 'dummy'

    @staticmethod
    def help(parser):
        parser.add_argument('--hello', metavar = 'TEXT', help = 'Prints hello message')

    def request_handler(self, req, req_body):
        self.logger.info('hello world from request_handler! Message: "%s", Req: "%s"' % (self.proxyOptions['hello'], req.path))

    def response_handler(self, req, req_body, res, res_body):
        self.logger.info('hello world from response_handler! Message: "%s", Req: "%s"' % (self.proxyOptions['hello'], req.path))