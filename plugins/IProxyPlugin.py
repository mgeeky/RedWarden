#!/usr/bin/python3
# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod

# These headers will be used by plugins to pass a message to the proxy,
# and proxy will remove them from the output response. Keep this dict keys in lowercase.
proxy2_metadata_headers = {
    'override_response_content_encoding': 'X-Proxy2-Override-Response-Content-Encoding',
    'strip_headers_during_forward' : 'X-Proxy2-Strip-Headers-During-Forward',
    'ignore_response_decompression_errors' : 'X-Proxy2-Ignore-Response-Decompression-Errors',
    'override_host_header' : 'X-Proxy2-Override-Host-Header',
}

class DropConnectionException(Exception):
    def __init__(self, txt):
        super().__init__('DropConnectionException: ' + txt)

class DontFetchResponseException(Exception):
    def __init__(self, txt):
        super().__init__('DontFetchResponseException: ' + txt)

class IProxyPlugin(ABC):
    def __init__(self, logger, proxyOptions):
        super().__init__()

    @staticmethod
    @abstractmethod
    def get_name():
        return 'IProxyPlugin'

    @abstractmethod
    def help(self, parser):
        '''
        @param parser - If given, the plugin should return it's specific options using argparse
                        interface. If not given, or passed as None - the plugin should perform it's options
                        validation logic internally.
        '''
        pass

    @abstractmethod
    def request_handler(self, req, req_body):
        pass

    @abstractmethod
    def response_handler(self, req, req_body, res, res_body):
        pass
