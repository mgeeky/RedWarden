#!/usr/bin/python3
# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod

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
